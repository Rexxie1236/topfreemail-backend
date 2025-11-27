/**
 * TopFreeMail backend - server.js
 *
 * Receives CloudMailin POSTs at /webhook, saves them to Postgres (Supabase),
 * and auto-creates inbox records when needed.
 *
 * This version forces TLS for the pg Pool in a way that works with Supabase poolers.
 * Adds token-protected read endpoints, rate limit and basic security headers.
 */

const express = require("express");
const multer = require("multer");
const { Pool } = require("pg");
const crypto = require("crypto");
const dns = require("dns");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

// Prefer IPv4 to avoid IPv6 routing issues
if (dns?.setDefaultResultOrder) {
  dns.setDefaultResultOrder("ipv4first");
}

const app = express();
const upload = multer(); // in-memory parser (we only store metadata)

// Basic body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Basic security headers
app.use(helmet());

// --------------------------
// Rate limit (light)
// --------------------------
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 300, // 300 requests per IP per hour (adjust if needed)
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// --------------------------
// Postgres pool (Supabase)
// --------------------------
// Prefer a full DATABASE_URL if available; fallback to separate env vars.
const connectionString = process.env.DATABASE_URL || null;

const poolConfig = connectionString
  ? {
      connectionString,
      ssl: {
        require: true,
        rejectUnauthorized: false,
      },
    }
  : {
      host: process.env.DB_HOST,
      port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 5432,
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      ssl: {
        require: true,
        rejectUnauthorized: false,
      },
    };

const pool = new Pool(poolConfig);

// Helper: quick check connected (not required, but useful in logs)
pool
  .connect()
  .then((c) => {
    c.release();
    console.log("✅ Postgres pool connected (initial check)");
  })
  .catch((err) => {
    console.error("❌ Postgres pool initial connect failed:", err && err.message ? err.message : err);
  });

// Utility: generate 16-character token (hex of 8 bytes = 16 chars)
function genToken16() {
  return crypto.randomBytes(8).toString("hex");
}

// --------------------------
// DB helper functions
// --------------------------
async function ensureInbox(address) {
  if (!address) throw new Error("no address provided to ensureInbox");

  const addr = String(address).trim().toLowerCase();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const res = await client.query(
      `select id, address, token, password_hash, created_at, last_active, deleted
       from public.inboxes
       where address = $1
       limit 1`,
      [addr]
    );

    if (res.rows.length > 0) {
      const row = res.rows[0];
      await client.query(`update public.inboxes set last_active = now() where id = $1`, [row.id]);
      await client.query("COMMIT");
      return row;
    }

    const token = genToken16();
    const insert = await client.query(
      `insert into public.inboxes (address, token, created_at, last_active)
       values ($1, $2, now(), now())
       returning id, address, token, password_hash, created_at, last_active, deleted`,
      [addr, token]
    );

    await client.query("COMMIT");
    return insert.rows[0];
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function getInboxById(id) {
  if (!id) return null;
  const res = await pool.query(`select id, address, token from public.inboxes where id = $1 limit 1`, [id]);
  return res.rows[0] || null;
}

async function getInboxByAddress(address) {
  if (!address) return null;
  const res = await pool.query(`select id, address, token from public.inboxes where address = $1 limit 1`, [String(address).toLowerCase()]);
  return res.rows[0] || null;
}

async function saveMessage(inboxId, mailFrom, mailTo, subject, body, raw, hasAttachments) {
  const q = `
    insert into public.messages
      (inbox_id, mail_from, mail_to, subject, body, raw, has_attachments, created_at)
    values ($1, $2, $3, $4, $5, $6, $7, now())
    returning id
  `;
  const vals = [inboxId, mailFrom || null, mailTo || null, subject || null, body || null, raw || null, !!hasAttachments];
  const res = await pool.query(q, vals);
  return res.rows[0];
}

// --------------------------
// Helpers: token validation
// --------------------------
function extractTokenFromReq(req) {
  // header takes precedence
  const header = req.headers["x-inbox-token"];
  if (header) return header;
  if (req.query && req.query.token) return String(req.query.token);
  return null;
}

async function checkTokenForInbox(inboxId, token) {
  if (!inboxId) return false;
  const inbox = await getInboxById(inboxId);
  if (!inbox) return false;
  // token must match exactly
  return !!(token && inbox.token === token);
}

// --------------------------
// Webhook endpoint - accepts form-data/multipart
// --------------------------
app.post("/webhook", upload.any(), async (req, res) => {
  try {
    console.log("📩 Incoming Email from CloudMailin");

    const fields = req.body || {};
    const files = req.files || [];

    const first = (v) => {
      if (Array.isArray(v)) return v[0];
      return v;
    };

    const mailFrom = first(fields.from) || first(fields["envelope-from"]) || null;

    let mailTo = first(fields.to) || first(fields["envelope-to"]) || null;
    if (Array.isArray(mailTo)) mailTo = mailTo[0];
    if (typeof mailTo === "string" && mailTo.includes(",")) mailTo = mailTo.split(",")[0].trim();

    const subject = first(fields.subject) || null;
    const text = first(fields.text) || null;
    const html = first(fields.html) || null;
    const body = text || html || null;

    const raw = {
      fields,
      files: files.map((f) => ({
        originalname: f.originalname,
        fieldname: f.fieldname,
        mimetype: f.mimetype,
        size: f.size,
      })),
      receivedAt: new Date().toISOString(),
    };

    console.log("from:", mailFrom, "to:", mailTo, "subject:", subject, "attachments:", files.length);

    if (!mailTo) {
      console.warn("No recipient (to) found in incoming payload. Saving raw only.");
      await pool.query(
        `insert into public.messages (inbox_id, mail_from, mail_to, subject, body, raw, has_attachments, created_at)
         values (null, $1, null, $2, $3, $4, $5, now())`,
        [mailFrom, subject, body, raw, files.length > 0]
      );
      return res.status(200).send("Received - no recipient");
    }

    const inbox = await ensureInbox(mailTo);
    const saved = await saveMessage(inbox.id, mailFrom, mailTo, subject, body, raw, files.length > 0);

    console.log(`Saved message ${saved.id} for inbox ${inbox.address}`);
    return res.status(200).send("Received");
  } catch (err) {
    console.error("Error handling webhook:", err && err.stack ? err.stack : err);
    // keep replying 200 to avoid retries from CloudMailin
    return res.status(200).send("Received (error)");
  }
});

// --------------------------
// Read endpoints (token-protected by default)
// --------------------------

// Get inbox metadata
app.get("/inboxes/:address", async (req, res) => {
  try {
    const address = String(req.params.address || "").toLowerCase();
    const inbox = await getInboxByAddress(address);
    if (!inbox) return res.status(404).json({ error: "not found" });

    // Do not reveal token here by default. If client provided token, verify and include it.
    const tokenProvided = extractTokenFromReq(req);
    const includeToken = tokenProvided && inbox.token === tokenProvided;
    const out = {
      id: inbox.id,
      address: inbox.address,
    };
    if (includeToken) out.token = inbox.token;
    return res.json(out);
  } catch (err) {
    console.error("GET /inboxes/:address error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ error: "server error" });
  }
});

// List messages for inbox
// Default security: require token unless ?require_token=0 is supplied (dev)
app.get("/inboxes/:address/messages", async (req, res) => {
  try {
    const address = String(req.params.address || "").toLowerCase();
    const inbox = await getInboxByAddress(address);
    if (!inbox) return res.status(404).json({ error: "not found" });

    const requireToken = req.query.require_token === "0" ? false : true; // default true
    if (requireToken) {
      const token = extractTokenFromReq(req);
      const ok = await checkTokenForInbox(inbox.id, token);
      if (!ok) return res.status(403).json({ error: "forbidden: invalid or missing token" });
    }

    // fetch messages
    const limit = Math.min(100, parseInt(req.query.limit, 10) || 20);
    const msgs = await pool.query(
      `select id, inbox_id, mail_from, mail_to, subject, coalesce(body,'') as body, has_attachments, created_at
       from public.messages
       where inbox_id = $1
       order by created_at desc
       limit $2`,
      [inbox.id, limit]
    );

    return res.json({ messages: msgs.rows });
  } catch (err) {
    console.error("GET /inboxes/:address/messages error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ error: "server error" });
  }
});

// Get a single message by id
// Default: token is required when message.inbox_id is not null
app.get("/messages/:id", async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) return res.status(400).json({ error: "bad request" });

    const msgRes = await pool.query(
      `select id, inbox_id, mail_from, mail_to, subject, body, raw, has_attachments, created_at
       from public.messages where id = $1 limit 1`,
      [id]
    );

    if (!msgRes.rows.length) return res.status(404).json({ error: "not found" });
    const msg = msgRes.rows[0];

    if (msg.inbox_id) {
      const token = extractTokenFromReq(req);
      const ok = await checkTokenForInbox(msg.inbox_id, token);
      if (!ok) return res.status(403).json({ error: "forbidden: invalid or missing token" });
    } else {
      // message has no inbox (raw-only). block if require_token in query (default: allow)
      // nothing extra for now
    }

    // By default return compact view; include raw only if include_raw=1
    const includeRaw = req.query.include_raw === "1";
    const out = {
      id: msg.id,
      inbox_id: msg.inbox_id,
      mail_from: msg.mail_from,
      mail_to: msg.mail_to,
      subject: msg.subject,
      body: msg.body,
      has_attachments: msg.has_attachments,
      created_at: msg.created_at,
    };
    if (includeRaw) out.raw = msg.raw;
    return res.json(out);
  } catch (err) {
    console.error("GET /messages/:id error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ error: "server error" });
  }
});

// Health endpoint
app.get("/", (req, res) => {
  res.send("TopFreeMail backend is running");
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
