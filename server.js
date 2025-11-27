/**
 * TopFreeMail backend - server.js
 *
 * Receives CloudMailin POSTs at /webhook, saves them to Postgres (Supabase),
 * and auto-creates inbox records when needed.
 *
 * This version forces TLS for the pg Pool in a way that works with Supabase poolers.
 */

const express = require("express");
const multer = require("multer");
const { Pool } = require("pg");
const crypto = require("crypto");
const dns = require("dns");

// Prefer IPv4 to avoid IPv6 routing issues
if (dns?.setDefaultResultOrder) {
  dns.setDefaultResultOrder("ipv4first");
}

const app = express();
const upload = multer(); // in-memory parser (we only store metadata)

// Basic body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --------------------------
// Postgres pool (Supabase)
// --------------------------
// Prefer a full DATABASE_URL if available; fallback to separate env vars.
const connectionString = process.env.DATABASE_URL || null;

const poolConfig = connectionString
  ? {
      connectionString,
      // When using a connection string with sslmode=require it still helps
      // to tell pg to accept the certificate chain used by Supabase pooler:
      ssl: {
        require: true,
        rejectUnauthorized: false,
      },
      // optional: set a small query timeout
      // statement_timeout: 15000,
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

// Ensure inbox exists for a full email address. Returns inbox row.
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

// Save message to DB
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

// Webhook endpoint - accepts form-data/multipart
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
    // Detailed logging so we can see the real DB/TLS error
    console.error("Error handling webhook:", err && err.stack ? err.stack : err);
    // Keep replying 200 to avoid retries, but log full error in Railway
    return res.status(200).send("Received (error)");
  }
});

// -------------------------
// Read endpoints for UI/testing
// -------------------------

// Helper: find inbox by address (lowercase)
async function getInboxByAddress(address) {
  const addr = String(address || "").trim().toLowerCase();
  const q = `
    SELECT id, address, token, created_at, last_active, deleted
    FROM public.inboxes
    WHERE address = $1
    LIMIT 1
  `;
  const r = await pool.query(q, [addr]);
  return r.rows[0] || null;
}

// GET /inboxes/:address  -> inbox metadata
app.get("/inboxes/:address", async (req, res) => {
  try {
    const inbox = await getInboxByAddress(req.params.address);
    if (!inbox) return res.status(404).json({ error: "inbox not found" });

    // by default DON'T reveal token to the public. reveal only if `?reveal_token=1` AND token provided
    if (req.query.reveal_token === "1") {
      // require the token via query param OR header to allow admin access
      const provided = req.query.token || req.get("x-inbox-token");
      if (!provided || provided !== inbox.token) {
        // hide token if not authorized
        delete inbox.token;
        return res.status(401).json({ error: "invalid token" });
      }
      // authorized: return inbox (including token)
      return res.json(inbox);
    }

    // default safe view
    delete inbox.token;
    res.json(inbox);
  } catch (err) {
    console.error("GET /inboxes/:address error:", err && err.stack ? err.stack : err);
    res.status(500).json({ error: "server error" });
  }
});

// GET /inboxes/:address/messages?limit=50&token=...
// returns recent messages for an inbox. If token present, require it. If no token param, allow read
// To enforce token by default, call with ?require_token=1
app.get("/inboxes/:address/messages", async (req, res) => {
  try {
    const inbox = await getInboxByAddress(req.params.address);
    if (!inbox) return res.status(404).json({ error: "inbox not found" });

    // If token param provided or require_token=1, require it matches
    const providedToken = req.query.token || req.get("x-inbox-token");
    if (req.query.require_token === "1") {
      if (!providedToken || providedToken !== inbox.token) {
        return res.status(401).json({ error: "invalid token" });
      }
    }

    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 50));

    const q = `
      SELECT id, mail_from, mail_to, subject, body, has_attachments, created_at
      FROM public.messages
      WHERE inbox_id = $1
      ORDER BY created_at DESC
      LIMIT $2
    `;
    const { rows } = await pool.query(q, [inbox.id, limit]);
    res.json({ inbox: { id: inbox.id, address: inbox.address }, messages: rows });
  } catch (err) {
    console.error("GET /inboxes/:address/messages error:", err && err.stack ? err.stack : err);
    res.status(500).json({ error: "server error" });
  }
});

// GET /messages/:id  -> returns full message row including raw (for viewing)
app.get("/messages/:id", async (req, res) => {
  try {
    const q = `SELECT id, inbox_id, mail_from, mail_to, subject, body, raw, has_attachments, created_at
               FROM public.messages
               WHERE id = $1
               LIMIT 1`;
    const { rows } = await pool.query(q, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: "message not found" });
    res.json(rows[0]);
  } catch (err) {
    console.error("GET /messages/:id error:", err && err.stack ? err.stack : err);
    res.status(500).json({ error: "server error" });
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
