/**
 * topfreemail-backend - server.js
 *
 * Receives CloudMailin POSTs at /webhook, saves them to Postgres (Supabase),
 * and auto-creates inbox records when needed.
 *
 * Required env vars (set in Railway):
 *  - DB_HOST
 *  - DB_PORT
 *  - DB_NAME
 *  - DB_USER
 *  - DB_PASSWORD
 *
 * NOTE: do NOT paste secrets here. Use Railway variables UI (you already did).
 */

const express = require("express");
const multer = require("multer");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const upload = multer(); // in-memory parser (we only store metadata)

// Basic body parsers (JSON + urlencoded for safety)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Postgres pool (Supabase-compatible)
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 5432,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false,
});

// Utility: generate 16-character token (hex of 8 bytes = 16 chars)
function genToken16() {
  return crypto.randomBytes(8).toString("hex");
}

// Ensure inbox exists for a full email address. Returns inbox row.
async function ensureInbox(address) {
  if (!address) throw new Error("no address provided to ensureInbox");

  // Normalize: lowercase trimmed
  const addr = String(address).trim().toLowerCase();

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Try find existing
    const res = await client.query(
      `select id, address, token, password_hash, created_at, last_active, deleted
       from public.inboxes
       where address = $1
       limit 1`,
      [addr]
    );

    if (res.rows.length > 0) {
      // update last_active
      const row = res.rows[0];
      await client.query(
        `update public.inboxes set last_active = now() where id = $1`,
        [row.id]
      );
      await client.query("COMMIT");
      return row;
    }

    // Not found -> create
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

// Webhook endpoint - accepts form-data/multipart (CloudMailin uses multipart)
app.post("/webhook", upload.any(), async (req, res) => {
  try {
    console.log("📩 Incoming Email from CloudMailin");

    // CloudMailin sends fields like: from, to, subject, text, html, attachments...
    // Accept flexible shapes (strings or arrays)
    const fields = req.body || {};
    const files = req.files || [];

    // Helpers to read field nicely
    const first = (v) => {
      if (Array.isArray(v)) return v[0];
      return v;
    };

    const mailFrom = first(fields.from) || first(fields["envelope-from"]) || null;
    // 'to' may be comma separated or an array: try to get first recipient
    let mailTo = first(fields.to) || fields["envelope-to"] || null;
    if (Array.isArray(mailTo)) mailTo = mailTo[0];
    if (typeof mailTo === "string" && mailTo.includes(",")) mailTo = mailTo.split(",")[0].trim();

    const subject = first(fields.subject) || null;
    // prefer text body; fallback to html if no text
    const text = first(fields.text) || null;
    const html = first(fields.html) || null;
    const body = text || html || null;

    // Build raw payload summary (safe to store)
    const raw = {
      fields: fields,
      files: files.map((f) => ({
        originalname: f.originalname,
        fieldname: f.fieldname,
        mimetype: f.mimetype,
        size: f.size
        // do not store file buffer here (would bloat DB). Attachments can be stored in object storage later.
      })),
      receivedAt: new Date().toISOString(),
    };

    console.log("from:", mailFrom, "to:", mailTo, "subject:", subject, "attachments:", files.length);

    if (!mailTo) {
      // If we don't know recipient, still respond 200 to avoid retries, but log.
      console.warn("No recipient (to) found in incoming payload. Saving raw only.");
      await pool.query(
        `insert into public.messages (inbox_id, mail_from, mail_to, subject, body, raw, has_attachments, created_at)
         values (null, $1, null, $2, $3, $4, $5, now())`,
        [mailFrom, subject, body, raw, files.length > 0]
      );
      return res.status(200).send("Received - no recipient");
    }

    // Ensure inbox record exists (auto create)
    const inbox = await ensureInbox(mailTo);

    // Save message row
    const saved = await saveMessage(inbox.id, mailFrom, mailTo, subject, body, raw, files.length > 0);

    console.log(`Saved message ${saved.id} for inbox ${inbox.address}`);
    // Good response
    return res.status(200).send("Received");
  } catch (err) {
    console.error("Error handling webhook:", err && err.stack ? err.stack : err);
    // Return 200 to CloudMailin to prevent repeated retries; you can change to 500 if you want retries
    return res.status(200).send("Received (error)");
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
