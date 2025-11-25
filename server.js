/**
 * topfreemail-backend - server.js
 *
 * Receives CloudMailin POSTs at /webhook, saves them to Postgres (Supabase),
 * and auto-creates inbox records when needed.
 */

const express = require("express");
const multer = require("multer");
const { Pool } = require("pg");
const crypto = require("crypto");
const dns = require("dns");

// ---------------------------
// FIX 1: Force IPv4 DNS first
// ---------------------------
if (dns?.setDefaultResultOrder) {
  dns.setDefaultResultOrder("ipv4first");
}

const app = express();
const upload = multer(); // in-memory parser (we only store metadata)

// Basic body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// -------------------------------------------------------------
// FIX 2: DATABASE_URL preferred + SSL handling + IPv4 reliability
// -------------------------------------------------------------
const connectionString =
  process.env.DATABASE_URL ||
  (() => {
    const host = process.env.DB_HOST || "localhost";
    const port = process.env.DB_PORT
      ? parseInt(process.env.DB_PORT, 10)
      : 5432;
    const database = process.env.DB_NAME || "postgres";
    const user = process.env.DB_USER || "postgres";
    const password = process.env.DB_PASSWORD || "";

    return `postgres://${encodeURIComponent(
      user
    )}:${encodeURIComponent(password)}@${host}:${port}/${database}?sslmode=require`;
  })();

const pool = new Pool({
  connectionString,
  ssl: { rejectUnauthorized: false }, // required for Supabase pooler
});

// Generate 16-char token
function genToken16() {
  return crypto.randomBytes(8).toString("hex");
}

// Ensure inbox exists
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
      await client.query(
        `update public.inboxes set last_active = now() where id = $1`,
        [row.id]
      );
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

// Save message
async function saveMessage(
  inboxId,
  mailFrom,
  mailTo,
  subject,
  body,
  raw,
  hasAttachments
) {
  const q = `
    insert into public.messages
      (inbox_id, mail_from, mail_to, subject, body, raw, has_attachments, created_at)
    values ($1, $2, $3, $4, $5, $6, $7, now())
    returning id
  `;
  const vals = [
    inboxId,
    mailFrom || null,
    mailTo || null,
    subject || null,
    body || null,
    raw || null,
    !!hasAttachments,
  ];

  const res = await pool.query(q, vals);
  return res.rows[0];
}

// Webhook
app.post("/webhook", upload.any(), async (req, res) => {
  try {
    console.log("📩 Incoming Email from CloudMailin");

    const fields = req.body || {};
    const files = req.files || [];

    const first = (v) => (Array.isArray(v) ? v[0] : v);

    const mailFrom =
      first(fields.from) || first(fields["envelope-from"]) || null;

    let mailTo =
      first(fields.to) || first(fields["envelope-to"]) || null;

    if (Array.isArray(mailTo)) mailTo = mailTo[0];
    if (typeof mailTo === "string" && mailTo.includes(",")) {
      mailTo = mailTo.split(",")[0].trim();
    }

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

    console.log(
      "from:",
      mailFrom,
      "to:",
      mailTo,
      "subject:",
      subject,
      "attachments:",
      files.length
    );

    if (!mailTo) {
      console.warn("No recipient found in payload.");
      await pool.query(
        `insert into public.messages
         (inbox_id, mail_from, mail_to, subject, body, raw, has_attachments, created_at)
         values (null, $1, null, $2, $3, $4, $5, now())`,
        [mailFrom, subject, body, raw, files.length > 0]
      );
      return res.status(200).send("Received - no recipient");
    }

    const inbox = await ensureInbox(mailTo);
    const saved = await saveMessage(
      inbox.id,
      mailFrom,
      mailTo,
      subject,
      body,
      raw,
      files.length > 0
    );

    console.log(`Saved message ${saved.id} for inbox ${inbox.address}`);
    return res.status(200).send("Received");
  } catch (err) {
    console.error("Error handling webhook:", err);
    return res.status(200).send("Received (error)");
  }
});

// Health
app.get("/", (req, res) => {
  res.send("TopFreeMail backend is running");
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
