const express = require("express");
const app = express();

// Parse incoming CloudMailin email (multipart/form-data)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Main webhook endpoint
app.post("/webhook", async (req, res) => {
  console.log("📩 Incoming Email from CloudMailin");

  // Log raw body to Railway logs
  console.log(req.body);

  // Always respond 200 so CloudMailin knows we received it
  res.status(200).send("Received");
});

// Health check
app.get("/", (req, res) => {
  res.send("TopFreeMail backend is running");
});

// Railway gives PORT env var
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
