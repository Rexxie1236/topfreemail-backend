const express = require('express');
const multer = require('multer');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const upload = multer();

app.get('/', (req, res) => {
  res.send('OK');
});

app.post('/webhook', upload.any(), (req, res) => {
  console.log('--- Incoming webhook ---');
  console.log('Fields:', req.body);
  console.log('Files:', req.files);

  res.status(200).send({ status: 'ok' });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
