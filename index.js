const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const userRoutes = require('./routes/routes');

dotenv.config();
const app = express();

app.use(bodyParser.json());
app.use('/images', express.static('public/images')); // optional static path
app.use('/api', userRoutes);

app.get('/', (req, res) => {
  res.send('Welcome to the HVAC Answers App');
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
