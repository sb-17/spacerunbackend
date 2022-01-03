const express = require('express');
var cors = require('cors');
const keys = require('./config/keys');
const bodyParser = require("body-parser");

const app = express();

const mongoose = require('mongoose');
mongoose.connect(keys.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ extended: false }));
app.use(bodyParser.urlencoded({ extended: false }));

const auth = require('./routes/auth');
const score = require('./routes/score');
app.use('/auth', auth.router);
app.use('/score', score);

app.listen(keys.port, () => {
    console.log("Server started on port " + keys.port);
});