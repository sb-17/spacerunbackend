const express = require('express');
const keys = require('./config/keys');
const bodyParser = require("body-parser");

const app = express();

const mongoose = require('mongoose');
mongoose.connect(keys.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });

app.use(bodyParser.urlencoded({ extended: false }));

const auth = require('./routes/auth');
app.use('/auth', auth.router);

app.listen(keys.port, () => {
    console.log("Server started on port " + keys.port);
});