const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const express = require('express');
const RateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const keys = require('../config/keys');

const User = require('../models/User');

const rateLimit = RateLimit({ windowMs: 5000, max: 5 });

const router = express.Router();
router.use(rateLimit);
router.use(express.json());

router.post('/login', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    if (!username || !password) {
        res.status(400).send('Please provide a valid username and password');
        return;
    }

    const response = await User.find({ "username": username });

    if (!response.length > 0) return res.status(401).send('Invalid username or password');

    const userdata = JSON.parse(JSON.stringify(response[0]));
    const success = bcrypt.compareSync(password, userdata.password);

    delete userdata.password;

    if (success) {
        const token = jwt.sign(userdata, keys.jwtSecret, { algorithm: 'HS256' });
        userdata["token"] = token;
        res.status(200).send(JSON.stringify(userdata));
    }
    else {
        res.status(401).send('Invalid username or password');
    }
});

router.post('/', (req, res) => {
    const token = req.headers.authorization;
    if (!token) return res.status(403).send('Please provide an Authorization header');
    const authdata = this.auth(token);
    if (!authdata) return res.status(403).send('Invalid token');
    res.status(200).send(authdata.username.toString());
});

router.post('/register', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const bestScore = req.body.bestScore;
    const coins = req.body.coins;

    if (!username || !password) {
        res.status(400).send('Please provide a valid username and password');
        return;
    }

    const exists = await User.find({ "username": username });
    if (exists.length !== 0) {
        res.status(400).send('Username already in use');
        return;
    }

    const salt = await bcrypt.genSalt();
    const hashed = await bcrypt.hash(password, salt);
    if (!hashed) return res.status(500).send('An error occurred while hashing the password');

    const userdata = { username, password: hashed, bestScore, coins };

    const id = User.create(userdata)[0];
    userdata.id = id;
    res.status(200).send('Registration successful');
});

function auth(token) {
    try {
        const data = jwt.verify(token, keys.jwtSecret, { algorithms: ['HS256'] });
        data.token = token;
        return data;
    }
    catch (e) {
        return null;
    }
}

exports.auth = auth;
exports.router = router;