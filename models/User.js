const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    bestScore: {
        type: Number,
        required: true
    },
    coins: {
        type: Number,
        required: true
    }
});

module.exports = User = mongoose.model('user', UserSchema);