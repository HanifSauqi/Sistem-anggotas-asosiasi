const express = require('express');
const { register, login } = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');
const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/profile', authMiddleware, (req, res) => {
    res.json({ message: `Selamat datang, ${req.user.id}` });
});

module.exports = router;
