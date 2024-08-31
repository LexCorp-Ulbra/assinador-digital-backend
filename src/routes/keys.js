const express = require('express');
const crypto = require('crypto');
const User = require('../models/User');
const authenticateToken = require('../middleware/authenticateToken');
const router = express.Router();

router.post('/keys', authenticateToken, async (req, res) => {
    try {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
        });

        const user = await User.findByIdAndUpdate(req.user.id, { publicKey, privateKey }, { new: true });
        res.status(201).json({ message: 'Chaves geradas com sucesso', publicKey: user.publicKey });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao gerar chaves' });
    }
});

router.delete('/keys', authenticateToken, async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.user.id, { publicKey: null, privateKey: null });
        res.status(200).json({ message: 'Chaves deletadas com sucesso' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao deletar chaves' });
    }
});

module.exports = router;
