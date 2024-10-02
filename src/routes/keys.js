const express = require("express");
const User = require("../models/User");
const authenticateToken = require("../middleware/authenticateToken");
const router = express.Router();
const forge = require("node-forge");
const fs = require("fs");
const path = require("path");
const archiver = require("archiver");

router.post("/keys", authenticateToken, async (req, res) => {
  try {
    const { privateKey, publicKey } = forge.pki.rsa.generateKeyPair(2048);

    const publicKeyPem = forge.pki.publicKeyToPem(publicKey);
    const privateKeyPem = forge.pki.privateKeyToPem(privateKey);

    const cert = forge.pki.createCertificate();
    cert.publicKey = publicKey;
    cert.serialNumber = "01";
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + 1
    );

    const attrs = [
      {
        name: "countryName",
        value: "BR",
      },
      {
        shortName: "ST",
        value: "TO",
      },
      {
        name: "localityName",
        value: "Palmas",
      },
      {
        name: "organizationName",
        value: "FC Solutions",
      },
      {
        shortName: "CN",
        value: "Seu Nome",
      },
    ];

    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.sign(privateKey);
    const certPem = forge.pki.certificateToPem(cert);

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { publicKey: publicKeyPem },
      { new: true }
    );

    const privateKeyPath = path.join(
      __dirname,
      "../documentos",
      `private_key_${req.user.id}.pem`
    );

    const certPath = path.join(__dirname, "../documentos/certificado.pem");

    fs.writeFileSync(privateKeyPath, privateKeyPem);
    fs.writeFileSync(certPath, certPem);

    const zipFilePath = path.join(__dirname, "../documentos/chaves.zip");
    const zip = archiver('zip', {
      zlib: { level: 9 } 
    });

    res.attachment('chaves.zip');

    zip.pipe(res);

    zip.file(certPath, { name: 'certificado.pem' });
    zip.file(privateKeyPath, { name: 'chave_privada.pem' });

    zip.finalize();

    zip.on('finish', () => {
      fs.unlinkSync(certPath);
      fs.unlinkSync(privateKeyPath);
    });

    zip.on('error', (err) => {
      console.error("Erro ao gerar zip:", err);
      return res.status(500).send("Erro ao gerar certificado.");
    });
  } catch (error) {
    console.error("Erro ao gerar chaves:", error);
    res.status(500).json({ error: "Erro ao gerar chaves" });
  }
});

router.delete("/keys", authenticateToken, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.user.id, {
      publicKey: null,
      privateKey: null,
    });
    res.status(200).json({ message: "Chaves deletadas com sucesso" });
  } catch (error) {
    res.status(500).json({ error: "Erro ao deletar chaves" });
  }
});

module.exports = router;
