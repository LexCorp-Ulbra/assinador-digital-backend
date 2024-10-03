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
    // Extraindo parâmetros do corpo da solicitação
    const {
      countryName,
      stateOrProvinceName,
      localityName,
      organizationName,
      commonName,
      startDate,       // Opcional, se você quiser personalizar a validade
      endDate,         // Opcional
    } = req.body;

    // Validação básica dos parâmetros
    if (!countryName || !stateOrProvinceName || !localityName || !organizationName || !commonName) {
      return res.status(400).json({ error: "Todos os campos são obrigatórios." });
    }

    // Gera o par de chaves RSA (pública e privada) com 2048 bits usando a biblioteca forge
    const { privateKey, publicKey } = forge.pki.rsa.generateKeyPair(2048);

    // Converte a chave pública e privada para o formato PEM (texto legível)
    const publicKeyPem = forge.pki.publicKeyToPem(publicKey);
    const privateKeyPem = forge.pki.privateKeyToPem(privateKey);

    // Criação de um certificado digital X.509
    const cert = forge.pki.createCertificate();
    cert.publicKey = publicKey;  // Associa a chave pública ao certificado
    cert.serialNumber = (Math.floor(Math.random() * 100000)).toString();  // Número de série único
    cert.validity.notBefore = startDate ? new Date(startDate) : new Date();  // Data de início de validade
    cert.validity.notAfter = endDate ? new Date(endDate) : new Date();
    if (!endDate) {
      cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);  // Validade padrão de 1 ano
    }

    // Atributos do certificado baseados nos parâmetros fornecidos
    const attrs = [
      {
        name: "countryName",
        value: countryName,
      },
      {
        shortName: "ST",
        value: stateOrProvinceName,
      },
      {
        name: "localityName",
        value: localityName,
      },
      {
        name: "organizationName",
        value: organizationName,
      },
      {
        shortName: "CN",
        value: commonName,
      },
    ];

    cert.setSubject(attrs);  // Define os atributos do certificado
    cert.setIssuer(attrs);   // Define o emissor do certificado (autoassinado)
    cert.sign(privateKey);   // Assina o certificado usando a chave privada gerada
    const certPem = forge.pki.certificateToPem(cert);  // Converte o certificado para o formato PEM

    // Pasta temporária única para cada usuário
    const tempDir = path.join(__dirname, "../../documentos", `temp_${req.user.id}_${Date.now()}`);
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir);
    }

    // Caminhos dos arquivos
    const privateKeyPath = path.join(tempDir, `private_key_${req.user.id}.pem`);
    const certPath = path.join(tempDir, "certificado.pem");

    // Salva a chave privada e o certificado
    fs.writeFileSync(privateKeyPath, privateKeyPem);
    fs.writeFileSync(certPath, certPem);

    // Verifica se os arquivos foram salvos
    if (!fs.existsSync(certPath) || !fs.existsSync(privateKeyPath)) {
      return res.status(500).send("Erro ao salvar as chaves ou certificado.");
    }

    // Compactação em arquivo ZIP
    const zip = archiver('zip', { zlib: { level: 9 } });
    res.attachment(`chaves_${Date.now()}.zip`);  // Nome único para o ZIP
    zip.pipe(res);

    // Adiciona os arquivos ao ZIP
    zip.file(certPath, { name: 'certificado.pem' });
    zip.file(privateKeyPath, { name: 'chave_privada.pem' });

    // Finaliza e remove arquivos temporários
    zip.finalize();
    zip.on('finish', () => {
      fs.rmSync(tempDir, { recursive: true, force: true });  // Remove a pasta temporária
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

module.exports = router;
