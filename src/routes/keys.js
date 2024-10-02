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
    // Gera o par de chaves RSA (pública e privada) com 2048 bits usando a biblioteca forge
    const { privateKey, publicKey } = forge.pki.rsa.generateKeyPair(2048);

    // Converte a chave pública e privada para o formato PEM (texto legível)
    const publicKeyPem = forge.pki.publicKeyToPem(publicKey);
    const privateKeyPem = forge.pki.privateKeyToPem(privateKey);

    // Criação de um certificado digital X.509
    const cert = forge.pki.createCertificate();
    cert.publicKey = publicKey;  // Associa a chave pública ao certificado
    cert.serialNumber = "01";  // Define o número de série do certificado (pode ser um valor único)
    cert.validity.notBefore = new Date();  // Certificado válido a partir da data atual
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);  // Define a validade de 1 ano

    // Atributos do certificado, como país, estado, localidade, organização e nome comum
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

    cert.setSubject(attrs);  // Define os atributos do certificado
    cert.setIssuer(attrs);  // Define o emissor do certificado (autoassinado)
    cert.sign(privateKey);  // Assina o certificado usando a chave privada gerada
    const certPem = forge.pki.certificateToPem(cert);  // Converte o certificado para o formato PEM

    // Atualiza o usuário no banco de dados com a chave pública
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { publicKey: publicKeyPem },  // Armazena apenas a chave pública no banco de dados
      { new: true }
    );

    // Define os caminhos para salvar a chave privada e o certificado no servidor
    const privateKeyPath = path.join(
      __dirname,
      "../documentos",
      `private_key_${req.user.id}.pem`
    );
    const certPath = path.join(__dirname, "../documentos/certificado.pem");

    // Salva a chave privada e o certificado em arquivos no sistema de arquivos
    fs.writeFileSync(privateKeyPath, privateKeyPem);
    fs.writeFileSync(certPath, certPem);

    // Define o caminho do arquivo ZIP onde os dois arquivos serão compactados
    const zipFilePath = path.join(__dirname, "../documentos/chaves.zip");
    const zip = archiver('zip', {
      zlib: { level: 9 }  // Nível de compressão máxima para o arquivo ZIP
    });

    // Define o arquivo de saída como "chaves.zip" no cabeçalho da resposta
    res.attachment('chaves.zip');

    // Envia os dados compactados diretamente no stream de resposta
    zip.pipe(res);

    // Adiciona os arquivos do certificado e da chave privada ao arquivo ZIP
    zip.file(certPath, { name: 'certificado.pem' });
    zip.file(privateKeyPath, { name: 'chave_privada.pem' });

    // Finaliza o processo de compactação e fecha o arquivo ZIP
    zip.finalize();

    // Após finalizar o envio do ZIP, remove os arquivos temporários (certificado e chave privada)
    zip.on('finish', () => {
      fs.unlinkSync(certPath);  // Remove o arquivo certificado
      fs.unlinkSync(privateKeyPath);  // Remove o arquivo chave privada
    });

    // Em caso de erro durante a criação do arquivo ZIP, envia uma resposta de erro ao cliente
    zip.on('error', (err) => {
      console.error("Erro ao gerar zip:", err);
      return res.status(500).send("Erro ao gerar certificado.");
    });
  } catch (error) {
    // Captura qualquer erro durante o processo e envia uma resposta de erro ao cliente
    console.error("Erro ao gerar chaves:", error);
    res.status(500).json({ error: "Erro ao gerar chaves" });
  }
});

module.exports = router;
