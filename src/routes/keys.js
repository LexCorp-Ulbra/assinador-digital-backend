const express = require("express");
const authenticateToken = require("../middleware/authenticateToken");
const router = express.Router();
const forge = require("node-forge");
const fs = require("fs");
const path = require("path");
const archiver = require("archiver");

router.post("/keys", authenticateToken, async (req, res) => {
  try {
    // Extrai os dados do corpo da solicitação (informações do certificado)
    const {
      countryName,
      stateOrProvinceName,
      localityName,
      organizationName,
      commonName,
      startDate,
      endDate,
    } = req.body;

    // Verifica se todos os campos obrigatórios foram fornecidos
    if (
      !countryName ||
      !stateOrProvinceName ||
      !localityName ||
      !organizationName ||
      !commonName
    ) {
      return res
        .status(400)
        .json({ error: "Todos os campos são obrigatórios." });
    }

    // 1. Gera o par de chaves RSA (pública e privada) para o Certificado CA Raiz
    const chavesRaiz = forge.pki.rsa.generateKeyPair(2048);
    const certificadoRaiz = forge.pki.createCertificate();
    certificadoRaiz.publicKey = chavesRaiz.publicKey; // Associa a chave pública ao certificado
    certificadoRaiz.serialNumber = Math.floor(Math.random() * 100000).toString(); // Número de série aleatório
    certificadoRaiz.validity.notBefore = startDate ? new Date(startDate) : new Date(); // Data de início
    certificadoRaiz.validity.notAfter = endDate ? new Date(endDate) : new Date();
    if (!endDate) {
      certificadoRaiz.validity.notAfter.setFullYear(
        certificadoRaiz.validity.notBefore.getFullYear() + 10
      ); // Validade de 10 anos para o CA raiz
    }

    // Definindo atributos do certificado CA raiz
    const atributosRaiz = [
      { name: "countryName", value: countryName },
      { shortName: "ST", value: stateOrProvinceName },
      { name: "localityName", value: localityName },
      { name: "organizationName", value: organizationName },
      { shortName: "CN", value: `${commonName} Root CA` }, // Nome comum para o CA raiz
    ];

    certificadoRaiz.setSubject(atributosRaiz); // Define os atributos do sujeito
    certificadoRaiz.setIssuer(atributosRaiz); // Define o emissor (autoassinado)
    certificadoRaiz.setExtensions([
      { name: "basicConstraints", cA: true }, // Certificado CA (pode assinar outros certificados)
      { name: "keyUsage", keyCertSign: true, digitalSignature: true }, // Permissão para assinar outros certificados
    ]);
    certificadoRaiz.sign(chavesRaiz.privateKey); // Certificado assinado com a chave privada do CA raiz

    // 2. Gera o par de chaves para o Certificado Intermediário
    const chavesIntermediario = forge.pki.rsa.generateKeyPair(2048);
    const certificadoIntermediario = forge.pki.createCertificate();
    certificadoIntermediario.publicKey = chavesIntermediario.publicKey; // Associa a chave pública ao certificado intermediário
    certificadoIntermediario.serialNumber = Math.floor(
      Math.random() * 100000
    ).toString(); // Número de série aleatório
    certificadoIntermediario.validity.notBefore = certificadoRaiz.validity.notBefore; // Mesma data de início do CA raiz
    certificadoIntermediario.validity.notAfter = certificadoRaiz.validity.notAfter; // Mesma validade do CA raiz

    // Definindo atributos do certificado intermediário
    const atributosIntermediario = [
      { name: "countryName", value: countryName },
      { shortName: "ST", value: stateOrProvinceName },
      { name: "localityName", value: localityName },
      { name: "organizationName", value: organizationName },
      { shortName: "CN", value: `${commonName} Intermediate CA` }, // Nome comum para o intermediário
    ];

    certificadoIntermediario.setSubject(atributosIntermediario); // Define os atributos do certificado intermediário
    certificadoIntermediario.setIssuer(atributosRaiz); // Certificado intermediário assinado pelo CA raiz
    certificadoIntermediario.setExtensions([
      { name: "basicConstraints", cA: true }, // Certificado intermediário pode assinar outros certificados
      { name: "keyUsage", keyCertSign: true, digitalSignature: true }, // Permissão para assinar certificados
    ]);
    certificadoIntermediario.sign(chavesRaiz.privateKey); // Certificado intermediário assinado pelo CA raiz

    // 3. Gera o par de chaves para o Certificado Final
    const chavesFinal = forge.pki.rsa.generateKeyPair(2048);
    const certificadoFinal = forge.pki.createCertificate();
    certificadoFinal.publicKey = chavesFinal.publicKey; // Associa a chave pública ao certificado final
    certificadoFinal.serialNumber = Math.floor(Math.random() * 100000).toString(); // Número de série aleatório
    certificadoFinal.validity.notBefore = new Date(); // Validade começa a partir da data atual
    certificadoFinal.validity.notAfter = new Date(); // Validade de 1 ano
    certificadoFinal.validity.notAfter.setFullYear(
      certificadoFinal.validity.notBefore.getFullYear() + 1
    );

    // Definindo atributos do certificado final
    const finalAttrs = [
      { name: "countryName", value: countryName },
      { shortName: "ST", value: stateOrProvinceName },
      { name: "localityName", value: localityName },
      { name: "organizationName", value: organizationName },
      { shortName: "CN", value: `${commonName} Final Certificate` }, // Nome comum para o certificado final
    ];

    certificadoFinal.setSubject(finalAttrs); // Define os atributos do certificado final
    certificadoFinal.setIssuer(atributosIntermediario); // Certificado final assinado pelo intermediário
    certificadoFinal.setExtensions([
      { name: "basicConstraints", cA: false }, // Não pode assinar outros certificados
      { name: "keyUsage", digitalSignature: true, keyEncipherment: true }, // Uso para assinatura digital e criptografia
    ]);
    certificadoFinal.sign(chavesIntermediario.privateKey); // Certificado final assinado pelo intermediário

    // 4. Converter certificados e chaves para formato PEM
    const certificadoRaizPem = forge.pki.certificateToPem(certificadoRaiz);
    const certificadoIntermediarioPem = forge.pki.certificateToPem(certificadoIntermediario);
    const certificadoFinalPem = forge.pki.certificateToPem(certificadoFinal);

    const chavePrivadaRaizPem = forge.pki.privateKeyToPem(chavesRaiz.privateKey);
    const chavePrivadaIntermediarioPem = forge.pki.privateKeyToPem(
      chavesIntermediario.privateKey
    );
    const chavePrivadaFinalPem = forge.pki.privateKeyToPem(chavesFinal.privateKey);

    // Define os caminhos para salvar a chave privada e o certificado no servidor
    const privateKeyPath = path.join(
      __dirname,
      "../documentos",
      `private_key_${req.user.id}.pem`
    );

    // Definir caminhos completos para salvar os arquivos PEM
    const certificadoRaizPath = path.join(__dirname, "../documentos/raiz_cert.pem");
    const certificadoIntermediarioPath = path.join(__dirname, "../documentos/intermediario_cert.pem");
    const certificadoFinalPath = path.join(__dirname, "../documentos/final_cert.pem");

    const chavePrivadaRaizPath = path.join(__dirname, "../documentos/raiz_key.pem");
    const chavePrivadaIntermediarioPath = path.join(__dirname, "../documentos/intermediario_key.pem");
    const chavePrivadaFinalPath = path.join(__dirname, "../documentos/final_key.pem");

    // Salva os certificados e chaves privadas nos arquivos correspondentes
    fs.writeFileSync(certificadoRaizPath, certificadoRaizPem);
    fs.writeFileSync(certificadoIntermediarioPath, certificadoIntermediarioPem);
    fs.writeFileSync(certificadoFinalPath, certificadoFinalPem);

    fs.writeFileSync(chavePrivadaRaizPath, chavePrivadaRaizPem);
    fs.writeFileSync(chavePrivadaIntermediarioPath, chavePrivadaIntermediarioPem);
    fs.writeFileSync(chavePrivadaFinalPath, chavePrivadaFinalPem);

    // 6. Compactação dos arquivos em um arquivo ZIP
    const zip = archiver("zip", { zlib: { level: 9 } });
    res.attachment(`certificados_${Date.now()}.zip`); // Define o nome do arquivo ZIP para download
    zip.pipe(res); // Envia o ZIP através da resposta HTTP

    // Adiciona os arquivos ao arquivo ZIP
    zip.file(certificadoRaizPath, { name: "raiz_cert.pem" });
    zip.file(certificadoIntermediarioPath, { name: "intermediario_cert.pem" });
    zip.file(certificadoFinalPath, { name: "final_cert.pem" });

    zip.file(chavePrivadaRaizPath, { name: "raiz_key.pem" });
    zip.file(chavePrivadaIntermediarioPath, { name: "intermediario_key.pem" });
    zip.file(chavePrivadaFinalPath, { name: "final_key.pem" });

    // Finaliza o processo de compactação e remove os arquivos temporários após o download
    zip.finalize();
    zip.on("finish", () => {
      fs.unlinkSync(certPath);  // Remove o arquivo certificado
      fs.unlinkSync(privateKeyPath);  // Remove o arquivo chave privada
    });

    // Tratamento de erros durante a geração do arquivo ZIP
    zip.on("error", (err) => {
      console.error("Erro ao gerar zip:", err);
      return res.status(500).send("Erro ao gerar certificado.");
    });
  } catch (error) {
    // Captura qualquer erro no processo de geração das chaves e certificados
    console.error("Erro ao gerar chaves:", error);
    res.status(500).json({ error: "Erro ao gerar chaves" });
  }
});
module.exports = router;
