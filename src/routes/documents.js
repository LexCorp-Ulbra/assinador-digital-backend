const express = require("express");
const crypto = require("crypto");
const Document = require("../models/Document");
const User = require("../models/User");
const authenticateToken = require("../middleware/authenticateToken");
const forge = require("node-forge");
const fs = require("fs");
const multer = require("multer");
const path = require("path");
const archiver = require("archiver"); // Biblioteca para criar ZIPs
const router = express.Router();
const upload = multer({ dest: "documentos/" }); // Configuração do multer

// ROTAS HELYEZER

// Endpoint para assinar um documento com o certificado e chave privada (do certificado final) fornecidos pelo cliente
router.post(
  "/documentos/assinar",
  upload.fields([
    { name: "documento", maxCount: 1 },
    { name: "chavePrivada", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      // Verificar se todos os arquivos foram enviados
      if (!req.files || !req.files["documento"] || !req.files["chavePrivada"]) {
        return res
          .status(400)
          .send("Documento e chave privada são obrigatórios.");
      }

      // Carregar os caminhos dos arquivos enviados
      const documentPath = path.join(
        __dirname,
        "../",
        req.files["documento"][0].path
      );
      const privateKeyPath = path.join(
        __dirname,
        "../",
        req.files["chavePrivada"][0].path
      );

      // Ler o conteúdo dos arquivos
      const documentContent = fs.readFileSync(documentPath); // Ler conteúdo em binário
      const privateKeyPem = fs.readFileSync(privateKeyPath, "utf8");

      // Converter a chave privada do formato PEM para objeto utilizável com forge
      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

      // Gerar o hash do documento usando SHA-256
      const md = forge.md.sha256.create();
      md.update(documentContent.toString("binary")); // Usar o conteúdo binário do documento

      // Assinar o hash do documento com a chave privada
      const signature = privateKey.sign(md);

      // Converter a assinatura para base64 (para armazenamento)
      const signatureBase64 = forge.util.encode64(signature);

      // Caminho para salvar o arquivo de assinatura
      const signaturePath = path.join(
        __dirname,
        "../documentos/assinatura_digital.txt"
      );

      // Salvar a assinatura em um arquivo separado
      fs.writeFileSync(signaturePath, signatureBase64);

      // Limpeza: remover os arquivos temporários após a assinatura
      fs.unlinkSync(documentPath);
      fs.unlinkSync(privateKeyPath);

      // Retornar o arquivo de assinatura para download
      res.download(signaturePath, "assinatura_digital.txt", (err) => {
        if (err) {
          console.error("Erro ao enviar arquivo:", err);
          res.status(500).send("Erro ao enviar arquivo de assinatura.");
        } else {
          console.log("Arquivo de assinatura enviado com sucesso.");
        }
      });
    } catch (error) {
      console.error("Erro ao assinar documento:", error);
      res.status(500).json({ error: "Erro ao assinar documento" });
    }
  }
);

router.post(
  "/documentos/validar", // Definindo a rota POST para validar a assinatura de documentos
  upload.fields([
    // Configuração do multer para receber os arquivos (assinatura digital, documento, e certificado)
    { name: "assinaturaDigital", maxCount: 1 }, // Aceita um arquivo chamado 'assinaturaDigital'
    { name: "documento", maxCount: 1 }, // Aceita um arquivo chamado 'documento'
    { name: "certificado", maxCount: 1 }, // Aceita um arquivo chamado 'certificado'
  ]),
  async (req, res) => {
    try {
      // Verifica se todos os arquivos necessários (assinatura, documento, e certificado) foram enviados
      if (
        !req.files ||
        !req.files["assinaturaDigital"] ||
        !req.files["documento"] ||
        !req.files["certificado"]
      ) {
        return res
          .status(400)
          .send(
            "Todos os arquivos são obrigatórios: assinaturaDigital, documento e certificado."
          );
      }

      // Caminho completo do arquivo de assinatura digital recebido
      const assinaturaPath = path.join(
        __dirname,
        "../",
        req.files["assinaturaDigital"][0].path
      );
      // Caminho completo do arquivo de documento recebido
      const documentoPath = path.join(
        __dirname,
        "../",
        req.files["documento"][0].path
      );
      // Caminho completo do arquivo de certificado digital recebido
      const certificadoPath = path.join(
        __dirname,
        "../",
        req.files["certificado"][0].path
      );

      // Leitura dos arquivos recebidos
      const assinaturaBase64 = fs.readFileSync(assinaturaPath, "utf8"); // Assinatura em base64
      const documento = fs.readFileSync(documentoPath); // Ler o documento como binário (sem 'utf8')
      const certificadoPem = fs.readFileSync(certificadoPath, "utf8"); // Certificado em formato PEM

      // Decodificar a assinatura de Base64 para binário
      const assinatura = forge.util.decode64(assinaturaBase64);

      // Carregar o certificado do arquivo PEM e extrair a chave pública
      const cert = forge.pki.certificateFromPem(certificadoPem);
      const publicKey = cert.publicKey;

      // Criar o hash do documento usando SHA-256
      const md = forge.md.sha256.create();
      md.update(documento.toString("binary")); // Atualizar o hash com o conteúdo binário do documento

      // Verificar a assinatura usando a chave pública e o hash do documento
      const isValid = publicKey.verify(md.digest().bytes(), assinatura);

      // Limpeza: remover os arquivos temporários após a validação
      fs.unlinkSync(assinaturaPath);
      fs.unlinkSync(documentoPath);
      fs.unlinkSync(certificadoPath);

      // Retornar o resultado da validação (true ou false)
      res.status(200).json({ valid: isValid });
    } catch (error) {
      console.error("Erro ao validar assinatura:", error);
      res.status(500).json({ error: "Erro ao validar assinatura" });
    }
  }
);

// ROTAS CORDEIRO

// Rota para validar a assinatura do documento existente
router.post(
  "/documents/:id/validate",
  authenticateToken,
  upload.single("signature"),
  async (req, res) => {
    const { id } = req.params;

    try {
      console.log(
        `Recebendo requisição para validar assinatura do documento ID: ${id}`
      );
      const document = await Document.findById(id).populate("signedBy");
      console.log("Documento encontrado:", document);

      if (!document) {
        console.log("Documento não encontrado.");
        return res.status(404).json({ error: "Documento não encontrado." });
      }

      if (!document.signature || !document.certificate) {
        console.log("Documento não está assinado.");
        return res
          .status(400)
          .json({ error: "Este documento não está assinado." });
      }

      // Recuperar o conteúdo do documento
      const documentContent = document.content;
      console.log("Conteúdo do Documento:", documentContent);

      // Variável para armazenar a assinatura a ser validada
      let signatureBuffer;

      if (req.file) {
        // Se um arquivo de assinatura foi enviado, use-o
        const uploadedSignaturePath = req.file.path;
        const uploadedSignature = fs.readFileSync(
          uploadedSignaturePath,
          "utf8"
        );

        // Supondo que a assinatura no arquivo está em Base64
        signatureBuffer = Buffer.from(uploadedSignature, "base64");
        console.log("Assinatura enviada via upload:", uploadedSignature);

        // Remova o arquivo temporário após a leitura
        fs.unlinkSync(uploadedSignaturePath);
      } else {
        // Se não houver arquivo enviado, use a assinatura armazenada no banco de dados
        const signatureBase64 = document.signature;
        signatureBuffer = Buffer.from(signatureBase64, "base64");
        console.log(
          "Assinatura armazenada no banco de dados:",
          signatureBase64
        );
      }

      // Converter o certificado PEM para objeto
      const cert = forge.pki.certificateFromPem(document.certificate);
      const publicKeyPem = forge.pki.publicKeyToPem(cert.publicKey);
      const publicKey = crypto.createPublicKey(publicKeyPem);
      console.log("Chave pública extraída do certificado:", publicKeyPem);

      // Verificar a assinatura usando o módulo crypto
      const verify = crypto.createVerify("SHA256");
      verify.update(documentContent);
      verify.end();

      const isValid = verify.verify(publicKey, signatureBuffer);
      console.log("Resultado da verificação:", isValid);

      res.status(200).json({
        valid: isValid,
        signedBy: document.signedBy.username,
        signedAt: document.signedAt,
      });
    } catch (error) {
      console.error("Erro ao validar assinatura:", error);
      res.status(500).json({ error: "Erro ao validar assinatura." });
    }
  }
);

router.post("/documents/:id/sign", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { signature, certificate } = req.body;

  // Adicione logs para verificar o que está sendo recebido
  console.log("Recebido assinatura:", signature);
  console.log("Recebido certificado:", certificate);

  // Verifica se a assinatura e o certificado foram fornecidos
  if (!signature || !certificate) {
    return res
      .status(400)
      .json({ error: "Assinatura e certificado são obrigatórios." });
  }

  try {
    const document = await Document.findById(id);

    // Verifica se o documento existe
    if (!document) {
      return res.status(404).json({ error: "Documento não encontrado" });
    }

    // Verifica se o usuário é o autor do documento
    if (document.createdBy.toString() !== req.user.id) {
      return res
        .status(403)
        .json({ error: "Você não tem permissão para assinar este documento" });
    }

    // Verifica se o documento já foi assinado
    if (document.signature) {
      return res.status(400).json({ error: "Este documento já foi assinado" });
    }

    // Assinatura já está em Base64
    const signatureBase64 = signature;
    console.log("Assinatura em Base64:", signatureBase64);

    // Atualiza o documento com a assinatura e o certificado
    document.signature = signatureBase64;
    document.signedBy = req.user.id;
    document.signedAt = new Date();
    document.certificate = certificate;

    await document.save();
    console.log("Documento após salvar:", document);

    // Define o diretório para salvar as assinaturas
    const assinaturaDir = path.join(__dirname, "../assinaturas");

    // Cria o diretório se não existir
    if (!fs.existsSync(assinaturaDir)) {
      fs.mkdirSync(assinaturaDir, { recursive: true });
    }

    // Define o caminho completo do arquivo de assinatura
    const assinaturaPath = path.join(
      assinaturaDir,
      `assinatura_digital_${id}.txt`
    );

    // Salva a assinatura no arquivo (em Base64)
    fs.writeFileSync(assinaturaPath, signatureBase64, "utf8");
    console.log("Assinatura salva em:", assinaturaPath);

    res
      .status(200)
      .json({ message: "Documento assinado com sucesso", document });
  } catch (error) {
    console.error("Erro ao assinar documento:", error);
    res.status(500).json({ error: "Erro ao assinar documento" });
  }
});

// Rota para baixar a assinatura digital em formato ZIP
router.get(
  "/documents/:id/signature/zip",
  authenticateToken,
  async (req, res) => {
    const { id } = req.params;

    try {
      const document = await Document.findById(id);

      if (!document) {
        return res.status(404).json({ error: "Documento não encontrado" });
      }

      // Verifica se o usuário é o autor ou o assinante
      if (
        document.createdBy.toString() !== req.user.id &&
        (!document.signedBy || document.signedBy.toString() !== req.user.id)
      ) {
        return res.status(403).json({
          error: "Você não tem permissão para acessar esta assinatura.",
        });
      }

      if (!document.signature) {
        return res
          .status(400)
          .json({ error: "Este documento ainda não foi assinado." });
      }

      const assinaturaDir = path.join(__dirname, "../assinaturas");
      const assinaturaPath = path.join(
        assinaturaDir,
        `assinatura_digital_${id}.txt`
      );

      // Verifica se o arquivo de assinatura existe
      if (!fs.existsSync(assinaturaPath)) {
        return res
          .status(404)
          .json({ error: "Arquivo de assinatura não encontrado." });
      }

      // Criar o arquivo ZIP
      const zipFileName = `assinatura_digital_${id}.zip`;
      res.attachment(zipFileName);

      const archive = archiver("zip", {
        zlib: { level: 9 }, // Nível de compressão
      });

      // Lidar com erro de arquivo ZIP
      archive.on("error", (err) => {
        console.error("Erro ao criar o arquivo ZIP:", err);
        res.status(500).json({ error: "Erro ao criar o arquivo ZIP." });
      });

      // Pipe (enviar) o conteúdo ZIP para o cliente
      archive.pipe(res);

      // Adicionar o arquivo de assinatura ao ZIP
      archive.file(assinaturaPath, { name: `assinatura_digital_${id}.txt` });

      // Finaliza o processo de criação do ZIP
      archive.finalize();
    } catch (error) {
      console.error("Erro ao processar o download da assinatura:", error);
      res
        .status(500)
        .json({ error: "Erro ao processar o download da assinatura." });
    }
  }
);

router.post("/documents", authenticateToken, async (req, res) => {
  const { title, content, signDocument } = req.body;

  let signature = null;
  let signedAt = null;
  if (signDocument) {
    signedAt = new Date();
    const user = await User.findById(req.user.id);
    const sign = crypto.createSign("SHA256");
    sign.update(content + signedAt);
    sign.end();
    signature = sign.sign(user.privateKey, "hex");
  }

  const newDocument = new Document({
    title,
    content,
    signedBy: signDocument ? req.user.id : null,
    signature,
    createdBy: req.user.id,
    signedAt,
  });

  try {
    const savedDocument = await newDocument.save();
    res.status(201).json({
      message: "Documento criado com sucesso",
      document: savedDocument,
    });
  } catch (error) {
    res.status(500).json({ error: "Erro ao criar documento" });
  }
});

router.get("/documents", authenticateToken, async (req, res) => {
  try {
    const documents = await Document.find().populate([
      { path: "createdBy", select: "username email publicKey" },
      { path: "signedBy", select: "username email publicKey" },
    ]);
    res.status(200).json(documents);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar documentos" });
  }
});

router.get("/documents/mydocuments", authenticateToken, async (req, res) => {
  try {
    const documents = await Document.find({ createdBy: req.user.id }).populate([
      { path: "createdBy", select: "username email publicKey" },
      { path: "signedBy", select: "username email publicKey" },
    ]);
    res.json(documents);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar documentos" });
  }
});

router.get("/documents/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const document = await Document.findById(id).populate([
      { path: "createdBy", select: "username email publicKey" },
      { path: "signedBy", select: "username email publicKey" },
    ]);
    if (!document) {
      return res.status(404).json({ error: "Documento não encontrado" });
    }
    res.status(200).json(document);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar documento" });
  }
});

module.exports = router;
