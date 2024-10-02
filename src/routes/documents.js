const express = require("express");
const crypto = require("crypto");
const Document = require("../models/Document");
const User = require("../models/User");
const authenticateToken = require("../middleware/authenticateToken");
const forge = require("node-forge");
const fs = require("fs");
const multer = require("multer");
const path = require("path");
const router = express.Router();
const upload = multer({ dest: "documentos/" });

router.post(
  "/documents/sign",
  upload.fields([
    { name: "documento", maxCount: 1 },
    { name: "chavePrivada", maxCount: 1 },
  ]),
  (req, res) => {
    if (!req.files || !req.files["documento"] || !req.files["chavePrivada"]) {
      return res
        .status(400)
        .send("Documento e chave privada são obrigatórios.");
    }

    const documentoPath = path.join(
      __dirname,
      "../",
      req.files["documento"][0].path
    );
    const documento = fs.readFileSync(documentoPath, "utf8");

    const chavePrivadaPath = path.join(
      __dirname,
      "../",
      req.files["chavePrivada"][0].path
    );
    const privateKeyPem = fs.readFileSync(chavePrivadaPath, "utf8");
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

    const md = forge.md.sha256.create();
    md.update(documento, "utf8");

    const assinatura = privateKey.sign(md);
    const assinaturaBase64 = forge.util.encode64(assinatura);

    const assinaturaPath = "documentos/assinatura_digital.txt";
    fs.writeFileSync(assinaturaPath, assinaturaBase64);

    res.download(assinaturaPath, "assinatura_digital.txt", (err) => {
      if (err) {
        console.error("Erro ao enviar arquivo:", err);
      } else {
        console.log("Arquivo de assinatura enviado.");
      }
    });
  }
);

router.post(
  "/documents/validate",
  upload.fields([
    { name: "assinaturaDigital", maxCount: 1 },
    { name: "documento", maxCount: 1 },
    { name: "certificado", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
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

      const assinaturaPath = path.join(
        __dirname,
        "../",
        req.files["assinaturaDigital"][0].path
      );
      const documentoPath = path.join(
        __dirname,
        "../",
        req.files["documento"][0].path
      );
      const certificadoPath = path.join(
        __dirname,
        "../",
        req.files["certificado"][0].path
      );

      const assinaturaBase64 = fs.readFileSync(assinaturaPath, "utf8");
      const documento = fs.readFileSync(documentoPath, "utf8");
      const certificadoPem = fs.readFileSync(certificadoPath, "utf8");

      const assinatura = forge.util.decode64(assinaturaBase64);

      const cert = forge.pki.certificateFromPem(certificadoPem);
      const publicKey = cert.publicKey;

      const md = forge.md.sha256.create();
      md.update(documento, "utf8");

      const isValid = publicKey.verify(md.digest().bytes(), assinatura);

      res.status(200).json({ valid: isValid });
    } catch (error) {
      console.error("Erro ao validar assinatura:", error);
      res.status(500).json({ error: "Erro ao validar assinatura" });
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

router.post("/documents/:id/sign", authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const document = await Document.findById(id);

    if (!document) {
      return res.status(404).json({ error: "Documento não encontrado" });
    }

    if (document.createdBy.toString() !== req.user.id) {
      return res
        .status(403)
        .json({ error: "Você não tem permissão para assinar este documento" });
    }

    if (document.signature) {
      return res.status(400).json({ error: "Este documento já foi assinado" });
    }

    const signedAt = new Date();
    const user = await User.findById(req.user.id);
    const sign = crypto.createSign("SHA256");
    sign.update(document.content + signedAt);
    sign.end();

    const signature = sign.sign(user.privateKey, "hex");

    document.signedBy = req.user.id;
    document.signature = signature;
    document.signedAt = signedAt;

    await document.save();

    res
      .status(200)
      .json({ message: "Documento assinado com sucesso", document });
  } catch (error) {
    res.status(500).json({ error: "Erro ao assinar documento" });
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

// router.post("/documents/validate", authenticateToken, async (req, res) => {
//   const { documentId, signature } = req.body;

//   try {
//     const document = await Document.findById(documentId).populate("signedBy");

//     if (!document || !document.signedBy) {
//       return res
//         .status(400)
//         .json({ error: "Documento não assinado ou inexistente" });
//     }

//     const verify = crypto.createVerify("SHA256");
//     verify.update(document.content + document.signedAt);
//     verify.end();

//     const isValid = verify.verify(
//       document.signedBy.publicKey,
//       signature,
//       "hex"
//     );

//     res.status(200).json({ valid: isValid, signedAt: document.signedAt });
//   } catch (error) {
//     res.status(500).json({ error: "Erro ao validar assinatura" });
//   }
// });

module.exports = router;
