// src/models/Document.js

const mongoose = require("mongoose");

const DocumentSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
  },
  content: {
    type: String, // Ou Buffer, dependendo de como você armazena o conteúdo
    required: true,
  },
  signature: {
    type: String, // Armazenando em Base64
    default: null,
  },
  certificate: {
    type: String, // PEM format
    default: null,
  },
  signedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null,
  },
  signedAt: {
    type: Date,
    default: null,
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("Document", DocumentSchema);
