require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Conectado ao MongoDB"))
  .catch((err) => console.log(err));

app.use(cors());
app.use("/api/auth", require("./routes/auth"));
app.use("/api", require("./routes/keys"));
app.use("/api", require("./routes/documents"));

app.listen(PORT, () => {
  console.log(`Servidor na porta: ${PORT}`);
});
