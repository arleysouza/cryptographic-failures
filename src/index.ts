import express, { Request, Response, NextFunction } from "express";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import router from "./routes";
import path from "path";
import fs from "fs";
import https from "https";

// Carrega as variáveis de ambiente definidas no arquivo .env
dotenv.config();

// Inicializa a aplicação Express
const app = express();

// Define a porta utilizada pelo servidor
const PORT = process.env.PORT || 3000;

// Middleware para permitir o envio de dados em formato JSON no corpo das requisições
app.use(express.json());

// Middleware para permitir o envio de dados em formato URL-encoded no corpo das requisições
app.use(express.urlencoded({ extended: true }));

// Middleware para cookies
app.use(cookieParser());

// Middleware para servir arquivos estáticos a partir do diretório "public"
app.use(express.static("public"));

// Certificados autoassinados
const options = {
  key: fs.readFileSync(path.join(__dirname, "./certs/key.pem")),
  cert: fs.readFileSync(path.join(__dirname, "./certs/cert.pem")),
};

// Inicializa o servidor na porta definida
https.createServer(options, app).listen(3001, () => {
  console.log(`Servidor rodando em https://localhost:${PORT}`);
});

app.use("/api", router);

app.use(function (_: Request, res: Response) {
  res.status(404).json({ error: "Rota não encontrada" });
});
