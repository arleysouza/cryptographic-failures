import { Request, Response } from "express";
import db from "./db";
import bcrypt from "bcrypt";
import crypto from "crypto";
import path from "path";
import fs from "fs";
import CryptoJS from "crypto-js";
import { encryptionIv, encryptionKey } from "../config/cryptoConfig";

const algorithm = "aes-256-cbc"; // Especifica o algoritmo simétrico AES (Advanced Encryption Standard);
const key = crypto.randomBytes(32); // Gera chave aleatória de 256 bits (32 bytes)
const iv = crypto.randomBytes(16); // Gera IV aleatório de 128 bits (16 bytes)
/*
function encrypt(text: string) {
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, "utf-8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}
*/
// Exercício 1 - modificação necessária para usar a chave de criptografia do arquivo cryptoConfig.ts
export function encrypt(text: string): string {
  const cipher = crypto.createCipheriv(algorithm, encryptionKey, encryptionIv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

/*
function decrypt(encrypted: string) {
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(encrypted, "hex", "utf-8");
  decrypted += decipher.final("utf-8");
  return decrypted;
}*/

// Exercício 2 - modificação necessária para usar a chave de criptografia do arquivo cryptoConfig.ts
export function decrypt(encryptedText: string): string {
  const decipher = crypto.createDecipheriv(
    algorithm,
    encryptionKey,
    encryptionIv
  );
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

export async function register(req: Request, res: Response) {
  const { username, password, email } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);
  const encryptedEmail = encrypt(email);

  await db.query(
    "INSERT INTO users(username, password, email) VALUES ($1, $2, $3)",
    [username, hashedPassword, encryptedEmail]
  );

  res.status(201).json({ message: "Usuário registrado com sucesso." });
}

// Endpoint para registrar usuário de forma criptografada
export async function registerSecure(req: Request, res: Response) {
  const privateKey = fs.readFileSync(
    path.join(__dirname, "../keys/private.pem"),
    "utf-8"
  );

  try {
    const { encryptedKey, encryptedData } = req.body;

    // 1. Descriptografa a chave AES com a chave privada RSA (RSA-OAEP)
    const bufferEncryptedKey = Buffer.from(encryptedKey, "base64");

    const decryptedKeyBase64 = crypto
      .privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        bufferEncryptedKey
      )
      .toString("utf-8"); // resultado: AES key codificada em base64

    // 2. Converte a AES key base64 para WordArray (requerido pela crypto-js 4.2.0)
    const aesKey = CryptoJS.enc.Base64.parse(decryptedKeyBase64);

    // 3. Descriptografa os dados com AES
    const bytes = CryptoJS.AES.decrypt(encryptedData, aesKey, {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.Pkcs7,
    });

    const decryptedPayload = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

    const hashedPassword = await bcrypt.hash(decryptedPayload.password, 10);
    const encryptedEmail = encrypt(decryptedPayload.email);

    await db.query(
      "INSERT INTO users(username, password, email) VALUES ($1, $2, $3)",
      [decryptedPayload.username, hashedPassword, encryptedEmail]
    );

    res.status(201).json({ message: "Usuário registrado com sucesso." });
  } catch (err: any) {
    console.error("Erro ao descriptografar:", err.message);
    res.status(400).json({ error: "Falha ao descriptografar os dados." });
  }
}

// Exercício 1
export async function loginSecure(req: Request, res: Response) {
  const privateKey = fs.readFileSync(
    path.join(__dirname, "../keys/private.pem"),
    "utf-8"
  );

  try {
    const { encryptedKey, encryptedData } = req.body;

    // 1. Descriptografa chave AES
    const bufferEncryptedKey = Buffer.from(encryptedKey, "base64");
    const decryptedKeyBase64 = crypto
      .privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        bufferEncryptedKey
      )
      .toString("utf-8");

    const aesKey = CryptoJS.enc.Base64.parse(decryptedKeyBase64);

    // 2. Descriptografa os dados
    const bytes = CryptoJS.AES.decrypt(encryptedData, aesKey, {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.Pkcs7,
    });

    const decryptedPayload = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

    const { email, password } = decryptedPayload;

    // 3. Buscar usuário por email criptografado
    const encryptedEmail = encrypt(email);
console.log("Email criptografado:", encryptedEmail );
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      encryptedEmail,
    ]);

    if (result.rowCount === 0) {
      res.status(401).json({ error: "Credenciais inválidas." });
    } else {
      const user = result.rows[0];

      // 4. Comparar a senha fornecida com a senha hash do BD
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        res.status(401).json({ error: "Credenciais inválidas." });
      } else {
        // 5. Define o cookie com o ID do usuário
        res.cookie("userId", user.id, {
          httpOnly: true,
          maxAge: 60 * 60 * 1000, // 1 hora
          sameSite: "strict",
          secure: false, // true em produção
        });
        res.json({ message: "Login realizado com sucesso!" });
      }
    }
  } catch (err: any) {
    console.error("Erro no login:", err.message);
    res.status(400).json({ error: "Falha na autenticação." });
  }
}

// Exercício 2
export async function getEncryptedProfile(req: Request, res: Response) {
  const userId = req.cookies.userId;

  try {
    const { encryptedKey } = req.body;

    // 1. Lê a chave privada RSA
    const privateKey = fs.readFileSync(
      path.join(__dirname, "../keys/private.pem"),
      "utf-8"
    );

    // 2. Descriptografa a chave AES enviada pelo cliente
    const bufferEncryptedKey = Buffer.from(encryptedKey, "base64");
    const decryptedKeyBase64 = crypto
      .privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        bufferEncryptedKey
      )
      .toString("utf-8");

    const aesKey = CryptoJS.enc.Base64.parse(decryptedKeyBase64);
    
    // 3. Busca dados do usuário
    const result = await db.query(
      "SELECT username, email FROM users WHERE id = $1",
      [userId]
    );

    if (result.rowCount === 0) {
      res.status(404).json({ error: "Usuário não encontrado" });
    } else {
      const user = result.rows[0];

      // 4. Descriptografa o email do banco
      const decryptedEmail = decrypt(user.email); // Sua função já existente

      // 5. Monta o payload e criptografa com AES
      const payload = JSON.stringify({
        username: user.username,
        email: decryptedEmail,
      });

      const encryptedData = CryptoJS.AES.encrypt(payload, aesKey, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7,
      }).toString();

      res.json({ encryptedData });
    }
  } catch (error: any) {
    console.error("Erro ao retornar perfil criptografado:", error.message);
    res.status(500).json({ error: "Erro interno no servidor" });
  }
}
