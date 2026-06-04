require("dotenv").config();

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const os = require("os");
const express = require("express");
const cors = require("cors");
const Groq = require("groq-sdk");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const TOKEN_SECRET = process.env.TOKEN_SECRET || "american-finance-dev-secret";
const TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 7;

app.use(cors());
app.use(express.json());

function ensureStore() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]", "utf8");
}

function readUsers() {
  ensureStore();
  return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
}

function saveUsers(users) {
  ensureStore();
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.pbkdf2Sync(password, salt, 120000, 64, "sha512").toString("hex");
  return { salt, hash };
}

function verifyPassword(password, user) {
  const { hash } = hashPassword(password, user.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(user.passwordHash, "hex"));
}

function base64url(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function signToken(payload) {
  const body = base64url({ ...payload, exp: Date.now() + TOKEN_TTL_MS });
  const signature = crypto.createHmac("sha256", TOKEN_SECRET).update(body).digest("base64url");
  return `${body}.${signature}`;
}

function readToken(req) {
  const header = req.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

function verifyToken(token) {
  const [body, signature] = String(token || "").split(".");
  if (!body || !signature) return null;

  const expected = crypto.createHmac("sha256", TOKEN_SECRET).update(body).digest("base64url");
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;

  const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  return payload.exp > Date.now() ? payload : null;
}

function authRequired(req, res, next) {
  try {
    const payload = verifyToken(readToken(req));
    if (!payload) return res.status(401).json({ error: "Sesión inválida o vencida." });
    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: "Sesión inválida o vencida." });
  }
}

app.post("/api/auth/register", (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");

  if (name.length < 2) return res.status(400).json({ error: "Escribe tu nombre." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Escribe un correo válido." });
  if (password.length < 8) return res.status(400).json({ error: "La contraseña debe tener mínimo 8 caracteres." });

  const users = readUsers();
  if (users.some((user) => user.email === email)) return res.status(409).json({ error: "Ese correo ya está registrado." });

  const { salt, hash } = hashPassword(password);
  const user = {
    id: crypto.randomUUID(),
    name,
    email,
    salt,
    passwordHash: hash,
    createdAt: new Date().toISOString(),
  };

  users.push(user);
  saveUsers(users);

  const token = signToken({ id: user.id, name: user.name, email: user.email });
  res.status(201).json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

app.post("/api/auth/login", (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");
  const user = readUsers().find((item) => item.email === email);

  if (!user || !verifyPassword(password, user)) {
    return res.status(401).json({ error: "Correo o contraseña incorrectos." });
  }

  const token = signToken({ id: user.id, name: user.name, email: user.email });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

app.get("/api/auth/me", authRequired, (req, res) => {
  res.json({ user: { id: req.user.id, name: req.user.name, email: req.user.email } });
});

app.post("/api/auth/logout", (_req, res) => {
  res.json({ ok: true });
});

const groq = process.env.GROQ_API_KEY
  ? new Groq({ apiKey: process.env.GROQ_API_KEY })
  : null;

app.post("/chat", async (req, res) => {
  try {
    if (!groq) return res.status(500).json({ error: "Falta configurar GROQ_API_KEY." });

    const { message } = req.body;
    const response = await groq.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      messages: [{ role: "user", content: message }],
    });

    res.json({ reply: response.choices[0].message.content });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al consultar Groq" });
  }
});

app.use(express.static(__dirname));

app.listen(PORT, "0.0.0.0", () => {
  ensureStore();
  const ip = require("os").networkInterfaces();
  const ipAddress = Object.values(ip).flat().find(i => i.family === "IPv4" && !i.internal)?.address || "localhost";
  console.log(`✅ Servidor iniciado en http://${ipAddress}:${PORT}`);
  console.log(`📱 Accesible desde otros dispositivos en: http://${ipAddress}:${PORT}`);
});
