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
const MAX_MESSAGE_CHARS = 4000;

app.use(cors());
app.use(express.json({ limit: "100kb" }));

function ensureStore() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]", "utf8");
}

function readUsers() {
  ensureStore();
  try {
    const users = JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
    return Array.isArray(users) ? users : [];
  } catch (error) {
    console.error("No se pudo leer data/users.json:", error.message);
    return [];
  }
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
  if (!user?.salt || !user?.passwordHash) return false;
  const { hash } = hashPassword(password, user.salt);
  const current = Buffer.from(hash, "hex");
  const expected = Buffer.from(user.passwordHash, "hex");
  return current.length === expected.length && crypto.timingSafeEqual(current, expected);
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
  try {
    const [body, signature] = String(token || "").split(".");
    if (!body || !signature) return null;

    const expected = crypto.createHmac("sha256", TOKEN_SECRET).update(body).digest("base64url");
    const current = Buffer.from(signature);
    const expectedBuffer = Buffer.from(expected);
    if (current.length !== expectedBuffer.length || !crypto.timingSafeEqual(current, expectedBuffer)) return null;

    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    return payload.exp > Date.now() ? payload : null;
  } catch {
    return null;
  }
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
const aiProvider = String(process.env.AI_PROVIDER || (groq ? "groq" : "none")).toLowerCase();

function aiConfiguration() {
  return {
    provider: aiProvider,
    configured: aiProvider === "groq" && Boolean(groq),
  };
}

function isNetworkError(error, seen = new Set()) {
  if (!error || seen.has(error)) return false;
  seen.add(error);

  if (["EACCES", "ENOTFOUND", "ECONNREFUSED", "ETIMEDOUT"].includes(error.code)) return true;
  if (Array.isArray(error.errors) && error.errors.some((item) => isNetworkError(item, seen))) return true;
  return isNetworkError(error.cause, seen);
}

function aiErrorResponse(error, res) {
  const status = Number(error?.status);
  console.error("Error del proveedor de IA:", error?.message || error);

  if (status === 401 || status === 403) {
    return res.status(502).json({ error: "La clave de la IA fue rechazada por el proveedor. Revisa GROQ_API_KEY en .env." });
  }
  if (status === 429) {
    return res.status(429).json({ error: "La IA alcanzó su límite de uso. Intenta de nuevo en unos minutos." });
  }
  if (isNetworkError(error)) {
    return res.status(503).json({ error: "No se pudo conectar con el proveedor de IA. Revisa la conexión de red, proxy o firewall del servidor." });
  }
  return res.status(502).json({ error: "El proveedor de IA no pudo completar la consulta. Intenta de nuevo." });
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, ai: aiConfiguration() });
});

app.post("/chat", async (req, res) => {
  try {
    if (aiProvider !== "groq" || !groq) {
      return res.status(503).json({ error: "La IA no está configurada. Define GROQ_API_KEY y AI_PROVIDER=groq en el archivo .env." });
    }

    const message = String(req.body?.message || "").trim();
    if (!message) return res.status(400).json({ error: "Escribe un mensaje para el asistente." });
    if (message.length > MAX_MESSAGE_CHARS) return res.status(400).json({ error: `El mensaje no puede superar ${MAX_MESSAGE_CHARS} caracteres.` });

    const response = await groq.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      messages: [
        {
          role: "system",
          content: "Eres AF-01, un asistente educativo de finanzas personales. Responde en español, con claridad, sin inventar datos actuales y sin presentar tu respuesta como asesoría financiera personalizada.",
        },
        { role: "user", content: message },
      ],
    });

    const reply = response.choices?.[0]?.message?.content?.trim();
    if (!reply) return res.status(502).json({ error: "La IA no devolvió una respuesta válida." });
    res.json({ reply });
  } catch (error) {
    return aiErrorResponse(error, res);
  }
});

app.use(express.static(__dirname));

app.use((error, _req, res, _next) => {
  if (error instanceof SyntaxError && "body" in error) {
    return res.status(400).json({ error: "El cuerpo de la solicitud debe ser JSON válido." });
  }
  console.error("Error no controlado:", error);
  res.status(500).json({ error: "Error interno del servidor." });
});

app.listen(PORT, "0.0.0.0", () => {
  ensureStore();
  const ip = os.networkInterfaces();
  const ipAddress = Object.values(ip).flat().find(i => i.family === "IPv4" && !i.internal)?.address || "localhost";
  console.log(`Servidor iniciado en http://${ipAddress}:${PORT}`);
  console.log(`Accesible desde otros dispositivos en: http://${ipAddress}:${PORT}`);
});
