
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: process.env.FRONTEND_URL || true
}));
app.use(express.json({ limit: "100kb" }));

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is not configured");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS participants (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'student',
      school TEXT DEFAULT '',
      grade TEXT DEFAULT '',
      class_letter TEXT DEFAULT '',
      code TEXT UNIQUE,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS access_codes (
      code TEXT PRIMARY KEY,
      role TEXT NOT NULL DEFAULT 'student',
      used BOOLEAN NOT NULL DEFAULT FALSE,
      assigned_name TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_sessions (
      token_hash TEXT PRIMARY KEY,
      participant_id TEXT NOT NULL REFERENCES participants(id)
        ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL
    );
  `);

  const adminEmail = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (adminEmail && adminPassword) {
    const existing = await pool.query(
      "SELECT id FROM participants WHERE email = $1",
      [adminEmail]
    );

    if (existing.rowCount === 0) {
      const passwordHash = await bcrypt.hash(adminPassword, 12);

      await pool.query(
        `INSERT INTO participants
         (id, name, email, password_hash, role, school, code)
         VALUES ($1, $2, $3, $4, 'admin', $5, $6)`,
        [
          crypto.randomUUID(),
          "Администратор",
          adminEmail,
          passwordHash,
          "Olympiad Academy",
          "OA-ADMIN"
        ]
      );
    }
  }

  console.log("PostgreSQL database initialized");
}

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function getUser(req) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

  if (!token) return null;

  const result = await pool.query(
    `SELECT p.id, p.name, p.email, p.role, p.school, p.grade,
            p.class_letter, p.code, p.status
     FROM user_sessions s
     JOIN participants p ON p.id = s.participant_id
     WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
    [hashToken(token)]
  );

  if (!result.rows[0] || result.rows[0].status !== "active") {
    return null;
  }

  return result.rows[0];
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    school: user.school,
    grade: user.grade,
    letter: user.class_letter,
    code: user.code,
    status: user.status
  };
}

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch {
    res.status(503).json({ ok: false, database: "unavailable" });
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const {
      name, email, password, school = "",
      grade = "", letter = "", code
    } = req.body || {};

    const normalizedEmail = String(email || "").trim().toLowerCase();
    const normalizedCode = String(code || "").trim().toUpperCase();

    if (!name?.trim() || !normalizedEmail ||
        typeof password !== "string" || password.length < 8 ||
        password.length > 128 || !normalizedCode) {
      return res.status(400).json({
        error: "Заполните все обязательные поля. Пароль — минимум 8 символов."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const codeResult = await client.query(
        `SELECT code, role, assigned_name FROM access_codes
         WHERE code = $1 AND used = FALSE FOR UPDATE`,
        [normalizedCode]
      );

      if (!codeResult.rows.length) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          error: "Код участника недействителен или уже использован."
        });
      }

      const accessCode = codeResult.rows[0];

      if (accessCode.assigned_name &&
          accessCode.assigned_name.trim().toLowerCase() !==
          name.trim().toLowerCase()) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          error: "Этот код назначен другому участнику."
        });
      }

      const id = crypto.randomUUID();

      await client.query(
        `INSERT INTO participants
         (id, name, email, password_hash, role, school, grade,
          class_letter, code)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          id, name.trim(), normalizedEmail, passwordHash,
          accessCode.role, String(school), String(grade),
          String(letter), normalizedCode
        ]
      );

      await client.query(
        "UPDATE access_codes SET used = TRUE WHERE code = $1",
        [normalizedCode]
      );

      await client.query("COMMIT");

      res.status(201).json({ ok: true });
    } catch (error) {
      await client.query("ROLLBACK");

      if (error.code === "23505") {
        return res.status(409).json({
          error: "Этот email уже зарегистрирован."
        });
      }

      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error("Registration error:", error.message);
    res.status(500).json({ error: "Ошибка регистрации на сервере." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = req.body?.password;

    const result = await pool.query(
      "SELECT * FROM participants WHERE email = $1",
      [email]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(
      typeof password === "string" ? password : "",
      user.password_hash
    ))) {
      return res.status(401).json({
        error: "Неверный email или пароль."
      });
    }

    if (user.status !== "active") {
      return res.status(403).json({
        error: "Учётная запись заблокирована."
      });
    }

    const token = makeToken();

    await pool.query(
      `INSERT INTO user_sessions (token_hash, participant_id, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
      [hashToken(token), user.id]
    );

    res.json({ token, user: publicUser(user) });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ error: "Ошибка входа на сервере." });
  }
});

app.get("/api/me", async (req, res) => {
  try {
    const user = await getUser(req);

    if (!user) {
      return res.status(401).json({ error: "Требуется вход." });
    }

    res.json({ user: publicUser(user) });
  } catch {
    res.status(500).json({ error: "Ошибка сервера." });
  }
});

app.post("/api/logout", async (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

  if (token) {
    await pool.query(
      "DELETE FROM user_sessions WHERE token_hash = $1",
      [hashToken(token)]
    ).catch(() => {});
  }

  res.json({ ok: true });
});

app.post("/api/admin/codes", async (req, res) => {
  try {
    const user = await getUser(req);

    if (!user || user.role !== "admin") {
      return res.status(403).json({ error: "Доступ запрещён." });
    }

    const role = req.body?.role === "admin" ? "admin" : "student";
    const assignedName = String(req.body?.assignedName || "").trim();

    const code = "OA-" +
      (role === "admin" ? "ADM-" : "") +
      crypto.randomBytes(4).toString("hex").toUpperCase();

    await pool.query(
      `INSERT INTO access_codes (code, role, assigned_name)
       VALUES ($1, $2, $3)`,
      [code, role, assignedName]
    );

    res.status(201).json({ code, role, assignedName, used: false });
  } catch (error) {
    console.error("Code creation error:", error.message);
    res.status(500).json({ error: "Не удалось создать код." });
  }
});

app.get("/api/admin/codes", async (req, res) => {
  try {
    const user = await getUser(req);

    if (!user || user.role !== "admin") {
      return res.status(403).json({ error: "Доступ запрещён." });
    }

    const result = await pool.query(
      `SELECT code, role, used, assigned_name AS "assignedName",
              created_at AS "createdAt"
       FROM access_codes ORDER BY created_at DESC`
    );

    res.json({ codes: result.rows });
  } catch {
    res.status(500).json({ error: "Не удалось загрузить коды." });
  }
});

app.get("/api/admin/participants", async (req, res) => {
  try {
    const user = await getUser(req);

    if (!user || user.role !== "admin") {
      return res.status(403).json({ error: "Доступ запрещён." });
    }

    const result = await pool.query(
      `SELECT id, name, email, role, school, grade,
              class_letter AS letter, code, status,
              created_at AS created
       FROM participants ORDER BY created_at DESC`
    );

    res.json({ participants: result.rows });
  } catch {
    res.status(500).json({ error: "Не удалось загрузить участников." });
  }
});

app.patch("/api/admin/participants/:id/status", async (req, res) => {
  try {
    const user = await getUser(req);

    if (!user || user.role !== "admin") {
      return res.status(403).json({ error: "Доступ запрещён." });
    }

    const status = req.body?.status;

    if (!["active", "blocked"].includes(status)) {
      return res.status(400).json({ error: "Недопустимый статус." });
    }

    const result = await pool.query(
      `UPDATE participants SET status = $1
       WHERE id = $2 AND role <> 'admin'
       RETURNING id, status`,
      [status, req.params.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Участник не найден." });
    }

    if (status === "blocked") {
      await pool.query(
        "DELETE FROM user_sessions WHERE participant_id = $1",
        [req.params.id]
      );
    }

    res.json(result.rows[0]);
  } catch {
    res.status(500).json({ error: "Не удалось изменить статус." });
  }
});

app.listen(PORT, async () => {
  try {
    await initDatabase();
    console.log(`Olympiad Academy server listening on ${PORT}`);
  } catch (error) {
    console.error("Startup failed:", error.message);
    process.exit(1);
  }
});
