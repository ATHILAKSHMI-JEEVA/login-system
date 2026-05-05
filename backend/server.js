const express    = require("express");
const mysql      = require("mysql2");
const bcrypt     = require("bcrypt");
const jwt        = require("jsonwebtoken");
const cors       = require("cors");
const nodemailer = require("nodemailer");
const admin      = require("firebase-admin");
const http       = require("http");
const { Server } = require("socket.io");
const multer     = require("multer");
const path       = require("path");
const fs         = require("fs");
require("dotenv").config();
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: "*" } });

app.use(express.json());
app.use(cors({
  origin: ["http://localhost:5500", "http://127.0.0.1:5500", "https://login-system-99cr.vercel.app", "https://login-system-backend-i3b8.onrender.com"],
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
  credentials: true
}));

const frontendDir = path.join(__dirname, "../frontend");
app.use(express.static(frontendDir));

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: async (req, file) => ({
    folder: "chat-uploads",
    resource_type: "auto",
    public_id: Date.now() + "-" + Math.round(Math.random() * 1e6),
  }),
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }
});

// ─── MySQL ───
const db = mysql.createConnection({
  host:     process.env.DB_HOST     || "localhost",
  port:     process.env.DB_PORT     || 3306,
  user:     process.env.DB_USER     || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME     || "logindb",
  ssl: process.env.DB_HOST && !process.env.DB_HOST.includes('localhost') ? { rejectUnauthorized: false } : false
});
db.connect(err => {
  if (err) console.log("❌ MySQL Error:", err.message);
  else     console.log("✅ MySQL Connected");
});

// ─── Tables ───
db.query(`
  CREATE TABLE IF NOT EXISTS groups_table (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    created_by  VARCHAR(255) NOT NULL,
    photo_url   VARCHAR(500) DEFAULT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`, err => { if (err) console.log('❌ Groups table error:', err.message); else console.log('✅ Groups table ready'); });

db.query(`
  CREATE TABLE IF NOT EXISTS group_members (
    id        INT AUTO_INCREMENT PRIMARY KEY,
    group_id  INT NOT NULL,
    email     VARCHAR(255) NOT NULL
  )
`, err => { if (err) console.log('❌ Group members table error:', err.message); else console.log('✅ Group members table ready'); });

db.query(`
  CREATE TABLE IF NOT EXISTS group_messages (
    id                   INT AUTO_INCREMENT PRIMARY KEY,
    group_id             INT NOT NULL,
    sender               VARCHAR(255) NOT NULL,
    message              TEXT,
    type                 VARCHAR(20) DEFAULT 'text',
    file_url             VARCHAR(500),
    file_name            VARCHAR(255),
    deleted_for_everyone TINYINT(1) DEFAULT 0,
    created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`, err => { if (err) console.log('❌ Group messages table error:', err.message); else console.log('✅ Group messages table ready'); });

db.query(`
  CREATE TABLE IF NOT EXISTS messages (
    id                   INT AUTO_INCREMENT PRIMARY KEY,
    sender               VARCHAR(255) NOT NULL,
    receiver             VARCHAR(255) NOT NULL,
    message              TEXT,
    type                 VARCHAR(20) DEFAULT 'text',
    file_url             VARCHAR(500),
    file_name            VARCHAR(255),
    deleted_for_everyone TINYINT(1) DEFAULT 0,
    deleted_for          TEXT DEFAULT NULL,
    created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`, err => {
  if (err) console.log("❌ Table error:", err.message);
  else     console.log("✅ Messages table ready");
});

// ── Migrate: add columns safely (ER_DUP_FIELDNAME = already exists, skip) ──
const alterQueries = [
  `ALTER TABLE messages ADD COLUMN deleted_for_everyone TINYINT(1) DEFAULT 0`,
  `ALTER TABLE messages ADD COLUMN deleted_for TEXT DEFAULT NULL`,
  `ALTER TABLE group_messages ADD COLUMN deleted_for_everyone TINYINT(1) DEFAULT 0`,
  `ALTER TABLE users ADD COLUMN is_admin TINYINT(1) DEFAULT 0`,
  `ALTER TABLE groups_table ADD COLUMN photo_url VARCHAR(500) DEFAULT NULL`
];
alterQueries.forEach(q => db.query(q, (err) => {
  if (err && err.code !== 'ER_DUP_FIELDNAME') console.log('⚠️ Alter warning:', err.message);
}));

// ─── Firebase ───
try {
  let serviceAccount;
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  } else {
    serviceAccount = require("./serviceAccountKey.json");
  }
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
  console.log("✅ Firebase Admin Ready");
} catch (e) {
  console.log("⚠️  Firebase not initialized:", e.message);
}

const otpStore = new Map();

// ─── REGISTER ───
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ message: "All fields required" });
  const hash = await bcrypt.hash(password, 10);
  db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email, hash], err => {
    if (err) return res.json({ message: "User already exists" });
    res.json({ message: "Registered successfully" });
  });
});

// ─── LOGIN ───
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
    if (!result || result.length === 0) return res.json({ message: "User not found" });
    const match = await bcrypt.compare(password, result[0].password);
    if (!match) return res.json({ message: "Wrong password" });
    const token = jwt.sign({ id: result[0].id, email }, process.env.JWT_SECRET || "mysupersecretkey", { expiresIn: "7d" });
    res.json({ message: "Login success", token, is_admin: result[0].is_admin === 1 });
  });
});

// ─── FIREBASE LOGIN ───
app.post("/firebase-login", async (req, res) => {
  const { idToken } = req.body;
  if (!idToken) return res.json({ success: false, message: "No token provided" });
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    const { email, name, picture } = decoded;
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
      if (err) return res.status(500).json({ success: false, message: "DB error" });
      const issueToken = (userId, isAdmin) => {
        const token = jwt.sign({ id: userId, email }, process.env.JWT_SECRET || "mysupersecretkey", { expiresIn: "7d" });
        res.json({ success: true, token, email, name, avatar: picture, is_admin: isAdmin === 1 });
      };
      if (result.length === 0) {
        db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email, "OAUTH_USER"], (err2, r) => {
          if (err2) return res.json({ success: false, message: "Could not create user" });
          issueToken(r.insertId, 0);
        });
      } else {
        issueToken(result[0].id, result[0].is_admin);
      }
    });
  } catch (err) {
    res.status(401).json({ success: false, message: "Invalid Firebase token: " + err.message });
  }
});

// ─── SEND OTP ───
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ success: false, message: "Email required" });
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore.set(email, { otp, expiresAt: Date.now() + 10 * 60 * 1000 });
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: process.env.MAIL_USER, pass: process.env.MAIL_PASS }
  });
  try {
    await transporter.sendMail({
      from: `"" <${process.env.MAIL_USER}>`,
      to: email,
      subject: "Your OTP Code",
      html: `<h2>Your OTP: <strong>${otp}</strong></h2><p>Valid for 10 minutes.</p>`
    });
    res.json({ success: true, message: "OTP sent" });
  } catch (err) {
    res.json({ success: false, message: "Email send failed: " + err.message });
  }
});

// ─── VERIFY OTP ───
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const stored = otpStore.get(email);
  if (!stored) return res.json({ success: false, message: "No OTP found." });
  if (Date.now() > stored.expiresAt) { otpStore.delete(email); return res.json({ success: false, message: "OTP expired." }); }
  if (stored.otp !== otp) return res.json({ success: false, message: "Wrong OTP." });
  otpStore.delete(email);
  db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
    const done = (userId, isAdmin) => {
      const token = jwt.sign({ id: userId, email }, process.env.JWT_SECRET || "mysupersecretkey", { expiresIn: "7d" });
      res.json({ success: true, message: "OTP Verified", token, is_admin: isAdmin === 1 });
    };
    if (!result || result.length === 0) {
      db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email, "OTP_USER"], (e, r) => done(r.insertId, 0));
    } else {
      done(result[0].id, result[0].is_admin);
    }
  });
});

// ─── RESET PASSWORD ───
app.post("/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword) return res.json({ success: false, message: "All fields required" });
  const stored = otpStore.get(email);
  if (!stored) return res.json({ success: false, message: "No OTP found." });
  if (Date.now() > stored.expiresAt) { otpStore.delete(email); return res.json({ success: false, message: "OTP expired" }); }
  if (stored.otp !== otp) return res.json({ success: false, message: "Wrong OTP" });
  const hashed = await bcrypt.hash(newPassword, 10);
  db.query("UPDATE users SET password = ? WHERE email = ?", [hashed, email], (err, result) => {
    if (err || result.affectedRows === 0) return res.json({ success: false, message: "User not found or DB error" });
    otpStore.delete(email);
    res.json({ success: true, message: "✅ Password updated successfully" });
  });
});

// ─── GET ALL USERS ───
app.get("/users", (req, res) => {
  db.query("SELECT email FROM users", (err, result) => {
    if (err) return res.json({ success: false });
    res.json({ success: true, users: result.map(r => r.email) });
  });
});

// ─── GET CHAT HISTORY ───
app.get("/messages/:user1/:user2", (req, res) => {
  const token = req.headers["authorization"];
  if (!token) return res.json({ success: false });
  try {
    jwt.verify(token, process.env.JWT_SECRET || "mysupersecretkey");
    const { user1, user2 } = req.params;
    db.query(
      `SELECT * FROM messages
       WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
       ORDER BY created_at ASC`,
      [user1, user2, user2, user1],
      (err, result) => {
        if (err) return res.json({ success: false });
        const filtered = result.filter(m => {
          if (m.deleted_for_everyone) return true;
          if (m.deleted_for) {
            const list = m.deleted_for.split(',');
            if (list.includes(user1)) return false;
          }
          return true;
        });
        res.json({ success: true, messages: filtered });
      }
    );
  } catch { res.status(401).json({ success: false }); }
});

// ─── FILE UPLOAD ───
app.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) return res.json({ success: false, message: "No file" });
  const fileUrl  = req.file.path;
  const fileName = req.file.originalname;
  const mimeType = req.file.mimetype;
  let type = "file";
  if (mimeType.startsWith("image/")) type = "image";
  else if (mimeType.startsWith("video/")) type = "video";
  else if (mimeType.startsWith("audio/")) type = "audio";
  res.json({ success: true, fileUrl, fileName, type });
});

// ─── PROTECTED HOME ───
app.get("/home", (req, res) => {
  const token = req.headers["authorization"];
  if (!token) return res.json({ message: "No token — please login" });
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET || "mysupersecretkey");
    res.json({ message: `✅ Secure data loaded! User ID: ${user.id} | Email: ${user.email}` });
  } catch { res.status(401).json({ message: "Invalid or expired token" }); }
});

// ═══════════════════════════════════════════════
//  DELETE MESSAGES
// ═══════════════════════════════════════════════

app.post("/messages/:id/delete-for-me", (req, res) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ success: false });
  try { jwt.verify(token, process.env.JWT_SECRET || "mysupersecretkey"); }
  catch { return res.status(401).json({ success: false }); }
  const { id } = req.params;
  const { email } = req.body;
  if (!email) return res.json({ success: false, message: 'Email required' });
  db.query('SELECT deleted_for FROM messages WHERE id = ?', [id], (err, result) => {
    if (err || !result.length) return res.json({ success: false, message: 'Message not found' });
    const existing = result[0].deleted_for || '';
    const list = existing ? existing.split(',') : [];
    if (!list.includes(email)) list.push(email);
    db.query('UPDATE messages SET deleted_for = ? WHERE id = ?', [list.join(','), id], (err2) => {
      if (err2) return res.json({ success: false, message: err2.message });
      res.json({ success: true });
    });
  });
});

app.post("/messages/:id/delete-for-everyone", (req, res) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ success: false });
  try { jwt.verify(token, process.env.JWT_SECRET || "mysupersecretkey"); }
  catch { return res.status(401).json({ success: false }); }
  const { id } = req.params;
  const { email } = req.body;
  db.query('SELECT sender FROM messages WHERE id = ?', [id], (err, result) => {
    if (err || !result.length) return res.json({ success: false, message: 'Message not found' });
    if (result[0].sender !== email) return res.json({ success: false, message: 'Only sender can delete for everyone' });
    db.query('UPDATE messages SET deleted_for_everyone = 1 WHERE id = ?', [id], (err2) => {
      if (err2) return res.json({ success: false, message: err2.message });
      res.json({ success: true });
    });
  });
});

app.post("/group-messages/:id/delete", (req, res) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ success: false });
  try { jwt.verify(token, process.env.JWT_SECRET || "mysupersecretkey"); }
  catch { return res.status(401).json({ success: false }); }
  const { id } = req.params;
  const { email } = req.body;
  db.query('SELECT sender FROM group_messages WHERE id = ?', [id], (err, result) => {
    if (err || !result.length) return res.json({ success: false, message: 'Message not found' });
    if (result[0].sender !== email) return res.json({ success: false, message: 'Only sender can delete for everyone' });
    db.query('UPDATE group_messages SET deleted_for_everyone = 1 WHERE id = ?', [id], (err2) => {
      if (err2) return res.json({ success: false, message: err2.message });
      res.json({ success: true });
    });
  });
});

// ─── CREATE GROUP ───
app.post("/groups", (req, res) => {
  const { name, members, created_by } = req.body;
  if (!name || !created_by) return res.json({ success: false, message: 'Name required' });
  db.query('INSERT INTO groups_table (name, created_by) VALUES (?, ?)', [name, created_by], (err, result) => {
    if (err) return res.json({ success: false, message: err.message });
    const groupId = result.insertId;
    const allMembers = [...new Set([created_by, ...(members || [])])];
    const values = allMembers.map(email => [groupId, email]);
    db.query('INSERT IGNORE INTO group_members (group_id, email) VALUES ?', [values], (err2) => {
      if (err2) return res.json({ success: false, message: err2.message });
      res.json({ success: true, groupId, name });
    });
  });
});

// ─── GET MY GROUPS (with fallback if photo_url column missing) ───
app.get("/groups/:email", (req, res) => {
  const { email } = req.params;
  db.query(
    `SELECT g.id, g.name, g.created_by, g.photo_url FROM groups_table g
     JOIN group_members gm ON g.id = gm.group_id
     WHERE gm.email = ?`,
    [email],
    (err, result) => {
      if (err) {
        console.log('⚠️ photo_url query failed, trying fallback:', err.message);
        // Fallback without photo_url
        db.query(
          `SELECT g.id, g.name, g.created_by FROM groups_table g
           JOIN group_members gm ON g.id = gm.group_id
           WHERE gm.email = ?`,
          [email],
          (err2, result2) => {
            if (err2) return res.json({ success: false, error: err2.message });
            res.json({ success: true, groups: result2.map(g => ({ ...g, photo_url: null })) });
          }
        );
        return;
      }
      res.json({ success: true, groups: result });
    }
  );
});

// ─── UPDATE GROUP PHOTO ───
app.post("/groups/:groupId/photo", (req, res) => {
  const { photo_url } = req.body;
  const { groupId } = req.params;
  if (!photo_url) return res.json({ success: false, message: 'photo_url required' });
  db.query(
    'UPDATE groups_table SET photo_url = ? WHERE id = ?',
    [photo_url, groupId],
    (err) => {
      if (err) return res.json({ success: false, message: err.message });
      res.json({ success: true });
    }
  );
});

// ─── GET GROUP MEMBERS ───
app.get("/groups/:groupId/members", (req, res) => {
  db.query('SELECT email FROM group_members WHERE group_id = ?', [req.params.groupId], (err, result) => {
    if (err) return res.json({ success: false });
    res.json({ success: true, members: result.map(r => r.email) });
  });
});

// ─── REMOVE GROUP MEMBER ───
app.post("/groups/:groupId/members/remove", (req, res) => {
  const { email, requestedBy } = req.body;
  const { groupId } = req.params;
  db.query('SELECT created_by FROM groups_table WHERE id = ?', [groupId], (err, result) => {
    if (err || !result.length) return res.json({ success: false, message: 'Group not found' });
    if (result[0].created_by !== requestedBy) return res.json({ success: false, message: 'Only admin can remove members' });
    db.query('DELETE FROM group_members WHERE group_id = ? AND email = ?', [groupId, email], (err2) => {
      if (err2) return res.json({ success: false, message: err2.message });
      res.json({ success: true });
    });
  });
});

// ─── GET GROUP MESSAGES ───
app.get("/group-messages/:groupId", (req, res) => {
  db.query(
    'SELECT * FROM group_messages WHERE group_id = ? ORDER BY created_at ASC',
    [req.params.groupId],
    (err, result) => {
      if (err) return res.json({ success: false });
      res.json({ success: true, messages: result });
    }
  );
});

// ─── ADD GROUP MEMBERS ───
app.post("/groups/:groupId/members", (req, res) => {
  const { members } = req.body;
  const { groupId } = req.params;
  if (!members || !members.length) return res.json({ success: false });
  const values = members.map(email => [parseInt(groupId), email]);
  db.query('INSERT IGNORE INTO group_members (group_id, email) VALUES ?', [values], (err) => {
    if (err) return res.json({ success: false, message: err.message });
    res.json({ success: true });
  });
});

// ─── LEAVE GROUP ───
app.post("/groups/:groupId/leave", (req, res) => {
  const { email } = req.body;
  const { groupId } = req.params;
  db.query('DELETE FROM group_members WHERE group_id=? AND email=?', [groupId, email], (err) => {
    if (err) return res.json({ success: false });
    res.json({ success: true });
  });
});

// ─── USER PROFILE TABLE ───
db.query(`
  CREATE TABLE IF NOT EXISTS user_profiles (
    email        VARCHAR(255) PRIMARY KEY,
    name         VARCHAR(255),
    bio          TEXT,
    avatar_url   VARCHAR(500),
    avatar_color VARCHAR(50) DEFAULT 'av0',
    updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  )
`, err => {
  if (err) console.log('❌ Profile table error:', err.message);
  else     console.log('✅ Profile table ready');
});

// ─── GET PROFILE ───
app.get('/profile/:email', (req, res) => {
  db.query('SELECT * FROM user_profiles WHERE email = ?', [req.params.email], (err, result) => {
    if (err || !result.length) return res.json({ success: false });
    res.json({ success: true, profile: result[0] });
  });
});

// ─── UPDATE PROFILE ───
app.post('/profile', upload.single('avatar'), async (req, res) => {
  const { email, name, bio, avatar_color } = req.body;
  if (!email) return res.json({ success: false, message: 'Email required' });
  let avatar_url = null;
  if (req.file) { avatar_url = req.file.path; }
  db.query(
    'INSERT INTO user_profiles (email, name, bio, avatar_color, avatar_url) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE name=VALUES(name), bio=VALUES(bio), avatar_color=VALUES(avatar_color)' + (avatar_url ? ', avatar_url=VALUES(avatar_url)' : ''),
    [email, name || '', bio || '', avatar_color || 'av0', avatar_url || ''],
    (err) => {
      if (err) return res.json({ success: false, message: err.message });
      res.json({ success: true, avatar_url });
    }
  );
});

// ─── GET ALL PROFILES ───
app.get('/profiles', (req, res) => {
  db.query('SELECT email, name, bio, avatar_url, avatar_color FROM user_profiles', (err, result) => {
    if (err) return res.json({ success: false });
    res.json({ success: true, profiles: result });
  });
});

// ─── SERVE ADMIN PAGE ───
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend', 'admin.html'));
});

// ═══════════════════════════════════════════════
//  ADMIN ROUTES
// ═══════════════════════════════════════════════

function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
  if (!token) return res.status(401).json({ success: false, message: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'mysupersecretkey');
    db.query('SELECT is_admin FROM users WHERE id = ?', [decoded.id], (err, rows) => {
      if (err || !rows.length || rows[0].is_admin !== 1) {
        return res.status(403).json({ success: false, message: 'Admin access only' });
      }
      req.adminEmail = decoded.email;
      next();
    });
  } catch {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
}

app.get('/admin/stats/users', requireAdmin, (req, res) => {
  db.query('SELECT COUNT(*) as count FROM users', (err, rows) => {
    res.json({ count: err ? 0 : rows[0].count });
  });
});

app.get('/admin/stats/groups', requireAdmin, (req, res) => {
  db.query('SELECT COUNT(*) as count FROM groups_table', (err, rows) => {
    res.json({ count: err ? 0 : rows[0].count });
  });
});

app.get('/admin/stats/messages', requireAdmin, (req, res) => {
  db.query('SELECT COUNT(*) as count FROM group_messages', (err, rows) => {
    res.json({ count: err ? 0 : rows[0].count });
  });
});

app.get('/admin/stats/issues', requireAdmin, (req, res) => {
  db.query("SELECT COUNT(*) as count FROM group_messages WHERE type = 'issue'", (err, rows) => {
    res.json({ count: err ? 0 : rows[0].count });
  });
});

app.get('/admin/groups', requireAdmin, (req, res) => {
  const sql = `
    SELECT g.*, COUNT(gm.id) as member_count
    FROM groups_table g
    LEFT JOIN group_members gm ON g.id = gm.group_id
    GROUP BY g.id
    ORDER BY g.created_at DESC
  `;
  db.query(sql, (err, rows) => {
    if (err) return res.json({ success: false, message: err.message });
    res.json({ success: true, groups: rows });
  });
});

app.post('/admin/groups', requireAdmin, (req, res) => {
  const { name, created_by } = req.body;
  if (!name) return res.json({ success: false, message: 'Name required' });
  const creator = created_by || req.adminEmail;
  db.query(
    'INSERT INTO groups_table (name, created_by) VALUES (?, ?)',
    [name, creator],
    (err, result) => {
      if (err) return res.json({ success: false, message: err.message });
      db.query('INSERT INTO group_members (group_id, email) VALUES (?, ?)', [result.insertId, creator], () => {});
      res.json({ success: true, group_id: result.insertId });
    }
  );
});

app.delete('/admin/groups/:id', requireAdmin, (req, res) => {
  const id = req.params.id;
  db.query('DELETE FROM group_messages WHERE group_id = ?', [id], (err) => {
    if (err) return res.json({ success: false, message: err.message });
    db.query('DELETE FROM group_members WHERE group_id = ?', [id], (err2) => {
      if (err2) return res.json({ success: false, message: err2.message });
      db.query('DELETE FROM groups_table WHERE id = ?', [id], (err3) => {
        if (err3) return res.json({ success: false, message: err3.message });
        res.json({ success: true });
      });
    });
  });
});

app.get('/admin/groups/:id/members', requireAdmin, (req, res) => {
  const sql = `
    SELECT gm.*, g.name as group_name
    FROM group_members gm
    JOIN groups_table g ON g.id = gm.group_id
    WHERE gm.group_id = ?
    ORDER BY gm.id DESC
  `;
  db.query(sql, [req.params.id], (err, rows) => {
    if (err) return res.json({ success: false, message: err.message });
    res.json({ success: true, members: rows });
  });
});

app.post('/admin/groups/:id/members', requireAdmin, (req, res) => {
  const { email } = req.body;
  const group_id = req.params.id;
  if (!email) return res.json({ success: false, message: 'Email required' });
  db.query('SELECT id FROM users WHERE email = ?', [email], (err, rows) => {
    if (err) return res.json({ success: false, message: err.message });
    if (!rows.length) return res.json({ success: false, message: 'User not found with this email' });
    db.query(
      'SELECT id FROM group_members WHERE group_id = ? AND email = ?',
      [group_id, email],
      (err2, existing) => {
        if (err2) return res.json({ success: false, message: err2.message });
        if (existing.length) return res.json({ success: false, message: 'Already a member' });
        db.query(
          'INSERT INTO group_members (group_id, email) VALUES (?, ?)',
          [group_id, email],
          (err3, result) => {
            if (err3) return res.json({ success: false, message: err3.message });
            res.json({ success: true, member_id: result.insertId });
          }
        );
      }
    );
  });
});

app.delete('/admin/members/:id', requireAdmin, (req, res) => {
  db.query('DELETE FROM group_members WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.json({ success: false, message: err.message });
    res.json({ success: true });
  });
});

app.get('/admin/messages', requireAdmin, (req, res) => {
  const sql = `
    SELECT gm.*, g.name as group_name
    FROM group_messages gm
    LEFT JOIN groups_table g ON g.id = gm.group_id
    ORDER BY gm.id DESC
    LIMIT 200
  `;
  db.query(sql, (err, rows) => {
    if (err) return res.json({ success: false, message: err.message });
    res.json({ success: true, messages: rows });
  });
});

app.get('/admin/messages/recent', requireAdmin, (req, res) => {
  const sql = `
    SELECT gm.*, g.name as group_name
    FROM group_messages gm
    LEFT JOIN groups_table g ON g.id = gm.group_id
    ORDER BY gm.id DESC
    LIMIT 10
  `;
  db.query(sql, (err, rows) => {
    if (err) return res.json({ success: false, message: err.message });
    res.json({ success: true, messages: rows });
  });
});

app.post('/admin/messages', requireAdmin, (req, res) => {
  const { group_id, message, type } = req.body;
  if (!group_id || !message) return res.json({ success: false, message: 'group_id and message required' });
  const sender = req.adminEmail;
  db.query(
    'INSERT INTO group_messages (group_id, sender, message, type) VALUES (?, ?, ?, ?)',
    [group_id, sender, message, type || 'text'],
    (err, result) => {
      if (err) return res.json({ success: false, message: err.message });
      io.emit('group-message', {
        id: result.insertId,
        groupId: group_id,
        from: sender,
        message,
        type: type || 'text',
        time: new Date().toISOString()
      });
      res.json({ success: true, message_id: result.insertId });
    }
  );
});

app.delete('/admin/messages/:id', requireAdmin, (req, res) => {
  db.query('DELETE FROM group_messages WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.json({ success: false, message: err.message });
    res.json({ success: true });
  });
});

app.patch('/admin/messages/:id/resolve', requireAdmin, (req, res) => {
  db.query(
    "UPDATE group_messages SET type = 'update' WHERE id = ?",
    [req.params.id],
    (err) => {
      if (err) return res.json({ success: false, message: err.message });
      res.json({ success: true });
    }
  );
});

app.get('/admin/users', requireAdmin, (req, res) => {
  db.query('SELECT id, email, is_admin FROM users ORDER BY id DESC', (err, rows) => {
    if (err) return res.json({ success: false, message: err.message });
    res.json({ success: true, users: rows });
  });
});

app.patch('/admin/users/:id/admin', requireAdmin, (req, res) => {
  db.query('UPDATE users SET is_admin = 1 WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.json({ success: false, message: err.message });
    res.json({ success: true });
  });
});

app.delete('/admin/users/:id', requireAdmin, (req, res) => {
  db.query('DELETE FROM users WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.json({ success: false, message: err.message });
    res.json({ success: true });
  });
});

app.post('/make-admin', (req, res) => {
  const { email, secret } = req.body;
  const ADMIN_SECRET = process.env.ADMIN_SECRET || 'WARD_ADMIN_2024';
  if (secret !== ADMIN_SECRET) return res.status(403).json({ success: false, message: 'Wrong secret' });
  db.query('UPDATE users SET is_admin = 1 WHERE email = ?', [email], (err, result) => {
    if (err) return res.json({ success: false, message: err.message });
    if (result.affectedRows === 0) return res.json({ success: false, message: 'User not found' });
    res.json({ success: true, message: `✅ ${email} is now an admin!` });
  });
});

// ═══════════════════════════════════════════════
//  SOCKET.IO
// ═══════════════════════════════════════════════
const onlineUsers = new Map();

io.on("connection", (socket) => {
  console.log("🔌 Socket connected:", socket.id);

  socket.on("join", (email) => {
    socket.userEmail = email;
    onlineUsers.set(email, socket.id);
    io.emit("online-users", Array.from(onlineUsers.keys()));
    console.log("👤 Joined:", email);
  });

  socket.on("join-group", (groupId) => {
    socket.join("group_" + groupId);
  });

  socket.on("typing", ({ to, from }) => {
    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) io.to(receiverSocketId).emit("typing", { from });
  });

  socket.on("stop-typing", ({ to, from }) => {
    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) io.to(receiverSocketId).emit("stop-typing", { from });
  });

  socket.on("msg-seen", ({ to, from }) => {
    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) io.to(receiverSocketId).emit("msg-seen", { from });
  });

  socket.on("private-message", ({ to, from, message, type, fileUrl, fileName }) => {
    db.query(
      "INSERT INTO messages (sender, receiver, message, type, file_url, file_name) VALUES (?, ?, ?, ?, ?, ?)",
      [from, to, message || "", type || "text", fileUrl || null, fileName || null],
      (err, result) => {
        const msgId = result ? result.insertId : null;
        const payload = { id: msgId, from, message, type, fileUrl, fileName, time: new Date().toISOString() };
        socket.emit('private-message-echo', payload);
        const receiverSocketId = onlineUsers.get(to);
        if (receiverSocketId) io.to(receiverSocketId).emit("private-message", payload);
      }
    );
  });

  socket.on("group-message", ({ groupId, from, message, type, fileUrl, fileName }) => {
    db.query(
      "INSERT INTO group_messages (group_id, sender, message, type, file_url, file_name) VALUES (?, ?, ?, ?, ?, ?)",
      [groupId, from, message || "", type || "text", fileUrl || null, fileName || null],
      (err, result) => {
        const msgId = result ? result.insertId : null;
        const payload = { id: msgId, groupId, from, message, type, fileUrl, fileName, time: new Date().toISOString() };
        socket.emit('group-message-echo', payload);
        socket.broadcast.emit("group-message", payload);
      }
    );
  });

  socket.on("delete-message", ({ msgId, deletedFor, to, groupId }) => {
    if (groupId) {
      io.emit("message-deleted", { msgId, deletedFor });
    } else if (to) {
      const receiverSocketId = onlineUsers.get(to);
      if (receiverSocketId) io.to(receiverSocketId).emit("message-deleted", { msgId, deletedFor });
    }
  });

  socket.on("disconnect", () => {
    if (socket.userEmail) {
      io.emit("user-last-seen", { email: socket.userEmail, time: new Date().toISOString() });
      onlineUsers.delete(socket.userEmail);
      io.emit("online-users", Array.from(onlineUsers.keys()));
      console.log("❌ Disconnected:", socket.userEmail);
    }
  });
});

server.listen(5000, () => console.log("🚀 Server running → http://localhost:5000"));