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

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: "*" } });

app.use(express.json());
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));

// ─── Uploads folder ───
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
app.use("/uploads", express.static(uploadsDir));

// ─── Serve frontend ───
const frontendDir = path.join(__dirname, "../frontend");
app.use(express.static(frontendDir));

// ─── Multer config ───
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename:    (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e6);
    cb(null, unique + path.extname(file.originalname));
  }
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// ─── MySQL ───
const db = mysql.createConnection({
  host:     process.env.DB_HOST     || "localhost",
  port:     process.env.DB_PORT     || 3306,
  user:     process.env.DB_USER     || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME     || "logindb",
  ssl: process.env.DB_HOST && !process.env.DB_HOST.includes('localhost')
       ? { rejectUnauthorized: false } : false
});
db.connect(err => {
  if (err) console.log("❌ MySQL Error:", err.message);
  else     console.log("✅ MySQL Connected");
});

// ─── Create Tables ───
db.query(`CREATE TABLE IF NOT EXISTS groups_table (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  created_by VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`, err => { if (err) console.log('❌ groups_table:', err.message); else console.log('✅ groups_table ready'); });

db.query(`CREATE TABLE IF NOT EXISTS group_members (
  id INT AUTO_INCREMENT PRIMARY KEY,
  group_id INT NOT NULL,
  email VARCHAR(255) NOT NULL
)`, err => { if (err) console.log('❌ group_members:', err.message); else console.log('✅ group_members ready'); });

db.query(`CREATE TABLE IF NOT EXISTS group_messages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  group_id INT NOT NULL,
  sender VARCHAR(255) NOT NULL,
  message TEXT,
  type VARCHAR(20) DEFAULT 'text',
  file_url VARCHAR(500),
  file_name VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`, err => { if (err) console.log('❌ group_messages:', err.message); else console.log('✅ group_messages ready'); });

db.query(`CREATE TABLE IF NOT EXISTS messages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sender VARCHAR(255) NOT NULL,
  receiver VARCHAR(255) NOT NULL,
  message TEXT,
  type VARCHAR(20) DEFAULT 'text',
  file_url VARCHAR(500),
  file_name VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`, err => { if (err) console.log("❌ messages:", err.message); else console.log("✅ messages ready"); });

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

// ════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ message: "All fields required" });
  const hash = await bcrypt.hash(password, 10);
  db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email, hash], err => {
    if (err) return res.json({ message: "User already exists" });
    res.json({ message: "Registered successfully" });
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
    if (!result || result.length === 0) return res.json({ message: "User not found" });
    const match = await bcrypt.compare(password, result[0].password);
    if (!match) return res.json({ message: "Wrong password" });
    const token = jwt.sign({ id: result[0].id, email }, process.env.JWT_SECRET || "mysupersecretkey", { expiresIn: "7d" });
    res.json({ message: "Login success", token, email });
  });
});

app.post("/firebase-login", async (req, res) => {
  const { idToken } = req.body;
  if (!idToken) return res.json({ success: false, message: "No token provided" });
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    const { email, name, picture } = decoded;
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
      if (err) return res.status(500).json({ success: false, message: "DB error" });
      const issueToken = (userId) => {
        const token = jwt.sign({ id: userId, email }, process.env.JWT_SECRET || "mysupersecretkey", { expiresIn: "7d" });
        res.json({ success: true, token, email, name, avatar: picture });
      };
      if (result.length === 0) {
        db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email, "OAUTH_USER"], (err2, r) => {
          if (err2) return res.json({ success: false, message: "Could not create user" });
          issueToken(r.insertId);
        });
      } else { issueToken(result[0].id); }
    });
  } catch (err) {
    res.status(401).json({ success: false, message: "Invalid Firebase token: " + err.message });
  }
});

app.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ success: false, message: "Email required" });
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore.set(email, { otp, expiresAt: Date.now() + 10 * 60 * 1000 });
  const transporter = nodemailer.createTransport({
    service: "gmail", auth: { user: process.env.MAIL_USER, pass: process.env.MAIL_PASS }
  });
  try {
    await transporter.sendMail({
      from: `"YourApp" <${process.env.MAIL_USER}>`, to: email,
      subject: "Your OTP Code",
      html: `<h2>Your OTP: <strong>${otp}</strong></h2><p>Valid for 10 minutes.</p>`
    });
    res.json({ success: true, message: "OTP sent" });
  } catch (err) { res.json({ success: false, message: "Email send failed: " + err.message }); }
});

app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const stored = otpStore.get(email);
  if (!stored) return res.json({ success: false, message: "No OTP found." });
  if (Date.now() > stored.expiresAt) { otpStore.delete(email); return res.json({ success: false, message: "OTP expired." }); }
  if (stored.otp !== otp) return res.json({ success: false, message: "Wrong OTP." });
  otpStore.delete(email);
  db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
    const done = (userId) => {
      const token = jwt.sign({ id: userId, email }, process.env.JWT_SECRET || "mysupersecretkey", { expiresIn: "7d" });
      res.json({ success: true, message: "OTP Verified", token });
    };
    if (!result || result.length === 0) {
      db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email, "OTP_USER"], (e, r) => done(r.insertId));
    } else { done(result[0].id); }
  });
});

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

// ════════════════════════════════════
// CHAT API ROUTES
// ════════════════════════════════════

app.get("/users", (req, res) => {
  db.query("SELECT email FROM users", (err, result) => {
    if (err) return res.json({ success: false });
    res.json({ success: true, users: result.map(r => r.email) });
  });
});

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
        res.json({ success: true, messages: result });
      }
    );
  } catch { res.status(401).json({ success: false }); }
});

app.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) return res.json({ success: false, message: "No file" });
  // For local: serve from /uploads/filename
  const fileName = req.file.originalname;
  const mimeType = req.file.mimetype;
  const fileUrl  = "/uploads/" + req.file.filename;  // relative URL
  let type = "file";
  if (mimeType.startsWith("image/")) type = "image";
  else if (mimeType.startsWith("video/")) type = "video";
  else if (mimeType.startsWith("audio/")) type = "audio";
  res.json({ success: true, fileUrl, fileName, type });
});

app.get("/home", (req, res) => {
  const token = req.headers["authorization"];
  if (!token) return res.json({ message: "No token — please login" });
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET || "mysupersecretkey");
    res.json({ message: `✅ User ID: ${user.id} | Email: ${user.email}` });
  } catch { res.status(401).json({ message: "Invalid or expired token" }); }
});

// ── GROUP ROUTES ──
app.post("/groups", (req, res) => {
  const { name, members, created_by } = req.body;
  if (!name || !created_by) return res.json({ success: false, message: 'Name required' });
  db.query('INSERT INTO groups_table (name, created_by) VALUES (?, ?)', [name, created_by], (err, result) => {
    if (err) return res.json({ success: false, message: err.message });
    const groupId = result.insertId;
    const allMembers = [...new Set([created_by, ...members])];
    const values = allMembers.map(email => [groupId, email]);
    db.query('INSERT INTO group_members (group_id, email) VALUES ?', [values], (err2) => {
      if (err2) return res.json({ success: false, message: err2.message });
      res.json({ success: true, groupId, name });
    });
  });
});

app.get("/groups/:email", (req, res) => {
  const { email } = req.params;
  db.query(
    `SELECT g.id, g.name, g.created_by FROM groups_table g
     JOIN group_members gm ON g.id = gm.group_id
     WHERE gm.email = ?`,
    [email],
    (err, result) => {
      if (err) return res.json({ success: false });
      res.json({ success: true, groups: result });
    }
  );
});

app.get("/groups/:groupId/members", (req, res) => {
  db.query('SELECT email FROM group_members WHERE group_id = ?', [req.params.groupId], (err, result) => {
    if (err) return res.json({ success: false });
    res.json({ success: true, members: result.map(r => r.email) });
  });
});

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

// ════════════════════════════════════
// SOCKET.IO  ← THE FIXED PART
// ════════════════════════════════════
const onlineUsers = new Map(); // email → socket.id

io.on("connection", (socket) => {
  console.log("🔌 Connected:", socket.id);

  // 1. User registers their email after connecting
  socket.on("join", (email) => {
    socket.userEmail = email;
    onlineUsers.set(email, socket.id);
    io.emit("online-users", Array.from(onlineUsers.keys()));
    console.log("👤 Online:", email);

    // Auto-join all group rooms this user belongs to
    // (so they receive messages even if they haven't opened the group)
    db.query(
      "SELECT group_id FROM group_members WHERE email = ?",
      [email],
      (err, rows) => {
        if (!err && rows) {
          rows.forEach(row => {
            socket.join("group_" + row.group_id);
            console.log(`   ↳ Auto-joined room: group_${row.group_id}`);
          });
        }
      }
    );
  });

  // 2. Explicit join-group (when user clicks a group chat)
  socket.on("join-group", (groupId) => {
    const room = "group_" + groupId;
    socket.join(room);
    console.log(`👥 ${socket.userEmail || socket.id} joined room: ${room}`);
  });

  // 3. Private message → save to DB + deliver to recipient
  socket.on("private-message", ({ to, from, message, type, fileUrl, fileName }) => {
    db.query(
      "INSERT INTO messages (sender, receiver, message, type, file_url, file_name) VALUES (?, ?, ?, ?, ?, ?)",
      [from, to, message || "", type || "text", fileUrl || null, fileName || null],
      (err) => { if (err) console.log("❌ private-message DB error:", err.message); }
    );
    const recipientSocketId = onlineUsers.get(to);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit("private-message", {
        from, message, type, fileUrl, fileName,
        time: new Date().toISOString()
      });
    }
  });

  // 4. Group message → save to DB + broadcast to entire room  ← KEY FIX
  socket.on("group-message", ({ groupId, from, message, type, fileUrl, fileName }) => {
    db.query(
      "INSERT INTO group_messages (group_id, sender, message, type, file_url, file_name) VALUES (?, ?, ?, ?, ?, ?)",
      [groupId, from, message || "", type || "text", fileUrl || null, fileName || null],
      (err, result) => {
        if (err) {
          console.log("❌ group-message DB error:", err.message);
          return;
        }
        const payload = {
          groupId,
          from,
          message,
          type,
          fileUrl,
          fileName,
          time: new Date().toISOString()
        };
        // Broadcast to everyone in the room (including sender for confirmation)
        io.to("group_" + groupId).emit("group-message", payload);
        console.log(`✅ Group msg → room group_${groupId} by ${from}: "${message}"`);
      }
    );
  });

  // 5. Typing
  socket.on("typing", ({ to, from }) => {
    const s = onlineUsers.get(to);
    if (s) io.to(s).emit("typing", { from });
  });

  socket.on("stop-typing", ({ to, from }) => {
    const s = onlineUsers.get(to);
    if (s) io.to(s).emit("stop-typing", { from });
  });

  // 6. Seen
  socket.on("msg-seen", ({ to, from }) => {
    const s = onlineUsers.get(to);
    if (s) io.to(s).emit("msg-seen", { from });
  });

  // 7. Disconnect
  socket.on("disconnect", () => {
    if (socket.userEmail) {
      io.emit("user-last-seen", { email: socket.userEmail, time: new Date().toISOString() });
      onlineUsers.delete(socket.userEmail);
      io.emit("online-users", Array.from(onlineUsers.keys()));
      console.log("🔴 Offline:", socket.userEmail);
    }
  });
});

server.listen(5000, () => console.log("🚀 Server running → http://localhost:5000"));