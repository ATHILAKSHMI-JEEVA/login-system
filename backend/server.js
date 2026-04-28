const express    = require("express");
const mysql      = require("mysql2");
const bcrypt     = require("bcrypt");
const jwt        = require("jsonwebtoken");
const cors       = require("cors");
const nodemailer = require("nodemailer");
const admin      = require("firebase-admin");
const http       = require("http");
const { Server } = require("socket.io");
require("dotenv").config();

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: "*" } });

app.use(express.json());
app.use(cors());

// ─────────────────────────────────────
// ✅ MySQL Connection
// ─────────────────────────────────────
const db = mysql.createConnection({
  host:     process.env.DB_HOST     || "localhost",
  port:     process.env.DB_PORT     || 3306,
  user:     process.env.DB_USER     || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME     || "logindb",
  ssl: { rejectUnauthorized: false }
});
db.connect(err => {
  if (err) console.log("❌ MySQL Error:", err.message);
  else     console.log("✅ MySQL Connected");
});

// ─────────────────────────────────────
// ✅ Create messages table if not exists
// ─────────────────────────────────────
db.query(`
  CREATE TABLE IF NOT EXISTS messages (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    sender     VARCHAR(255) NOT NULL,
    receiver   VARCHAR(255) NOT NULL,
    message    TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`, (err) => {
  if (err) console.log("❌ Table error:", err.message);
  else     console.log("✅ Messages table ready");
});

// ─────────────────────────────────────
// ✅ Firebase Admin SDK
// ─────────────────────────────────────
try {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
  console.log("✅ Firebase Admin Ready");
} catch (e) {
  console.log("⚠️  Firebase Admin not initialized:", e.message);
}

const otpStore = new Map();

// ─────────────────────────────────────
// ✅ REGISTER
// ─────────────────────────────────────
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ message: "All fields required" });
  const hash = await bcrypt.hash(password, 10);
  db.query(
    "INSERT INTO users (email, password) VALUES (?, ?)",
    [email, hash],
    (err) => {
      if (err) return res.json({ message: "User already exists" });
      res.json({ message: "Registered successfully" });
    }
  );
});

// ─────────────────────────────────────
// ✅ LOGIN
// ─────────────────────────────────────
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
    if (!result || result.length === 0) return res.json({ message: "User not found" });
    const match = await bcrypt.compare(password, result[0].password);
    if (!match) return res.json({ message: "Wrong password" });
    const token = jwt.sign({ id: result[0].id, email }, process.env.JWT_SECRET || "mysupersecretkey", { expiresIn: "1h" });
    res.json({ message: "Login success", token });
  });
});

// ─────────────────────────────────────
// ✅ FIREBASE LOGIN
// ─────────────────────────────────────
app.post("/firebase-login", async (req, res) => {
  const { idToken } = req.body;
  if (!idToken) return res.json({ success: false, message: "No token provided" });
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    const { email, name, picture } = decoded;
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
      if (err) return res.status(500).json({ success: false, message: "DB error" });
      const issueToken = (userId) => {
        const token = jwt.sign({ id: userId, email }, process.env.JWT_SECRET || "mysupersecretkey", { expiresIn: "1h" });
        res.json({ success: true, token, email, name, avatar: picture });
      };
      if (result.length === 0) {
        db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email, "OAUTH_USER"], (err2, r) => {
          if (err2) return res.json({ success: false, message: "Could not create user" });
          issueToken(r.insertId);
        });
      } else {
        issueToken(result[0].id);
      }
    });
  } catch (err) {
    res.status(401).json({ success: false, message: "Invalid Firebase token: " + err.message });
  }
});

// ─────────────────────────────────────
// ✅ SEND OTP
// ─────────────────────────────────────
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
      from: `"YourApp" <${process.env.MAIL_USER}>`,
      to: email,
      subject: "Your OTP Code",
      html: `<h2>Your OTP: <strong>${otp}</strong></h2><p>Valid for 10 minutes.</p>`
    });
    res.json({ success: true, message: "OTP sent" });
  } catch (err) {
    res.json({ success: false, message: "Email send failed: " + err.message });
  }
});

// ─────────────────────────────────────
// ✅ VERIFY OTP
// ─────────────────────────────────────
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const stored = otpStore.get(email);
  if (!stored) return res.json({ success: false, message: "No OTP found." });
  if (Date.now() > stored.expiresAt) { otpStore.delete(email); return res.json({ success: false, message: "OTP expired." }); }
  if (stored.otp !== otp) return res.json({ success: false, message: "Wrong OTP." });
  otpStore.delete(email);
  db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
    const done = (userId) => {
      const token = jwt.sign({ id: userId, email }, process.env.JWT_SECRET || "mysupersecretkey", { expiresIn: "1h" });
      res.json({ success: true, message: "OTP Verified", token });
    };
    if (!result || result.length === 0) {
      db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email, "OTP_USER"], (e, r) => done(r.insertId));
    } else {
      done(result[0].id);
    }
  });
});

// ─────────────────────────────────────
// ✅ RESET PASSWORD
// ─────────────────────────────────────
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

// ─────────────────────────────────────
// ✅ GET ALL USERS (for user list)
// ─────────────────────────────────────
app.get("/users", (req, res) => {
  const token = req.headers["authorization"];
  if (!token) return res.json({ success: false, message: "No token" });
  try {
    jwt.verify(token, process.env.JWT_SECRET || "mysupersecretkey");
    db.query("SELECT email FROM users", (err, result) => {
      if (err) return res.json({ success: false });
      res.json({ success: true, users: result.map(r => r.email) });
    });
  } catch {
    res.status(401).json({ success: false });
  }
});

// ─────────────────────────────────────
// ✅ GET CHAT HISTORY between two users
// ─────────────────────────────────────
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
  } catch {
    res.status(401).json({ success: false });
  }
});

// ─────────────────────────────────────
// ✅ PROTECTED HOME ROUTE
// ─────────────────────────────────────
app.get("/home", (req, res) => {
  const token = req.headers["authorization"];
  if (!token) return res.json({ message: "No token — please login" });
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET || "mysupersecretkey");
    res.json({ message: `✅ Secure data loaded! User ID: ${user.id} | Email: ${user.email}` });
  } catch {
    res.status(401).json({ message: "Invalid or expired token" });
  }
});

// ─────────────────────────────────────
// ✅ SOCKET.IO — Real-time Private Chat
// ─────────────────────────────────────
const onlineUsers = new Map(); // email -> socketId

io.on("connection", (socket) => {
  console.log("🔌 Socket connected:", socket.id);

  // User joins with their email
  socket.on("join", (email) => {
    socket.userEmail = email;
    onlineUsers.set(email, socket.id);
    // Broadcast updated online list to everyone
    io.emit("online-users", Array.from(onlineUsers.keys()));
    console.log("👤 Joined:", email);
  });

  // Private message
  socket.on("private-message", ({ to, from, message }) => {
    // Save to DB
    db.query(
      "INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
      [from, to, message]
    );

    // Send to receiver if online
    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit("private-message", { from, message, time: new Date().toISOString() });
    }

    // Echo back to sender too
    socket.emit("private-message-sent", { to, message, time: new Date().toISOString() });
  });

  // Disconnect
  socket.on("disconnect", () => {
    if (socket.userEmail) {
      io.emit("user-last-seen", { email: socket.userEmail, time: new Date().toISOString() });
    }
    if (socket.userEmail) {
      onlineUsers.delete(socket.userEmail);
      io.emit("online-users", Array.from(onlineUsers.keys()));
      console.log("❌ Disconnected:", socket.userEmail);
    }
  });
});

server.listen(5000, () => console.log("🚀 Server running → http://localhost:5000"));
