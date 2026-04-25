const express    = require("express");
const mysql      = require("mysql2");
const bcrypt     = require("bcrypt");
const jwt        = require("jsonwebtoken");
const cors       = require("cors");
const nodemailer = require("nodemailer");
const admin      = require("firebase-admin");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

// ─────────────────────────────────────
// ✅ MySQL Connection
// ─────────────────────────────────────
const db = mysql.createConnection({
  host:     process.env.DB_HOST     || "localhost",
  user:     process.env.DB_USER     || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME     || "logindb"
});

db.connect(err => {
  if (err) console.log("❌ MySQL Error:", err.message);
  else     console.log("✅ MySQL Connected");
});

// ─────────────────────────────────────
// ✅ Firebase Admin SDK
// ─────────────────────────────────────
try {
  const serviceAccount = require("./serviceAccountKey.json");
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
  console.log("✅ Firebase Admin Ready");
} catch (e) {
  console.log("⚠️  Firebase Admin not initialized:", e.message);
}

// In-memory OTP store  { email -> { otp, expiresAt } }
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
// ✅ EMAIL + PASSWORD LOGIN
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
// ✅ GOOGLE / GITHUB FIREBASE LOGIN
//    → Verifies Firebase idToken
//    → Returns JWT + user email/name/avatar
// ─────────────────────────────────────
app.post("/firebase-login", async (req, res) => {
  const { idToken } = req.body;
  if (!idToken) return res.json({ success: false, message: "No token provided" });

  try {
    // Verify with Firebase Admin
    const decoded = await admin.auth().verifyIdToken(idToken);
    const { email, name, picture, uid } = decoded;

    // Auto-create user in MySQL if not exists
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
      if (err) return res.status(500).json({ success: false, message: "DB error" });

      const issueToken = (userId) => {
        const token = jwt.sign(
          { id: userId, email },
          process.env.JWT_SECRET || "mysupersecretkey",
          { expiresIn: "1h" }
        );
        res.json({ success: true, token, email, name, avatar: picture });
      };

      if (result.length === 0) {
        // New user → insert
        db.query(
          "INSERT INTO users (email, password) VALUES (?, ?)",
          [email, "OAUTH_USER"],
          (err2, r) => {
            if (err2) return res.json({ success: false, message: "Could not create user" });
            issueToken(r.insertId);
          }
        );
      } else {
        issueToken(result[0].id);
      }
    });

  } catch (err) {
    console.error("❌ Firebase verify error:", err.message);
    res.status(401).json({ success: false, message: "Invalid Firebase token: " + err.message });
  }
});

// ─────────────────────────────────────
// ✅ SEND OTP  (Nodemailer → Gmail)
// ─────────────────────────────────────
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ success: false, message: "Email required" });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore.set(email, { otp, expiresAt: Date.now() + 10 * 60 * 1000 });

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.MAIL_USER || "jathilakshmi2@gmail.com",
      pass: process.env.MAIL_PASS || "rmhyguxcimphnmew"   // App Password
    }
  });

  try {
    await transporter.sendMail({
      from: `"YourApp" <${process.env.MAIL_USER || "jathilakshmi2@gmail.com"}>`,
      to: email,
      subject: "Your OTP Code — YourApp",
      html: `
        <div style="font-family:sans-serif;max-width:420px;margin:0 auto;background:#0d1117;color:#e6edf3;border-radius:14px;padding:28px;border:1px solid #30363d;">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px;">
            <div style="width:38px;height:38px;background:linear-gradient(135deg,#4493f8,#a371f7);border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;">🔐</div>
            <div>
              <div style="font-weight:600;font-size:15px;">YourApp</div>
              <div style="font-size:11px;color:#8b949e;font-family:monospace;">Secure Portal</div>
            </div>
          </div>
          <h2 style="color:#4493f8;margin-bottom:6px;">Your Login OTP</h2>
          <p style="color:#8b949e;font-size:14px;margin-bottom:20px;">Use this code to sign in. Valid for <strong style="color:#e6edf3;">10 minutes</strong>.</p>
          <div style="background:#161b22;padding:24px;text-align:center;border-radius:10px;border:1px solid #30363d;margin-bottom:20px;">
            <span style="font-size:42px;font-weight:700;letter-spacing:14px;font-family:monospace;color:#4493f8;">${otp}</span>
          </div>
          <p style="color:#8b949e;font-size:12px;font-family:monospace;">🔒 Don't share this code with anyone. YourApp will never ask for your OTP.</p>
        </div>
      `
    });
    console.log("✅ OTP sent to:", email, "→", otp);
    res.json({ success: true, message: "OTP sent" });
  } catch (err) {
    console.error("❌ Email error:", err.message);
    res.json({ success: false, message: "Email send failed: " + err.message });
  }
});

// ─────────────────────────────────────
// ✅ VERIFY OTP
// ─────────────────────────────────────
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const stored = otpStore.get(email);

  if (!stored)                    return res.json({ success: false, message: "No OTP found. Request again." });
  if (Date.now() > stored.expiresAt) { otpStore.delete(email); return res.json({ success: false, message: "OTP expired." }); }
  if (stored.otp !== otp)         return res.json({ success: false, message: "Wrong OTP." });

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
// ✅ FORGOT PASSWORD — RESET
// ─────────────────────────────────────
app.post("/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword) return res.json({ success: false, message: "All fields required" });

  const stored = otpStore.get(email);
  if (!stored)                     return res.json({ success: false, message: "No OTP found. Request again." });
  if (Date.now() > stored.expiresAt) { otpStore.delete(email); return res.json({ success: false, message: "OTP expired" }); }
  if (stored.otp !== otp)          return res.json({ success: false, message: "Wrong OTP" });

  const hashed = await bcrypt.hash(newPassword, 10);
  db.query("UPDATE users SET password = ? WHERE email = ?", [hashed, email], (err, result) => {
    if (err || result.affectedRows === 0) return res.json({ success: false, message: "User not found or DB error" });
    otpStore.delete(email);
    res.json({ success: true, message: "✅ Password updated successfully" });
  });
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

app.listen(5000, () => console.log("🚀 Server running → http://localhost:5000"));
