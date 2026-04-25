# 🔐 Secure Login System — Setup Guide

## Folder Structure
```
login-system/
├── frontend/
│   ├── index.html      ← Login page (Google, GitHub, Password, OTP)
│   ├── home.html       ← Dashboard (shows your Google email + avatar)
│   ├── register.html
│   └── forgot.html
└── backend/
    ├── server.js
    ├── .env
    └── serviceAccountKey.json   ← (your existing file)
```

---

## 1️⃣ MySQL Setup
Run this in MySQL Workbench or terminal:
```sql
CREATE DATABASE IF NOT EXISTS logindb;
USE logindb;
CREATE TABLE IF NOT EXISTS users (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  email    VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL
);
```

---

## 2️⃣ Start Backend
```bash
cd backend
node server.js
```
You should see:
```
✅ MySQL Connected
✅ Firebase Admin Ready
🚀 Server running → http://localhost:5000
```

---

## 3️⃣ Open Frontend
Open `frontend/index.html` in your browser (or use Live Server in VS Code).

---

## 4️⃣ Google Login Fix — Firebase Console Steps

### Problem: "Continue with Google" not showing email
**Fix in Firebase Console:**

1. Go to → https://console.firebase.google.com
2. Select your project: **myloginapp-4a42a**
3. Go to → **Authentication** → **Sign-in method**
4. Make sure **Google** is **Enabled** ✅
5. Go to → **Authentication** → **Settings** → **Authorized domains**
6. Add `localhost` if not already there ✅

### Google OAuth also needs this in Google Cloud Console:
1. Go to → https://console.cloud.google.com
2. Search: **OAuth 2.0 Client IDs**
3. Click your Web Client → **Authorized JavaScript origins**
4. Add: `http://localhost` and `http://127.0.0.1`
5. **Authorized redirect URIs** → Add: `https://myloginapp-4a42a.firebaseapp.com/__/auth/handler`
6. Save ✅

---

## 5️⃣ How It Works

| Button | What happens |
|--------|-------------|
| **Google** | Firebase popup opens → you pick your Gmail account → email + avatar shown in dashboard |
| **GitHub** | Firebase GitHub popup → same flow |
| **Send OTP** | Email sent to inbox → enter 6 digits → dashboard opens |
| **Sign in** | Email + password → backend MySQL check → dashboard |

---

## 6️⃣ Google Login Flow (Detailed)

```
User clicks "Google"
    ↓
Firebase opens "Continue with Google" popup
    ↓
User selects their Gmail account
    ↓
Firebase returns: idToken + email + name + photoURL
    ↓
Frontend sends idToken → POST /firebase-login
    ↓
Backend verifies idToken with Firebase Admin SDK
    ↓
Creates/finds user in MySQL
    ↓
Returns JWT + email + name + avatar
    ↓
localStorage saves: token, email, name, avatar, method="Google"
    ↓
Redirects → home.html
    ↓
Dashboard shows: Google avatar + Gmail address in navbar
```
