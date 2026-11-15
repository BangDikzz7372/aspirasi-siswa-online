
-- ASPIRASI SISWA ONLINE
-- Database Schema v1.0

PRAGMA foreign_keys = ON;

-- ADMIN
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- SESI ADMIN
CREATE TABLE IF NOT EXISTS admin_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (admin_id)
    REFERENCES admins(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_token
ON admin_sessions(token_hash);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry
ON admin_sessions(expires_at);

-- ASPIRASI SISWA
CREATE TABLE IF NOT EXISTS aspirations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tracking_code TEXT NOT NULL UNIQUE,
  pin_hash TEXT NOT NULL,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  sender_name TEXT,
  is_anonymous INTEGER DEFAULT 1,
  status TEXT DEFAULT 'Menunggu',
  is_published INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- PESAN ASPIRASI
CREATE TABLE IF NOT EXISTS aspiration_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  aspiration_id INTEGER NOT NULL,
  sender_type TEXT NOT NULL,
  message TEXT NOT NULL,
  visibility TEXT DEFAULT 'private',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (aspiration_id)
    REFERENCES aspirations(id) ON DELETE CASCADE
);

-- PENGUMUMAN OSIS
CREATE TABLE IF NOT EXISTS announcements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  is_published INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ANGGOTA GRUP DISKUSI
CREATE TABLE IF NOT EXISTS group_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nickname TEXT NOT NULL,
  session_token_hash TEXT NOT NULL UNIQUE,
  is_muted INTEGER DEFAULT 0,
  joined_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- PESAN GRUP DISKUSI
CREATE TABLE IF NOT EXISTS group_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id INTEGER,
  message TEXT NOT NULL,
  reply_to INTEGER,
  is_deleted INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (member_id)
    REFERENCES group_members(id),
  FOREIGN KEY (reply_to)
    REFERENCES group_messages(id)
);

-- LAPORAN PESAN
CREATE TABLE IF NOT EXISTS group_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id INTEGER NOT NULL,
  reason TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (message_id)
    REFERENCES group_messages(id)
);

-- INDEX
CREATE INDEX IF NOT EXISTS idx_aspirations_status
ON aspirations(status);

CREATE INDEX IF NOT EXISTS idx_aspirations_published
ON aspirations(is_published);

CREATE INDEX IF NOT EXISTS idx_aspiration_messages
ON aspiration_messages(aspiration_id);

CREATE INDEX IF NOT EXISTS idx_group_messages
ON group_messages(created_at);
