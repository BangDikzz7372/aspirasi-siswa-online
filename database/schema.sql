
-- ASPIRASI SISWA ONLINE
-- Database Schema v1.0

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

CREATE TABLE IF NOT EXISTS aspiration_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  aspiration_id INTEGER NOT NULL,
  sender_type TEXT NOT NULL,
  message TEXT NOT NULL,
  visibility TEXT DEFAULT 'private',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (aspiration_id) REFERENCES aspirations(id)
);

CREATE TABLE IF NOT EXISTS announcements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  is_published INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
