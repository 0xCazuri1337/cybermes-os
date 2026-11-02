import sqlite3
SCHEMA = """
CREATE TABLE IF NOT EXISTS lessons(
  id INTEGER PRIMARY KEY, topic TEXT, body TEXT, score REAL,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY, title TEXT, class_id TEXT, severity TEXT,
  status TEXT, created_at TEXT DEFAULT (datetime('now'))
);
"""
def init(con):
    con.executescript(SCHEMA)
    con.commit()
