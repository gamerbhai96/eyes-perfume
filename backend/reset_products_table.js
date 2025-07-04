import sqlite3 from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const db = new sqlite3.Database(path.join(__dirname, 'users.db'));
db.serialize(() => {
  db.run('DROP TABLE IF EXISTS products');
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    originalPrice REAL,
    image TEXT,
    description TEXT,
    category TEXT,
    rating REAL,
    isNew INTEGER,
    isBestseller INTEGER
  )`);
  console.log('Products table reset.');
  db.close();
}); 