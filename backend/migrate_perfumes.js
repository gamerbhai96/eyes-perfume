import sqlite3 from 'sqlite3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const db = new sqlite3.Database(path.join(__dirname, 'users.db'));
const perfumes = JSON.parse(fs.readFileSync('./backend/perfumes.json', 'utf-8'));

db.serialize(() => {
  db.run('DELETE FROM products', [], function (err) {
    if (err) console.error('Error clearing products table:', err.message);
    else console.log('Cleared products table');
  });

  perfumes.forEach(p => {
    db.run(
      'INSERT OR REPLACE INTO products (id, name, price, originalPrice, image, description, category, rating, isNew, isBestseller) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        p.id,
        p.name,
        p.price,
        p.originalPrice || null,
        p.image,
        p.description,
        p.category || '',
        p.rating || null,
        p.isNew ? 1 : 0,
        p.isBestseller ? 1 : 0
      ],
      function (err) {
        if (err) console.error('Error inserting', p.name, err.message);
        else console.log('Inserted', p.name, 'with id', p.id, p);
      }
    );
  });

  db.close();
}); 