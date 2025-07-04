import sqlite3 from 'sqlite3';
import fs from 'fs';
import bcrypt from 'bcrypt';
import path from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const db = new sqlite3.Database(path.join(__dirname, 'users.db'));
const users = JSON.parse(fs.readFileSync('./backend/users_seed.json', 'utf-8'));
const orders = JSON.parse(fs.readFileSync('./backend/orders_seed.json', 'utf-8'));

async function seedUsers() {
  for (const u of users) {
    const passwordHash = await bcrypt.hash(u.password, 10);
    db.run(
      'INSERT OR IGNORE INTO users (firstName, lastName, email, passwordHash, role) VALUES (?, ?, ?, ?, ?)',
      [u.firstName, u.lastName, u.email, passwordHash, u.role],
      function (err) {
        if (err) console.error('Error inserting user', u.email, err.message);
        else console.log('Inserted user', u.email);
      }
    );
  }
}

function seedOrders() {
  orders.forEach(o => {
    db.run(
      'INSERT INTO orders (userId, createdAt, name, address, phone) VALUES (?, ?, ?, ?, ?)',
      [o.userId, o.createdAt, o.name, o.address, o.phone],
      function (err) {
        if (err) return console.error('Error inserting order for user', o.userId, err.message);
        const orderId = this.lastID;
        o.items.forEach(item => {
          db.run(
            'INSERT INTO order_items (orderId, perfumeId, quantity) VALUES (?, ?, ?)',
            [orderId, item.perfumeId, item.quantity],
            function (err2) {
              if (err2) console.error('Error inserting order item', err2.message);
            }
          );
        });
        console.log('Inserted order for user', o.userId);
      }
    );
  });
}

(async () => {
  await seedUsers();
  setTimeout(() => {
    seedOrders();
    db.close();
  }, 1000); // Wait for user inserts to finish
})(); 