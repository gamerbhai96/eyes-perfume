import express from 'express';
import sqlite3 from 'sqlite3';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

// --- AdminJS Imports ---
import AdminJS from 'adminjs';
import AdminJSExpress from '@adminjs/express';
import { Database, Resource } from '@adminjs/sql';
import session from 'express-session';

dotenv.config();

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const db = new sqlite3.Database(path.join(__dirname, 'users.db'));
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'GOOGLE_CLIENT_ID_HERE';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'GOOGLE_CLIENT_SECRET_HERE';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

const otpStore = {};

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// --- This function sets up and launches AdminJS with Authentication ---
const startAdminJS = async () => {
    try {
        AdminJS.registerAdapter({ Database, Resource });

        const db_admin = new Database('sqlite3', {
            connectionString: path.join(__dirname, 'users.db'),
        });

        const adminJs = new AdminJS({
            branding: {
                companyName: 'EYES Perfume',
                softwareBrothers: false,
            },
            resources: [
                { resource: { table: 'users', database: db_admin } },
                { resource: { table: 'products', database: db_admin } },
                { resource: { table: 'orders', database: db_admin } },
                { resource: { table: 'reviews', database: db_admin } },
                { resource: { table: 'cart', database: db_admin } },
                { resource: { table: 'order_items', database: db_admin } },
            ],
            rootPath: '/admin',
        });

        const adminRouter = AdminJSExpress.buildAuthenticatedRouter(adminJs, {
            authenticate: async (email, password) => {
                const user = await new Promise((resolve, reject) => {
                    db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
                        if (err) reject(err);
                        resolve(row);
                    });
                });

                if (user && user.role === 'admin') {
                    const matched = await bcrypt.compare(password, user.passwordHash);
                    if (matched) {
                        return user;
                    }
                }
                return false;
            },
            cookieName: 'admin-session',
            cookiePassword: 'a-very-secret-and-long-password-for-cookies-change-me',
        });

        // Add middleware for session management
        app.use(session({
            secret: 'a-very-secret-and-long-password-for-sessions-change-me',
            resave: false,
            saveUninitialized: true,
        }));
        
        app.use(adminJs.options.rootPath, adminRouter);
        console.log('AdminJS with authentication is running at /admin');
    } catch (error) {
        console.error("Failed to start AdminJS:", error);
    }
};

startAdminJS();

function sendOtpEmail(email, otp) {
    return transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your EYES Perfume OTP Code',
        text: `Your OTP code is: ${otp}. It expires in 5 minutes.`,
    });
}

function generateOtp() {
    return (Math.floor(100000 + Math.random() * 900000)).toString();
}

function generateTempToken(email) {
    return crypto.randomBytes(24).toString('hex') + ':' + email;
}

app.use(cors({
    origin: [
        'https://eyes-perfume-wl8p.vercel.app',
        'https://eyes-perfume.vercel.app',
        'https://eyes-perfume.onrender.com'
    ],
    credentials: true
}));
app.use(express.json());

// --- Database Table Creation ---
db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, firstName TEXT NOT NULL, lastName TEXT NOT NULL, email TEXT NOT NULL UNIQUE, passwordHash TEXT NOT NULL, role TEXT DEFAULT 'user')`);
db.run(`CREATE TABLE IF NOT EXISTS cart (userId INTEGER, perfumeId INTEGER, quantity INTEGER, PRIMARY KEY (userId, perfumeId))`);
db.run(`CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, userId INTEGER, createdAt TEXT, name TEXT, address TEXT, phone TEXT)`);
db.run(`CREATE TABLE IF NOT EXISTS order_items (orderId INTEGER, perfumeId INTEGER, quantity INTEGER)`);
db.run(`CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, perfumeId INTEGER, userId INTEGER, rating INTEGER, comment TEXT, createdAt TEXT)`);
db.run(`CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, price REAL NOT NULL, originalPrice REAL, image TEXT, description TEXT, category TEXT, rating REAL, isNew INTEGER, isBestseller INTEGER)`);

// --- API and Auth Routes ---
app.get('/', (req, res) => {
    res.send('Perfume backend running');
});

app.post('/api/signup', async (req, res) => {
    const { firstName, lastName, email, password, confirmPassword } = req.body;
    if (!firstName || !lastName || !email || !password || !confirmPassword) {
        return res.status(400).json({ error: 'All fields are required.' });
    }
    if (password !== confirmPassword) {
        return res.status(400).json({ error: 'Passwords do not match.' });
    }
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error.' });
        if (user) return res.status(400).json({ error: 'Email already registered.' });
        try {
            const passwordHash = await bcrypt.hash(password, 10);
            db.run(
                'INSERT INTO users (firstName, lastName, email, passwordHash, role) VALUES (?, ?, ?, ?, ?)',
                [firstName, lastName, email, passwordHash, 'user'],
                function (err) {
                    if (err) return res.status(500).json({ error: 'Failed to create user.' });
                    const otp = generateOtp();
                    const tempToken = generateTempToken(email);
                    otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000, tempToken, user: { id: this.lastID, firstName, lastName, email }, passwordHash, };
                    sendOtpEmail(email, otp).then(() => res.json({ otpRequired: true, tempToken })).catch(() => res.status(500).json({ error: 'Failed to send OTP email.' }));
                }
            );
        } catch (e) {
            res.status(500).json({ error: 'Server error.' });
        }
    });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error.' });
        if (!user) return res.status(400).json({ error: 'Invalid email or password.' });
        const match = await bcrypt.compare(password, user.passwordHash);
        if (!match) return res.status(400).json({ error: 'Invalid email or password.' });
        const otp = generateOtp();
        const tempToken = generateTempToken(email);
        otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000, tempToken, user: { id: user.id, firstName: user.firstName, lastName: user.lastName, email: user.email }, passwordHash: user.passwordHash, };
        sendOtpEmail(email, otp).then(() => res.json({ otpRequired: true, tempToken })).catch(() => res.status(500).json({ error: 'Failed to send OTP email.' }));
    });
});

app.post('/api/verify-otp', (req, res) => {
    const { email, otp, tempToken } = req.body;
    const entry = otpStore[email];
    if (!entry || entry.tempToken !== tempToken) return res.status(400).json({ error: 'Invalid or expired OTP session.' });
    if (Date.now() > entry.expires) {
        delete otpStore[email];
        return res.status(400).json({ error: 'OTP expired.' });
    }
    if (entry.otp !== otp) return res.status(400).json({ error: 'Invalid OTP.' });
    const { user } = entry;
    db.get('SELECT id, firstName, lastName, email, role FROM users WHERE id = ?', [user.id], (err, dbUser) => {
        if (err || !dbUser) {
            delete otpStore[email];
            return res.status(500).json({ error: 'User not found after OTP.' });
        }
        const token = jwt.sign({ id: dbUser.id, email: dbUser.email, role: dbUser.role }, JWT_SECRET, { expiresIn: '7d' });
        delete otpStore[email];
        res.json({ token, user: dbUser });
    });
});

passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
}, (accessToken, refreshToken, profile, done) => {
    const email = profile.emails && profile.emails[0].value;
    if (!email) return done(null, false, { message: 'No email from Google' });
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) return done(err);
        if (user) return done(null, user);
        db.run('INSERT INTO users (firstName, lastName, email, passwordHash, role) VALUES (?, ?, ?, ?, ?)', [profile.name.givenName || '', profile.name.familyName || '', email, '', 'user'], function (err) {
            if (err) return done(err);
            db.get('SELECT * FROM users WHERE id = ?', [this.lastID], (err, newUser) => {
                if (err) return done(err);
                done(null, newUser);
            });
        });
    });
}));

app.use(passport.initialize());
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { session: false, failureRedirect: '/login' }), (req, res) => {
    const user = req.user;
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    const redirectUrl = `${FRONTEND_URL}/login?token=${encodeURIComponent(token)}&user=${encodeURIComponent(JSON.stringify(user))}`;
    res.redirect(redirectUrl);
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

function authenticateAdmin(req, res, next) {
    authenticateToken(req, res, () => {
        db.get('SELECT role FROM users WHERE id = ?', [req.user.id], (err, user) => {
            if (err || !user) return res.sendStatus(403);
            if (user.role === 'admin') return next();
            res.sendStatus(403);
        });
    });
}

app.get('/api/profile', authenticateToken, (req, res) => {
    db.get('SELECT id, firstName, lastName, email, role FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    });
});

app.post('/api/profile', authenticateToken, async (req, res) => {
    const { firstName, lastName, email, password } = req.body;
    if (!firstName && !lastName && !email && !password) {
        return res.status(400).json({ error: 'No fields to update' });
    }
    db.get('SELECT * FROM users WHERE id = ?', [req.user.id], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user) return res.status(404).json({ error: 'User not found' });
        let passwordHash = user.passwordHash;
        if (password) passwordHash = await bcrypt.hash(password, 10);
        db.run(
            'UPDATE users SET firstName = ?, lastName = ?, email = ?, passwordHash = ? WHERE id = ?',
            [firstName || user.firstName, lastName || user.lastName, email || user.email, passwordHash, req.user.id],
            function (err) {
                if (err) return res.status(500).json({ error: 'Failed to update profile' });
                res.json({ success: true });
            }
        );
    });
});

app.get('/api/cart', authenticateToken, (req, res) => {
    db.all('SELECT perfumeId, quantity FROM cart WHERE userId = ?', [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

app.post('/api/cart', authenticateToken, (req, res) => {
    const { perfumeId, quantity } = req.body;
    if (!perfumeId || quantity == null) return res.status(400).json({ error: 'perfumeId and quantity required' });
    if (quantity <= 0) {
        db.run('DELETE FROM cart WHERE userId = ? AND perfumeId = ?', [req.user.id, perfumeId], function (err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ success: true });
        });
    } else {
        db.run('INSERT OR REPLACE INTO cart (userId, perfumeId, quantity) VALUES (?, ?, ?)', [req.user.id, perfumeId, quantity], function (err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ success: true });
        });
    }
});

app.post('/api/checkout', authenticateToken, (req, res) => {
    const { name, address, phone } = req.body;
    db.all('SELECT perfumeId, quantity FROM cart WHERE userId = ?', [req.user.id], (err, items) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!items.length) return res.status(400).json({ error: 'Cart is empty' });
        db.run('INSERT INTO orders (userId, createdAt, name, address, phone) VALUES (?, ?, ?, ?, ?)', [req.user.id, new Date().toISOString(), name || '', address || '', phone || ''], function (err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            const orderId = this.lastID;
            const stmt = db.prepare('INSERT INTO order_items (orderId, perfumeId, quantity) VALUES (?, ?, ?)');
            items.forEach(item => stmt.run(orderId, item.perfumeId, item.quantity));
            stmt.finalize();
            db.run('DELETE FROM cart WHERE userId = ?', [req.user.id]);
            res.json({ success: true, orderId });
        });
    });
});

app.get('/api/orders', authenticateToken, (req, res) => {
    db.all('SELECT * FROM orders WHERE userId = ? ORDER BY createdAt DESC', [req.user.id], (err, orders) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!orders.length) return res.json([]);
        const orderIds = orders.map(o => o.id);
        db.all(`SELECT * FROM order_items WHERE orderId IN (${orderIds.map(() => '?').join(',')})`, orderIds, (err, items) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            const ordersWithItems = orders.map(order => ({ ...order, items: items.filter(i => i.orderId === order.id) }));
            res.json(ordersWithItems);
        });
    });
});

app.post('/api/reviews', authenticateToken, (req, res) => {
    const { perfumeId, rating, comment } = req.body;
    if (!perfumeId || !rating) return res.status(400).json({ error: 'perfumeId and rating required' });
    db.run('INSERT INTO reviews (perfumeId, userId, rating, comment, createdAt) VALUES (?, ?, ?, ?, ?)', [perfumeId, req.user.id, rating, comment || '', new Date().toISOString()], function (err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true, reviewId: this.lastID });
    });
});

app.get('/api/reviews/:perfumeId', (req, res) => {
    db.all('SELECT r.*, u.firstName, u.lastName FROM reviews r JOIN users u ON r.userId = u.id WHERE r.perfumeId = ? ORDER BY r.createdAt DESC', [req.params.perfumeId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

const productColumns = [ { name: 'originalPrice', type: 'REAL' }, { name: 'category', type: 'TEXT' }, { name: 'rating', type: 'REAL' }, { name: 'isNew', type: 'INTEGER' }, { name: 'isBestseller', type: 'INTEGER' }];
db.all("PRAGMA table_info(products)", (err, columns) => {
    if (err) return;
    const colNames = columns.map(col => col.name);
    productColumns.forEach(col => {
        if (!colNames.includes(col.name)) {
            db.run(`ALTER TABLE products ADD COLUMN ${col.name} ${col.type}`);
        }
    });
});

app.get('/api/products', (req, res) => {
    db.all('SELECT * FROM products', (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

app.post('/api/products', authenticateAdmin, (req, res) => {
    const { name, price, originalPrice, image, description, category, rating, isNew, isBestseller } = req.body;
    if (!name || !price) return res.status(400).json({ error: 'Name and price required' });
    db.run(
        'INSERT INTO products (name, price, originalPrice, image, description, category, rating, isNew, isBestseller) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [name, price, originalPrice, image || '', description || '', category || '', rating || null, isNew ? 1 : 0, isBestseller ? 1 : 0],
        function (err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ id: this.lastID, ...req.body });
        }
    );
});

app.put('/api/products/:id', authenticateAdmin, (req, res) => {
    const { name, price, originalPrice, image, description, category, rating, isNew, isBestseller } = req.body;
    db.run(
        'UPDATE products SET name = ?, price = ?, originalPrice = ?, image = ?, description = ?, category = ?, rating = ?, isNew = ?, isBestseller = ? WHERE id = ?',
        [name, price, originalPrice, image, description, category, rating, isNew ? 1 : 0, isBestseller ? 1 : 0, req.params.id],
        function (err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ success: true });
        }
    );
});

app.delete('/api/products/:id', authenticateAdmin, (req, res) => {
    db.run('DELETE FROM products WHERE id = ?', [req.params.id], function (err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true });
    });
});

app.get('/api/admin/users', authenticateAdmin, (req, res) => {
    db.all('SELECT id, firstName, lastName, email, role FROM users', (err, users) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(users);
    });
});

app.put('/api/admin/users/:id', authenticateAdmin, (req, res) => {
    const { firstName, lastName, email, role } = req.body;
    db.run('UPDATE users SET firstName = ?, lastName = ?, email = ?, role = ? WHERE id = ?', [firstName, lastName, email, role, req.params.id], function (err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true });
    });
});

app.delete('/api/admin/users/:id', authenticateAdmin, (req, res) => {
    db.run('DELETE FROM users WHERE id = ?', [req.params.id], function (err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true });
    });
});

app.get('/api/admin/orders', authenticateAdmin, (req, res) => {
    db.all('SELECT o.*, u.firstName, u.lastName, u.email FROM orders o JOIN users u ON o.userId = u.id ORDER BY o.createdAt DESC', (err, orders) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!orders.length) return res.json([]);
        const orderIds = orders.map(o => o.id);
        db.all(`SELECT * FROM order_items WHERE orderId IN (${orderIds.map(() => '?').join(',')})`, orderIds, (err, items) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            const ordersWithItems = orders.map(order => ({ ...order, items: items.filter(i => i.orderId === order.id) }));
            res.json(ordersWithItems);
        });
    });
});

app.put('/api/admin/orders/:id', authenticateAdmin, (req, res) => {
    const { name, address, phone } = req.body;
    db.run('UPDATE orders SET name = ?, address = ?, phone = ? WHERE id = ?', [name, address, phone, req.params.id], function (err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true });
    });
});

app.delete('/api/admin/orders/:id', authenticateAdmin, (req, res) => {
    db.run('DELETE FROM order_items WHERE orderId = ?', [req.params.id], function (err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        db.run('DELETE FROM orders WHERE id = ?', [req.params.id], function (err2) {
            if (err2) return res.status(500).json({ error: 'Database error' });
            res.json({ success: true });
        });
    });
});

// --- Final server listen ---
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
