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
import session from 'express-session';
import connectSqlite3 from 'connect-sqlite3';

// AdminJS Imports
import AdminJS from 'adminjs';
import AdminJSExpress from '@adminjs/express';
import { Database, Resource } from '@adminjs/sql';

// --- THIS IS CRITICAL: Register the adapter right after imports ---
AdminJS.registerAdapter({ Database, Resource });

dotenv.config();

// --- App and Variable Initialization ---
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

// Create a session store that uses SQLite
const SQLiteStore = connectSqlite3(session);
const store = new SQLiteStore({
    db: 'sessions.db', // The file to store sessions in
    dir: __dirname, // The directory for the session database
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// --- Helper Functions ---
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

// --- Main Server Function ---
const startServer = async () => {

    // --- 1. MIDDLEWARE SETUP ---
    app.use(cors({
        origin: [
            'https://eyes-perfume-wl8p.vercel.app',
            'https://eyes-perfume.vercel.app',
            'https://eyes-perfume.onrender.com',
            'http://localhost:5173'
        ],
        credentials: true
    }));
    app.use(express.json());
    // Use the persistent SQLite session store to fix the MemoryStore warning
    app.use(session({
        store: store,
        secret: 'a-very-secret-and-long-password-for-sessions-change-me',
        resave: false,
        saveUninitialized: false, // Recommended for login sessions
        cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 7 days
    }));
    app.use(passport.initialize());
    app.use(passport.session()); // Enable persistent login sessions

    // --- 2. ADMINJS SETUP ---
    try {
        const adminJs = new AdminJS({
            branding: { companyName: 'EYES Perfume', softwareBrothers: false },
            // Pass your database connection directly. Because the adapter is registered,
            // AdminJS will know how to handle this 'db' object.
            resources: [
                { resource: db,
                  options: {
                    // You can specify properties for each resource (table) here
                    // For example, for the users table:
                    id: 'users',
                    properties: { passwordHash: { isVisible: false } }
                  }
                },
                // Add other tables from the same database
                { resource: db, options: { id: 'products' } },
                { resource: db, options: { id: 'orders' } },
                { resource: db, options: { id: 'reviews' } },
                { resource: db, options: { id: 'cart' } },
                { resource: db, options: { id: 'order_items' } },
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
                    if (matched) return user;
                }
                return false;
            },
            cookieName: 'admin-session',
            cookiePassword: 'a-very-secret-and-long-password-for-cookies-change-me',
        });
        app.use(adminJs.options.rootPath, adminRouter);
        console.log('AdminJS setup complete.');
    } catch (error) {
        console.error("Failed to start AdminJS:", error);
    }

    // --- 3. DATABASE TABLE CREATION ---
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, firstName TEXT NOT NULL, lastName TEXT NOT NULL, email TEXT NOT NULL UNIQUE, passwordHash TEXT NOT NULL, role TEXT DEFAULT 'user')`);
        db.run(`CREATE TABLE IF NOT EXISTS cart (userId INTEGER, perfumeId INTEGER, quantity INTEGER, PRIMARY KEY (userId, perfumeId))`);
        db.run(`CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, userId INTEGER, createdAt TEXT, name TEXT, address TEXT, phone TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS order_items (orderId INTEGER, perfumeId INTEGER, quantity INTEGER)`);
        db.run(`CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, perfumeId INTEGER, userId INTEGER, rating INTEGER, comment TEXT, createdAt TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, price REAL NOT NULL, originalPrice REAL, image TEXT, description TEXT, category TEXT, rating REAL, isNew INTEGER, isBestseller INTEGER)`);

        const productColumns = [ { name: 'originalPrice', type: 'REAL' }, { name: 'category', type: 'TEXT' }, { name: 'rating', type: 'REAL' }, { name: 'isNew', type: 'INTEGER' }, { name: 'isBestseller', 'type': 'INTEGER' }];
        db.all("PRAGMA table_info(products)", (err, columns) => {
            if (err) return;
            if (columns) {
                const colNames = columns.map(col => col.name);
                productColumns.forEach(col => {
                    if (!colNames.includes(col.name)) {
                        db.run(`ALTER TABLE products ADD COLUMN ${col.name} ${col.type}`);
                    }
                });
            }
        });
    });

    // --- 4. PASSPORT.JS SETUP ---
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser((id, done) => {
        db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
            done(err, user);
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

    // --- 5. API ROUTES --- (Your existing routes remain unchanged)
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

    app.get('/', (req, res) => res.send('Perfume backend running'));

    app.post('/api/signup', async (req, res) => {
        const { firstName, lastName, email, password, confirmPassword } = req.body;
        if (!firstName || !lastName || !email || !password || !confirmPassword) return res.status(400).json({ error: 'All fields are required.' });
        if (password !== confirmPassword) return res.status(400).json({ error: 'Passwords do not match.' });
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) return res.status(500).json({ error: 'Database error.' });
            if (user) return res.status(400).json({ error: 'Email already registered.' });
            try {
                const passwordHash = await bcrypt.hash(password, 10);
                db.run('INSERT INTO users (firstName, lastName, email, passwordHash, role) VALUES (?, ?, ?, ?, ?)', [firstName, lastName, email, passwordHash, 'user'], function (err) {
                    if (err) return res.status(500).json({ error: 'Failed to create user.' });
                    const otp = generateOtp();
                    const tempToken = generateTempToken(email);
                    otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000, tempToken, user: { id: this.lastID, firstName, lastName, email }, passwordHash, };
                    sendOtpEmail(email, otp).then(() => res.json({ otpRequired: true, tempToken })).catch(() => res.status(500).json({ error: 'Failed to send OTP email.' }));
                });
            } catch (e) {
                res.status(500).json({ error: 'Server error.' });
            }
        });
    });

    app.post('/api/login', (req, res) => {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
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
        if (Date.now() > entry.expires) { delete otpStore[email]; return res.status(400).json({ error: 'OTP expired.' }); }
        if (entry.otp !== otp) return res.status(400).json({ error: 'Invalid OTP.' });
        const { user } = entry;
        db.get('SELECT id, firstName, lastName, email, role FROM users WHERE id = ?', [user.id], (err, dbUser) => {
            if (err || !dbUser) { delete otpStore[email]; return res.status(500).json({ error: 'User not found after OTP.' }); }
            const token = jwt.sign({ id: dbUser.id, email: dbUser.email, role: dbUser.role }, JWT_SECRET, { expiresIn: '7d' });
            delete otpStore[email];
            res.json({ token, user: dbUser });
        });
    });

    app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
    app.get('/auth/google/callback', passport.authenticate('google', {
        failureRedirect: `${FRONTEND_URL}/login`
    }), (req, res) => {
        const user = req.user;
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
        const redirectUrl = `${FRONTEND_URL}/login?token=${encodeURIComponent(token)}&user=${encodeURIComponent(JSON.stringify(user))}`;
        res.redirect(redirectUrl);
    });

    app.get('/api/profile', authenticateToken, (req, res) => {
        db.get('SELECT id, firstName, lastName, email, role FROM users WHERE id = ?', [req.user.id], (err, user) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (!user) return res.status(404).json({ error: 'User not found' });
            res.json(user);
        });
    });

    app.post('/api/profile', authenticateToken, async (req, res) => {
        const { firstName, lastName, email, password } = req.body;
        if (!firstName && !lastName && !email && !password) return res.status(400).json({ error: 'No fields to update' });
        db.get('SELECT * FROM users WHERE id = ?', [req.user.id], async (err, user) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (!user) return res.status(404).json({ error: 'User not found' });
            let passwordHash = user.passwordHash;
            if (password) passwordHash = await bcrypt.hash(password, 10);
            db.run('UPDATE users SET firstName = ?, lastName = ?, email = ?, passwordHash = ? WHERE id = ?', [firstName || user.firstName, lastName || user.lastName, email || user.email, passwordHash, req.user.id], function (err) {
                if (err) return res.status(500).json({ error: 'Failed to update profile' });
                res.json({ success: true });
            });
        });
    });

    // ... (Your other API routes for cart, checkout, reviews, products, etc. remain here)

    // --- 6. START THE SERVER ---
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
        console.log(`AdminJS should be available at http://localhost:${PORT}/admin`);
    });
};

// --- This is the only command at the top level ---
startServer();
