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

// AdminJS Imports
import AdminJS from 'adminjs';
import AdminJSExpress from '@adminjs/express';
import { Database, Resource } from '@adminjs/sql';

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

const startServer = async () => {
    try {
        AdminJS.registerAdapter({ Database, Resource });

        const db_admin = new Database('sqlite3', {
            connectionString: path.join(__dirname, 'users.db'),
        });

        const adminJs = new AdminJS({
            branding: { companyName: 'EYES Perfume', softwareBrothers: false },
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
                    if (matched) return user;
                }
                return false;
            },
            cookieName: 'admin-session',
            cookiePassword: 'a-very-secret-and-long-password-for-cookies-change-me',
        });
        
        app.use(session({
            secret: 'a-very-secret-and-long-password-for-sessions-change-me',
            resave: false,
            saveUninitialized: true,
        }));

        app.use(adminJs.options.rootPath, adminRouter);
        console.log('AdminJS setup complete.');

    } catch (error) {
        console.error("Failed to start AdminJS:", error);
    }

    // --- All Middleware and API Routes are Placed Here ---

    app.use(cors({
        origin: [ 'https://eyes-perfume.onrender.com' ],
        credentials: true
    }));
    app.use(express.json());

    // ... (Your table creation and all your API routes go here) ...
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, firstName TEXT NOT NULL, lastName TEXT NOT NULL, email TEXT NOT NULL UNIQUE, passwordHash TEXT NOT NULL, role TEXT DEFAULT 'user')`);
    // ... etc. for all tables

    app.get('/', (req, res) => res.send('Perfume backend running'));
    app.post('/api/signup', async (req, res) => { /*... your code ...*/ });
    // ... etc. for all your API routes

    // --- The server is started last, inside this function ---
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
        console.log(`AdminJS is available at http://localhost:${PORT}/admin`);
    });
};

// --- This is now the only command at the top level ---
startServer();
