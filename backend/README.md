# Perfume Backend

## Setup

1. Install dependencies:
   ```sh
   npm install
   ```
2. Start the server:
   ```sh
   npm run dev
   ```
   The server runs on port 4000 by default.

## API Endpoints

### POST /api/signup
- **Body:** `{ firstName, lastName, email, password, confirmPassword }`
- **Response:** `{ token, user }` or error

### POST /api/login
- **Body:** `{ email, password }`
- **Response:** `{ token, user }` or error

## Database
- Uses SQLite (`users.db` file in backend directory)
- User table: `id`, `firstName`, `lastName`, `email`, `passwordHash`

---

For development, use the provided scripts and ensure Node.js 18+ is installed. 