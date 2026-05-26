const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

// Using direct parsing to ensure Render doesn't drop the domain suffix
const pool = new Pool({
    connectionString: "postgresql://main_db_ug3g_user:MOBiz2ykgNQytQPeLbYyIumLArJGeKj7@dpg-d8anre5ckfvc73ckd7r0-a.singapore-postgres.render.com/main_db_ug3g",
    ssl: { rejectUnauthorized: false }
});

async function initDb() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS chapters (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS system_sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        `);
    } catch (err) {
        console.error("Database initialization failed:", err);
    }
}

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function parseCookieSession(req, res, next) {
    req.session = {};
    const cookieHeader = req.headers.cookie || '';
    const match = cookieHeader.match(/session_token=([^;]+)/);
    
    if (!match) return next();
    
    const token = match[1];
    // FIXED: Changed '?' to '$1'
    pool.query("SELECT user_id, username FROM system_sessions WHERE token = $1 AND expires_at > NOW()", [token], (err, result) => {
        if (!err && result && result.rows.length > 0) {
            req.session.userId = result.rows[0].user_id;
            req.session.username = result.rows[0].username;
            req.session.token = token;
        }
        next();
    });
}

app.use(parseCookieSession);

function redirectIfAuth(req, res, next) {
    if (req.session.userId) {
        return res.redirect('/');
    }
    next();
}

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
}

app.get('/', requireAuth, (req, res) => {
    // FIXED: Changed '?' to '$1'
    pool.query("SELECT * FROM chapters WHERE user_id = $1 ORDER BY id ASC", [req.session.userId], (err, result) => {
        if (err) {
            return res.status(500).send("Database extraction error.");
        }
        
        res.render('index', { 
            pageTitle: "book-editor", 
            status: "ACTIVE",
            username: req.session.username,
            chapters: result ? result.rows : [] 
        });
    });
});

app.post('/', requireAuth, (req, res) => {
    const { title, content } = req.body;

    if (!title || !content || title.trim().length === 0 || content.trim().length === 0) {
        return res.status(400).send("Missing fields");
    }

    const sanitizedTitle = title.replace(/</g, "&lt;").replace(/>/g, "&gt;").trim();
    const sanitizedContent = content.replace(/</g, "&lt;").replace(/>/g, "&gt;").trim();

    // FIXED: Changed '?' to '$1, $2, $3'
    const sql = "INSERT INTO chapters (title, content, user_id) VALUES ($1, $2, $3)";
    const params = [sanitizedTitle, sanitizedContent, req.session.userId];

    pool.query(sql, params, (err) => {
        if (err) {
            return res.status(500).send("Database insertion error.");
        }
        res.redirect('/');
    });
});

app.get('/login', redirectIfAuth, (req, res) => {
    res.render('login', { pageTitle: "Login", error: null });
});

app.post('/login', redirectIfAuth, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send("Missing credentials");

    const hashedPassword = hashPassword(password);

    // FIXED: Changed '?' to '$1'
    pool.query("SELECT * FROM users WHERE username = $1", [username.trim()], (err, result) => {
        if (err || !result || result.rows.length === 0 || result.rows[0].password_hash !== hashedPassword) {
            return res.render('login', { pageTitle: "Login", error: "Invalid username or password." });
        }

        const user = result.rows[0];
        const token = crypto.randomBytes(32).toString('hex');
        
        // FIXED: Changed '?' to '$1, $2, $3'
        pool.query("INSERT INTO system_sessions (token, user_id, username, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour')", 
            [token, user.id, user.username], (sessionErr) => {
                if (sessionErr) return res.status(500).send("Session creation error.");
                res.setHeader('Set-Cookie', `session_token=${token}; Path=/; HttpOnly; Max-Age=3600`);
                res.redirect('/');
            }
        );
    });
});

app.get('/signup', redirectIfAuth, (req, res) => {
    res.render('signup', { pageTitle: "Sign Up", error: null });
});

app.post('/signup', redirectIfAuth, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || username.trim().length === 0 || password.length < 6) {
        return res.render('signup', { pageTitle: "Sign Up", error: "Invalid username or password (min. 6 characters)" });
    }

    const hashedPassword = hashPassword(password);

    // FIXED: Changed '?' to '$1, $2'
    pool.query("INSERT INTO users (username, password_hash) VALUES ($1, $2)", [username.trim(), hashedPassword], (err) => {
        if (err) {
            return res.render('signup', { pageTitle: "Sign Up", error: "Username already taken" });
        }
        res.redirect('/login');
    });
});

app.get('/logout', (req, res) => {
    if (req.session.token) {
        // FIXED: Changed '?' to '$1'
        pool.query("DELETE FROM system_sessions WHERE token = $1", [req.session.token], () => {
            res.setHeader('Set-Cookie', 'session_token=; Path=/; HttpOnly; Max-Age=0');
            res.redirect('/login');
        });
    } else {
        res.redirect('/login');
    }
});

app.listen(PORT, async () => {
    console.log(`[SYSTEM] Web service container initialized on port ${PORT}.`);
    await initDb();
    console.log(`[ONLINE] Postgres Architecture active and verified.`);
});
