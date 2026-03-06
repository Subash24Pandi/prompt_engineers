require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 5000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// IMPORTANT for Render
app.set('trust proxy', 1);

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'dev-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Render handles HTTPS
}));

// ================= AUTH CHECK =================

const isAuth = (req, res, next) => {
    if (!req.session.userId) return res.redirect('/login');
    next();
};

// ================= ROOT =================

app.get('/', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.redirect('/login');
});

    // Render the home page with admin and prompt engineer login options
    res.render('home', { showAdminLogin: true });

app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));

// ================= REGISTER =================

app.post('/register', async (req, res) => {
    try {
        const { id_number, name, password } = req.body;
        const hashed = await bcrypt.hash(password, 10);

        await pool.query(
            "INSERT INTO engineers (id_number, name, password) VALUES ($1,$2,$3)",
            [id_number, name, hashed]
        );

        res.redirect('/login');
    } catch (err) {
        console.error(err);
        res.status(500).send("Registration Error");
    }
});

// ================= LOGIN =================

app.post('/login', async (req, res) => {
    try {
        const { id_number, password } = req.body;

        const result = await pool.query(
            'SELECT * FROM engineers WHERE id_number = $1',
            [id_number]
        );

        if (result.rows.length === 0) return res.send('Unauthorized');

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password);

        if (!match) return res.send('Unauthorized');

        req.session.userId = user.id;
        res.redirect('/dashboard');

    } catch (err) {
        console.error(err);
        res.status(500).send("Login Error");
    }
});

// ================= DASHBOARD =================

app.get('/dashboard', isAuth, async (req, res) => {
    const agents = await pool.query(
        'SELECT * FROM agents WHERE engineer_id = $1 ORDER BY id DESC',
        [req.session.userId]
    );

    res.render('dashboard', { agents: agents.rows });
});

app.post('/create-agent', isAuth, async (req, res) => {
    const { agent_name } = req.body;

    await pool.query(
        'INSERT INTO agents (engineer_id, agent_name) VALUES ($1, $2)',
        [req.session.userId, agent_name]
    );

    res.redirect('/dashboard');
});

app.post('/delete-agent', isAuth, async (req, res) => {
    const { agentId } = req.body;

    await pool.query(
        'DELETE FROM agents WHERE id = $1 AND engineer_id = $2',
        [agentId, req.session.userId]
    );

    res.redirect('/dashboard');
});

// ================= AGENT PAGE =================

app.get('/agent/:id', isAuth, async (req, res) => {

    const agentCheck = await pool.query(
        'SELECT * FROM agents WHERE id = $1 AND engineer_id = $2',
        [req.params.id, req.session.userId]
    );

    if (agentCheck.rows.length === 0)
        return res.status(403).send("Unauthorized");

    const prompts = await pool.query(
        'SELECT * FROM prompts WHERE agent_id = $1 ORDER BY last_edit_date DESC NULLS LAST',
        [req.params.id]
    );

    res.render('agent', {
        agentId: req.params.id,
        prompts: prompts.rows
    });
});

// ================= SAVE PROMPT =================

app.post('/save-prompt', isAuth, async (req, res) => {
    const { agentId, title, content } = req.body;

    const check = await pool.query(
        'SELECT * FROM agents WHERE id = $1 AND engineer_id = $2',
        [agentId, req.session.userId]
    );

    if (check.rows.length === 0)
        return res.status(403).send("Unauthorized");

    await pool.query(
        'INSERT INTO prompts (agent_id, title, content) VALUES ($1, $2, $3)',
        [agentId, title, content]
    );

    res.redirect(`/agent/${agentId}`);
});

// ================= UPDATE PROMPT =================

app.post('/update-prompt', isAuth, async (req, res) => {
    const { promptId, agentId, content, reason } = req.body;

    const check = await pool.query(
        `SELECT p.id FROM prompts p
         JOIN agents a ON p.agent_id = a.id
         WHERE p.id = $1 AND a.engineer_id = $2`,
        [promptId, req.session.userId]
    );

    if (check.rows.length === 0)
        return res.status(403).send("Unauthorized");

    await pool.query(
        `UPDATE prompts
         SET content = $1,
             last_edit_reason = $2,
             last_edit_date = NOW()
         WHERE id = $3`,
        [content, reason, promptId]
    );

    res.redirect(`/agent/${agentId}`);
});

// ================= DELETE PROMPT =================

app.post('/delete-prompt', isAuth, async (req, res) => {
    const { promptId } = req.body;

    const check = await pool.query(
        `SELECT p.agent_id FROM prompts p
         JOIN agents a ON p.agent_id = a.id
         WHERE p.id = $1 AND a.engineer_id = $2`,
        [promptId, req.session.userId]
    );

    if (check.rows.length === 0)
        return res.status(403).send("Unauthorized");

    const agentId = check.rows[0].agent_id;

    await pool.query(
        'DELETE FROM prompts WHERE id = $1',
        [promptId]
    );

    res.redirect(`/agent/${agentId}`);
});

// ================= START SERVER =================

app.listen(PORT, () => {
    console.log(`Server Running on port ${PORT}`);
});
// ================= LOGOUT =================

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.redirect('/dashboard');
        }
        res.clearCookie('connect.sid'); // important
        res.redirect('/');
    });
});
