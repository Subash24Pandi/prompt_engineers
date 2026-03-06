

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
    res.render('home', { showAdminLogin: true });
});

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
    // Always pass engineers as empty array for engineer view
    res.render('dashboard', { agents: agents.rows, engineers: [], admin: false });
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
             last_edit_date = NOW(),
             last_edit_by = $4
         WHERE id = $3`,
        [content, reason, promptId, 'engineer']
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
app.post('/admin/delete-prompt', async (req, res) => {
    const { agentId } = req.body;
    // Find latest prompt for agent
    const promptResult = await pool.query(
        'SELECT id FROM prompts WHERE agent_id = $1 ORDER BY last_edit_date DESC NULLS LAST LIMIT 1',
        [agentId]
    );
    if (promptResult.rows.length === 0) return res.status(404).send('Prompt not found');
    const promptId = promptResult.rows[0].id;
    await pool.query('DELETE FROM prompts WHERE id = $1', [promptId]);
    res.redirect('/admin');
});

// ================= ADMIN VIEW PROMPT =================
app.get('/admin/view-prompt/:agentId', async (req, res) => {
    const agentResult = await pool.query('SELECT * FROM agents WHERE id = $1', [req.params.agentId]);
    if (agentResult.rows.length === 0) return res.status(404).send('Agent not found');
    const agent = agentResult.rows[0];
    const promptResult = await pool.query(
        'SELECT * FROM prompts WHERE agent_id = $1 ORDER BY last_edit_date DESC NULLS LAST LIMIT 1',
        [req.params.agentId]
    );
    const prompt = promptResult.rows[0] || null;
    res.render('view-prompt', { agent, prompt });
});

// ================= ADMIN API: GET AGENT PROMPT =================
app.get('/api/agent/:agentId/prompt', async (req, res) => {
    // Get latest prompt for agent
    const result = await pool.query(
        'SELECT content FROM prompts WHERE agent_id = $1 ORDER BY last_edit_date DESC NULLS LAST LIMIT 1',
        [req.params.agentId]
    );
    res.json({ content: result.rows[0]?.content || '' });
});

// ================= ADMIN EDIT PROMPT =================
app.post('/admin/edit-prompt', async (req, res) => {
    const { agentId, engineerId, content, reason } = req.body;
    // Find latest prompt for agent
    const promptResult = await pool.query(
        'SELECT id FROM prompts WHERE agent_id = $1 ORDER BY last_edit_date DESC NULLS LAST LIMIT 1',
        [agentId]
    );
    if (promptResult.rows.length === 0) return res.status(404).send('Prompt not found');
    const promptId = promptResult.rows[0].id;
    await pool.query(
        `UPDATE prompts SET content = $1, last_edit_reason = $2, last_edit_date = NOW() WHERE id = $3`,
        [content, reason, promptId]
    );
    res.redirect('/admin');
});

// ================= ADMIN PAGE =================
app.get('/admin', isAuth, async (req, res) => {
    // Only allow founder@theaitel.com
    const userResult = await pool.query('SELECT * FROM engineers WHERE id = $1', [req.session.userId]);
    if (userResult.rows.length === 0 || userResult.rows[0].id_number !== 'founder@theaitel.com') {
        return res.status(403).send('Admin access only');
    }
    // Get all engineers
    const engineers = await pool.query('SELECT * FROM engineers ORDER BY id DESC');
    // Get all agents
    const agents = await pool.query('SELECT * FROM agents');
    // Group agents by engineer
    const engineerMap = {};
    engineers.rows.forEach(e => engineerMap[e.id] = { ...e, agents: [] });
    agents.rows.forEach(a => {
        if (engineerMap[a.engineer_id]) engineerMap[a.engineer_id].agents.push(a);
    });
    const engineerList = Object.values(engineerMap);
    res.render('dashboard', { engineers: engineerList, admin: true });
});
// ...existing code...

// ================= ADMIN LOGIN =================
app.get('/admin-login', (req, res) => {
    res.render('admin-login');
});

app.post('/admin-login', async (req, res) => {
    const { username, password } = req.body;
    // username is email (id_number)
    const result = await pool.query('SELECT * FROM engineers WHERE id_number = $1 AND name = $2', [username, 'Admin']);
    if (result.rows.length === 0) return res.send('Unauthorized');
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.send('Unauthorized');
    req.session.userId = user.id;
    req.session.isAdmin = true;
    res.redirect('/admin-dashboard');
});

// ================= ADMIN DASHBOARD =================
app.get('/admin-dashboard', async (req, res) => {
    // Only allow admin session
    if (!req.session.isAdmin) return res.redirect('/admin-login');
    const engineers = await pool.query('SELECT * FROM engineers ORDER BY id DESC');
    res.render('admin-dashboard', { engineers: engineers.rows });
});

// ================= ADMIN ENGINEER AGENTS =================
app.get('/admin-dashboard/engineer/:id', async (req, res) => {
    if (!req.session.isAdmin) return res.redirect('/admin-login');
    const engineerResult = await pool.query('SELECT * FROM engineers WHERE id = $1', [req.params.id]);
    if (engineerResult.rows.length === 0) return res.status(404).send('Engineer not found');
    const agentsResult = await pool.query('SELECT * FROM agents WHERE engineer_id = $1 ORDER BY id DESC', [req.params.id]);
    res.render('admin-engineer-agents', { engineer: engineerResult.rows[0], agents: agentsResult.rows });
});

// ================= ADMIN AGENT PROMPTS =================
app.get('/admin-dashboard/engineer/:engineerId/agent/:agentId', async (req, res) => {
    if (!req.session.isAdmin) return res.redirect('/admin-login');
    const engineerResult = await pool.query('SELECT * FROM engineers WHERE id = $1', [req.params.engineerId]);
    if (engineerResult.rows.length === 0) return res.status(404).send('Engineer not found');
    const agentResult = await pool.query('SELECT * FROM agents WHERE id = $1', [req.params.agentId]);
    if (agentResult.rows.length === 0) return res.status(404).send('Agent not found');
    const promptsResult = await pool.query('SELECT * FROM prompts WHERE agent_id = $1 ORDER BY last_edit_date DESC NULLS LAST', [req.params.agentId]);
    res.render('admin-agent-prompts', {
        engineer: engineerResult.rows[0],
        agent: agentResult.rows[0],
        prompts: promptsResult.rows
    });
});

// ================= ADMIN PROMPT VIEW =================
app.get('/admin-dashboard/engineer/:engineerId/agent/:agentId/prompt/:promptId/view', async (req, res) => {
    if (!req.session.isAdmin) return res.redirect('/admin-login');
    const engineerResult = await pool.query('SELECT * FROM engineers WHERE id = $1', [req.params.engineerId]);
    const agentResult = await pool.query('SELECT * FROM agents WHERE id = $1', [req.params.agentId]);
    const promptResult = await pool.query('SELECT * FROM prompts WHERE id = $1', [req.params.promptId]);
    if (promptResult.rows.length === 0) return res.status(404).send('Prompt not found');
    res.render('admin-prompt-view', {
        engineer: engineerResult.rows[0],
        agent: agentResult.rows[0],
        prompt: promptResult.rows[0]
    });
});

// ================= ADMIN PROMPT EDIT =================
app.get('/admin-dashboard/engineer/:engineerId/agent/:agentId/prompt/:promptId/edit', async (req, res) => {
    if (!req.session.isAdmin) return res.redirect('/admin-login');
    const engineerResult = await pool.query('SELECT * FROM engineers WHERE id = $1', [req.params.engineerId]);
    const agentResult = await pool.query('SELECT * FROM agents WHERE id = $1', [req.params.agentId]);
    const promptResult = await pool.query('SELECT * FROM prompts WHERE id = $1', [req.params.promptId]);
    if (promptResult.rows.length === 0) return res.status(404).send('Prompt not found');
    res.render('admin-prompt-edit', {
        engineer: engineerResult.rows[0],
        agent: agentResult.rows[0],
        prompt: promptResult.rows[0]
    });
});

app.post('/admin-dashboard/engineer/:engineerId/agent/:agentId/prompt/:promptId/edit', async (req, res) => {
    if (!req.session.isAdmin) return res.redirect('/admin-login');
    const { content, reason } = req.body;
    await pool.query(
        'UPDATE prompts SET content = $1, last_edit_reason = $2, last_edit_date = NOW(), last_edit_by = $3 WHERE id = $4',
        [content, reason, 'admin', req.params.promptId]
    );
    res.redirect(`/admin-dashboard/engineer/${req.params.engineerId}/agent/${req.params.agentId}`);
});

// ================= ADMIN PROMPT DELETE =================
app.post('/admin-dashboard/engineer/:engineerId/agent/:agentId/prompt/:promptId/delete', async (req, res) => {
    if (!req.session.isAdmin) return res.redirect('/admin-login');
    await pool.query('DELETE FROM prompts WHERE id = $1', [req.params.promptId]);
    res.redirect(`/admin-dashboard/engineer/${req.params.engineerId}/agent/${req.params.agentId}`);
});

// ================= CREATE ADMIN =================
app.get('/create-admin', (req, res) => {
    if (!req.session.isAdmin) return res.redirect('/admin-login');
    res.render('create-admin');
});

app.post('/create-admin', async (req, res) => {
    if (!req.session.isAdmin) return res.redirect('/admin-login');
    const { username, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
        "INSERT INTO engineers (id_number, name, password) VALUES ($1, $2, $3)",
        [username, 'Admin', hashed]
    );
    res.redirect('/admin-dashboard');
});
// ================= ADMIN DELETE ENGINEER =================
app.post('/admin-dashboard/engineer/:engineerId/delete', async (req, res) => {
    if (!req.session.isAdmin) return res.redirect('/admin-login');
    const engineerId = req.params.engineerId;
    // Delete all agents and prompts for this engineer
    await pool.query('DELETE FROM prompts WHERE agent_id IN (SELECT id FROM agents WHERE engineer_id = $1)', [engineerId]);
    await pool.query('DELETE FROM agents WHERE engineer_id = $1', [engineerId]);
    await pool.query('DELETE FROM engineers WHERE id = $1', [engineerId]);
    res.redirect('/admin-dashboard');
});

// ================= ADMIN DELETE AGENT =================
app.post('/admin-dashboard/engineer/:engineerId/agent/:agentId/delete', async (req, res) => {
    if (!req.session.isAdmin) return res.redirect('/admin-login');
    const { engineerId, agentId } = req.params;
    // Delete all prompts for this agent
    await pool.query('DELETE FROM prompts WHERE agent_id = $1', [agentId]);
    await pool.query('DELETE FROM agents WHERE id = $1', [agentId]);
    res.redirect(`/admin-dashboard/engineer/${engineerId}`);
});
// ...existing code...

// ...existing code...

// ...existing code...

// ...existing code...

// ================= ADMIN DELETE PROMPT =================
// ================= TEMP ADMIN LIST =================
// Place this after app and pool initialization
app.get('/admin-list', async (req, res) => {
    const admins = await pool.query("SELECT id, id_number, name FROM engineers WHERE name = 'Admin'");
    res.json(admins.rows);
});