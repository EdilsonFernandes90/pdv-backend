const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({ limit: '1mb' }));

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;

if (!DATABASE_URL || !ADMIN_USER || !ADMIN_PASSWORD || !JWT_SECRET) {
  console.error('Faltam variáveis obrigatórias: DATABASE_URL, ADMIN_USER, ADMIN_PASSWORD e JWT_SECRET.');
  process.exit(1);
}
if (JWT_SECRET.length < 32) {
  console.error('JWT_SECRET precisa ter pelo menos 32 caracteres.');
  process.exit(1);
}

app.use(cors({
  origin(origin, callback) {
    // Permite chamadas sem Origin para testes/health checks; navegadores com Origin
    // só são aceitos se corresponderem ao endereço configurado.
    if (!origin || (FRONTEND_ORIGIN && origin === FRONTEND_ORIGIN)) return callback(null, true);
    return callback(new Error('Origem não autorizada pelo CORS'));
  },
  methods: ['GET', 'POST', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      price NUMERIC(12,2) NOT NULL CHECK (price > 0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS customers (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sales (
      id BIGSERIAL PRIMARY KEY,
      date TEXT NOT NULL,
      "customerName" TEXT NOT NULL,
      "paymentMethod" TEXT NOT NULL,
      "paymentStatus" TEXT NOT NULL CHECK ("paymentStatus" IN ('Pago', 'Pendente')),
      "paidAmount" NUMERIC(12,2) NOT NULL DEFAULT 0,
      "changeAmount" NUMERIC(12,2) NOT NULL DEFAULT 0,
      total NUMERIC(12,2) NOT NULL CHECK (total >= 0),
      items JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: 'connected' });
  } catch (err) {
    console.error('Health database error:', err.message);
    res.status(503).json({ ok: false, error: 'Banco de dados indisponível' });
  }
});

app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string' ||
      username !== ADMIN_USER || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
  }
  const token = jwt.sign({ sub: ADMIN_USER }, JWT_SECRET, { expiresIn: '8h' });
  return res.json({ token, expiresIn: 28800 });
});

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Faça login para continuar.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (_err) {
    return res.status(401).json({ error: 'Sessão expirada. Entre novamente.' });
  }
}
app.use('/api', (req, res, next) => {
  if (req.path === '/login' || req.path === '/health') return next();
  return requireAuth(req, res, next);
});

app.get('/api/products', async (_req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT id, name, price::float8 AS price FROM products ORDER BY name, id');
    res.json(rows);
  } catch (err) { next(err); }
});
app.post('/api/products', async (req, res, next) => {
  try {
    const name = String(req.body?.name || '').trim();
    const price = Number(req.body?.price);
    if (!name || !Number.isFinite(price) || price <= 0) return res.status(400).json({ error: 'Informe nome e preço maior que zero.' });
    const { rows } = await pool.query('INSERT INTO products(name, price) VALUES($1, $2) RETURNING id, name, price::float8 AS price', [name, price]);
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});
app.delete('/api/products/:id', async (req, res, next) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM products WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Produto não encontrado.' });
    res.status(204).end();
  } catch (err) { next(err); }
});

app.get('/api/customers', async (_req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT id, name, phone FROM customers ORDER BY name, id');
    res.json(rows);
  } catch (err) { next(err); }
});
app.post('/api/customers', async (req, res, next) => {
  try {
    const name = String(req.body?.name || '').trim();
    const phone = String(req.body?.phone || '').trim();
    if (!name) return res.status(400).json({ error: 'Informe o nome do cliente.' });
    const { rows } = await pool.query('INSERT INTO customers(name, phone) VALUES($1, $2) RETURNING id, name, phone', [name, phone || null]);
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

app.delete('/api/customers/:id', async (req, res, next) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM customers WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Cliente não encontrado.' });
    res.status(204).end();
  } catch (err) { next(err); }
});

app.get('/api/sales', async (_req, res, next) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, date, "customerName", "paymentMethod", "paymentStatus",
             "paidAmount"::float8 AS "paidAmount",
             "changeAmount"::float8 AS "changeAmount",
             total::float8 AS total, items
      FROM sales ORDER BY id DESC
    `);
    res.json(rows);
  } catch (err) { next(err); }
});
app.post('/api/sales', async (req, res, next) => {
  try {
    const s = req.body || {};
    const total = Number(s.total);
    const items = Array.isArray(s.items) ? s.items : null;
    if (!items || items.length === 0 || !Number.isFinite(total) || total < 0) return res.status(400).json({ error: 'Venda inválida: confira os itens e o total.' });
    if (!['Pago', 'Pendente'].includes(s.paymentStatus)) return res.status(400).json({ error: 'Status de pagamento inválido.' });
    const { rows } = await pool.query(`
      INSERT INTO sales(date, "customerName", "paymentMethod", "paymentStatus", "paidAmount", "changeAmount", total, items)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
      RETURNING id, date, "customerName", "paymentMethod", "paymentStatus",
                "paidAmount"::float8 AS "paidAmount", "changeAmount"::float8 AS "changeAmount",
                total::float8 AS total, items
    `, [
      String(s.date || new Date().toLocaleString('pt-BR')),
      String(s.customerName || 'Consumidor Final'),
      String(s.paymentMethod || 'Dinheiro'),
      s.paymentStatus,
      Number(s.paidAmount) || 0,
      Number(s.changeAmount) || 0,
      total,
      JSON.stringify(items)
    ]);
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});
app.patch('/api/sales/:id/status', async (req, res, next) => {
  try {
    const status = req.body?.paymentStatus;
    if (!['Pago', 'Pendente'].includes(status)) return res.status(400).json({ error: 'Status inválido.' });
    const { rows } = await pool.query(`
      UPDATE sales SET "paymentStatus" = $1 WHERE id = $2
      RETURNING id, date, "customerName", "paymentMethod", "paymentStatus",
                "paidAmount"::float8 AS "paidAmount", "changeAmount"::float8 AS "changeAmount",
                total::float8 AS total, items
    `, [status, req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Venda não encontrada.' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

app.use((err, _req, res, _next) => {
  console.error('API error:', err.message);
  if (err.message === 'Origem não autorizada pelo CORS') return res.status(403).json({ error: err.message });
  res.status(500).json({ error: 'Erro interno do servidor. Consulte os logs do Render.' });
});

initDb().then(() => {
  app.listen(PORT, '0.0.0.0', () => console.log(`PDV API ativa na porta ${PORT}`));
}).catch(err => {
  console.error('Não foi possível inicializar o banco PostgreSQL:', err.message);
  process.exit(1);
});
