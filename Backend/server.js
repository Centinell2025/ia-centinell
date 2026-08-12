require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

// --- Inicialización ---
const app = express();
const PORT = process.env.PORT || 3000;

// --- Middleware ---
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// --- Simulación de BD en memoria ---
const db = {
  users: [],
  clients: [],
  quarantine: [],
  baseline: [],
  hitl: [],
  logs: [],
  threatSignatures: [
    { hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', name: 'EICAR Test File' },
    { hash: 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592', name: 'Ransomware.WannaCry' }
  ]
};

// --- Utilidades ---
function generateToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
}

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Middleware de subida de archivos ---
const storage = multer.memoryStorage();
const upload = multer({ storage: storage, limits: { fileSize: 10 * 1024 * 1024 } });

// --- Rutas de autenticación ---
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name, company } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const existing = db.users.find(u => u.email === email);
  if (existing) return res.status(409).json({ error: 'User already exists' });
  const hashed = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), email, password: hashed, name, company, role: 'user', created: new Date() };
  db.users.push(user);
  const token = generateToken(user);
  res.status(201).json({ token, user: { id: user.id, email, name, company, role: user.role } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const token = generateToken(user);
  res.json({ token, user: { id: user.id, email: user.email, name: user.name, company: user.company, role: user.role } });
});

app.post('/api/auth/logout', verifyToken, (req, res) => {
  res.json({ message: 'Logged out' });
});

// --- Ruta de estado de protección ---
app.get('/api/protection/status', verifyToken, (req, res) => {
  const score = Math.floor(Math.random() * 30) + 70;
  res.json({
    score,
    status: score > 80 ? 'PROTECTED' : score > 60 ? 'WARNING' : 'DANGER',
    engines: {
      threatShield: 'ACTIVE',
      netSentinel: 'ACTIVE',
      fileGuardian: 'ACTIVE',
      hitlGovernor: 'ACTIVE'
    }
  });
});

// --- THREAT SHIELD ---
app.post('/api/shield/scan', verifyToken, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const file = req.file;
  // Simular cálculo SHA-256 (en realidad se haría con crypto)
  const hash = require('crypto').createHash('sha256').update(file.buffer).digest('hex');
  const signature = db.threatSignatures.find(s => s.hash === hash);
  const isMalicious = !!signature;
  const result = {
    fileName: file.originalname,
    size: file.size,
    hash,
    isMalicious,
    signature: signature ? signature.name : null,
    verdict: isMalicious ? 'THREAT_DETECTED' : 'CLEAN',
    timestamp: new Date()
  };
  // Si es malicioso, añadir a cuarentena
  if (isMalicious) {
    db.quarantine.push({
      id: uuidv4(),
      name: file.originalname,
      type: signature.name || 'Malware',
      risk: 'HIGH',
      ts: new Date(),
      status: 'QUARANTINED',
      auto: true
    });
  }
  res.json(result);
});

app.post('/api/shield/behavior', verifyToken, async (req, res) => {
  const { description, type } = req.body;
  // Simular análisis IA
  const analysis = `Behavioral analysis for ${type || 'malware'}:\n- Suspicious process chain detected.\n- MITRE T1055, T1071 observed.\n- Risk Score: 78/100.`;
  res.json({ analysis });
});

// --- NET SENTINEL ---
app.get('/api/net/connections', verifyToken, (req, res) => {
  const connections = [
    { ip: '192.168.1.1', port: 443, proto: 'HTTPS', status: 'ALLOWED', bytes: '1.2MB' },
    { ip: '203.0.113.42', port: 4444, proto: 'TCP', status: 'BLOCKED', bytes: '450MB' }
  ];
  res.json({ connections });
});

app.post('/api/net/anomaly', verifyToken, (req, res) => {
  const { description } = req.body;
  res.json({ analysis: 'Anomaly detected: potential port scanning activity. Recommend blocking IP 203.0.113.42.' });
});

// --- FILE GUARDIAN ---
app.post('/api/guardian/baseline', verifyToken, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const hash = require('crypto').createHash('sha256').update(req.file.buffer).digest('hex');
  db.baseline.push({ name: req.file.originalname, hash, size: req.file.size, added: new Date() });
  res.json({ message: 'File added to baseline', hash });
});

app.get('/api/guardian/verify', verifyToken, (req, res) => {
  // Simular verificación
  const verified = db.baseline.map(f => ({ ...f, status: 'OK' }));
  res.json({ baseline: verified });
});

// --- QUARANTINE ---
app.get('/api/quarantine/list', verifyToken, (req, res) => {
  res.json({ items: db.quarantine });
});

app.post('/api/quarantine/add', verifyToken, (req, res) => {
  const { name, type, risk } = req.body;
  const item = { id: uuidv4(), name, type, risk, ts: new Date(), status: 'QUARANTINED', auto: false };
  db.quarantine.push(item);
  res.status(201).json(item);
});

app.put('/api/quarantine/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const item = db.quarantine.find(q => q.id === id);
  if (!item) return res.status(404).json({ error: 'Not found' });
  item.status = status;
  res.json(item);
});

// --- IA-CORE-1-1 AUDIT ---
app.post('/api/ia-core/audit', verifyToken, async (req, res) => {
  const { payload, key } = req.body;
  const ts = new Date().toISOString();
  const data = `${payload}|${ts}|${key}`;
  const hash = require('crypto').createHash('sha256').update(data).digest('hex');
  res.json({ timestamp: ts, payload: data, hash });
});

// --- IA-CORE-1-2 FORENSIC ---
app.post('/api/ia-core/forensic', verifyToken, (req, res) => {
  const { description, mode } = req.body;
  res.json({ report: `Forensic analysis (${mode}):\n- Extracted IOCs: 5\n- Timeline reconstructed.\n- Chain of custody hash: ${uuidv4()}` });
});

// --- IA-CORE-1-3 ETHICS ---
app.post('/api/ia-core/ethics', verifyToken, (req, res) => {
  const { input, framework, risk } = req.body;
  res.json({ ethicsScore: 85, verdict: 'APPROVED', violations: [], biasDetected: false });
});

// --- IA-CORE-1-4 THREAT ---
app.post('/api/ia-core/threat', verifyToken, (req, res) => {
  const { indicators, mode } = req.body;
  res.json({ threatScore: 72, iocs: ['203.0.113.42', 'malicious-c2.net'], ttps: ['T1055', 'T1071'], attribution: 'APT-29' });
});

// --- AI ANALYST ---
app.post('/api/analyst/query', verifyToken, async (req, res) => {
  const { query, mode, language } = req.body;
  // Aquí se integraría la llamada a Claude/Gemini
  // Simulación:
  const response = `[${mode}] Response to: "${query}"\n- Threat analysis: moderate risk\n- Recommended action: monitor and update firewall rules.`;
  res.json({ response });
});

// --- ALGO LAB ---
app.post('/api/algo/solve', verifyToken, (req, res) => {
  const { problem, domain, language, depth } = req.body;
  res.json({ solution: `Solution for ${domain} problem:\n\nfunction solve() {\n  // optimized algorithm\n  return result;\n}\n\nComplexity: O(n log n)`, complexity: 'O(n log n)' });
});

// --- CLIENTS (Admin) ---
app.get('/api/clients', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  res.json(db.clients);
});

app.post('/api/clients', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { name, type, role } = req.body;
  const client = { id: uuidv4(), name, type, role, status: 'ACTIVE', since: new Date().toISOString().slice(0,10), ops: 0 };
  db.clients.push(client);
  res.status(201).json(client);
});

// --- INFRASTRUCTURE ---
app.get('/api/infra/nodes', verifyToken, (req, res) => {
  const nodes = [
    { id: 'NODE-01', region: 'USA-EAST', status: 'ONLINE', cpu: '67%', latency: '12ms' },
    { id: 'NODE-02', region: 'EU-CENTRAL', status: 'ONLINE', cpu: '54%', latency: '28ms' },
    { id: 'NODE-03', region: 'APAC', status: 'WARNING', cpu: '89%', latency: '67ms' },
    { id: 'NODE-04', region: 'LATAM', status: 'ONLINE', cpu: '42%', latency: '41ms' }
  ];
  res.json({ nodes });
});

// --- Ruta principal para servir el frontend ---
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- Iniciar servidor ---
app.listen(PORT, () => {
  console.log(`🚀 IA CENTINELL Server running on http://localhost:${PORT}`);
  console.log(`📡 API ready for frontend integration.`);
});
