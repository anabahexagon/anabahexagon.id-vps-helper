require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const { Client } = require('ssh2');
const { generateKeyPairSync, createPrivateKey, createPublicKey } = require('crypto');
const Database = require('better-sqlite3');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3005;
const SECRET_KEY = process.env.SECRET_KEY || 'your-secure-secret-key';
const DEFAULT_KEY_NAME = process.env.DEFAULT_KEY_NAME || 'anaba-hexagon-key';
const METRICS_RETENTION_DAYS = parseInt(process.env.METRICS_RETENTION_DAYS || '7');

// --- DATABASE INITIALIZATION ---
const db = new Database('vps_helper.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS metrics_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serverId TEXT NOT NULL,
    cpu REAL,
    ram_percent REAL,
    ram_used REAL,
    ram_total REAL,
    disk_percent REAL,
    disk_used REAL,
    disk_total REAL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_metrics_serverId_timestamp ON metrics_history(serverId, timestamp);
`);

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

const requireAuth = (req, res, next) => {
  const key = req.headers['x-anaba-secret-key'];
  if (key !== SECRET_KEY) return res.status(401).json({ success: false, error: 'Unauthorized' });
  next();
};

function getOpenSSHFormat(publicKey, keyName) {
  try {
    if (publicKey.asymmetricKeyType === 'ed25519') {
      // Manually construct Ed25519 SSH wire format
      const spkiBuffer = publicKey.export({ type: 'spki', format: 'der' });
      // Ed25519 SPKI ends with the 32-byte public key
      const pubBytes = spkiBuffer.subarray(spkiBuffer.length - 32);
      
      const name = Buffer.from("ssh-ed25519");
      const nameLen = Buffer.alloc(4); nameLen.writeUInt32BE(name.length);
      const keyLen = Buffer.alloc(4); keyLen.writeUInt32BE(pubBytes.length);
      
      const blob = Buffer.concat([nameLen, name, keyLen, pubBytes]);
      return `ssh-ed25519 ${blob.toString('base64')} ${keyName}`;
    }

    // Default to SPKI for other types, PKCS1 for RSA
    const type = publicKey.asymmetricKeyType === 'rsa' ? 'pkcs1' : 'spki';
    const exported = publicKey.export({ type, format: 'der' });
    const b64 = exported.toString('base64');
    const prefix = publicKey.asymmetricKeyType === 'rsa' ? 'ssh-rsa' : `ssh-${publicKey.asymmetricKeyType}`;
    return `${prefix} ${b64} ${keyName}`;
  } catch (error) {
    console.error("Error formatting public key:", error.message);
    // Fallback to basic SPKI export
    const exported = publicKey.export({ type: 'spki', format: 'der' });
    return `ssh-key ${exported.toString('base64')} ${keyName}`;
  }
}

// This builds the "authfile" format used by OpenSSH (-----BEGIN OPENSSH PRIVATE KEY-----)
function toOpenSSHPrivateKey(pk) {
  const spkiBuffer = createPublicKey(pk).export({ type: 'spki', format: 'der' });
  const pubBytes = spkiBuffer.subarray(spkiBuffer.length - 32);
  const privBytes = pk.export({ type: 'pkcs8', format: 'der' }).subarray(16, 48); // Standard Ed25519 seed offset in PKCS8

  const cipherName = "none";
  const kdfName = "none";
  const kdfOptions = Buffer.alloc(4); // empty
  const numKeys = 1;

  // 1. Write Public Key part
  const pubPartName = Buffer.from("ssh-ed25519");
  const pubPartNameLen = Buffer.alloc(4); pubPartNameLen.writeUInt32BE(pubPartName.length);
  const pubKeyLen = Buffer.alloc(4); pubKeyLen.writeUInt32BE(pubBytes.length);
  const pubKeyFull = Buffer.concat([pubPartNameLen, pubPartName, pubKeyLen, pubBytes]);
  const pubKeyFullLen = Buffer.alloc(4); pubKeyFullLen.writeUInt32BE(pubKeyFull.length);

  // 2. Write Private Key part (with padding)
  const checkInt = Buffer.alloc(4); // random check integers (using 0 for simplicity)
  const privPartName = Buffer.from("ssh-ed25519");
  const privPartNameLen = Buffer.alloc(4); privPartNameLen.writeUInt32BE(privPartName.length);
  const pubKeyLen2 = Buffer.alloc(4); pubKeyLen2.writeUInt32BE(pubBytes.length);
  const privKeyLen = Buffer.alloc(4); privKeyLen.writeUInt32BE(64); // Ed25519 priv is pub + priv concatenated (64 bytes)
  const privKeyFull = Buffer.concat([privBytes, pubBytes]);
  const comment = Buffer.from("");
  const commentLen = Buffer.alloc(4); commentLen.writeUInt32BE(comment.length);

  let kbound = Buffer.concat([
    checkInt, checkInt, 
    privPartNameLen, privPartName, 
    pubKeyLen2, pubBytes, 
    privKeyLen, privKeyFull, 
    commentLen, comment
  ]);

  // Padding to multiple of 8
  const padLen = (8 - (kbound.length % 8)) % 8;
  if (padLen > 0) {
    const pad = Buffer.alloc(padLen);
    for (let i = 0; i < padLen; i++) pad[i] = i + 1;
    kbound = Buffer.concat([kbound, pad]);
  }
  const kboundLen = Buffer.alloc(4); kboundLen.writeUInt32BE(kbound.length);

  // 3. Combine everything
  const magic = Buffer.from("openssh-key-v1\0");
  const header = Buffer.concat([
    magic,
    Buffer.alloc(4), // cipherName length (0 for none)
    Buffer.alloc(4), // kdfName length (0 for none)
    Buffer.alloc(4), // kdfOptions length (0)
    Buffer.alloc(4, 1), // numKeys (1)
    pubKeyFullLen, pubKeyFull,
    kboundLen, kbound
  ]);

  const cName = Buffer.from("none"); const cNameL = Buffer.alloc(4); cNameL.writeUInt32BE(cName.length);
  const kName = Buffer.from("none"); const kNameL = Buffer.alloc(4); kNameL.writeUInt32BE(kName.length);
  const finalHeader = Buffer.concat([
    magic,
    cNameL, cName,
    kNameL, kName,
    Buffer.alloc(4), // kdfOptions length (0)
    Buffer.alloc(4), // numKeys (set to 1 below)
  ]);
  finalHeader.writeUInt32BE(1, finalHeader.length - 4);

  const finalCombined = Buffer.concat([finalHeader, pubKeyFullLen, pubKeyFull, kboundLen, kbound]);

  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${finalCombined.toString("base64").match(/.{1,70}/g).join("\n")}\n-----END OPENSSH PRIVATE KEY-----`;
}

function prepareKeyForSsh2(privateKeyStr, passphrase) {
  const pk = createPrivateKey({
    key: privateKeyStr.trim().replace(/\\n/g, '\n'),
    ...(passphrase ? { passphrase } : {})
  });

  if (pk.asymmetricKeyType === 'ed25519') {
    try {
      return pk.export({ type: 'openssh', format: 'pem' });
    } catch (e) {
      console.log("Using Manual OpenSSH Construction for Ed25519...");
      return toOpenSSHPrivateKey(pk);
    }
  }
  return pk.export({ type: 'pkcs1', format: 'pem' });
}

app.post('/generate', requireAuth, (req, res) => {
  try {
    const { type = 'ed25519', passphrase, keyName = DEFAULT_KEY_NAME } = req.body;
    const { privateKey, publicKey } = generateKeyPairSync(type.toLowerCase(), { ...(type === 'rsa' ? { modulusLength: 4096 } : {}) });
    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem', ...(passphrase ? { cipher: 'aes-256-cbc', passphrase } : {}) });
    res.json({ success: true, result: { privateKey: privPem.toString(), publicKeySSH: getOpenSSHFormat(publicKey, keyName) } });
  } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/derive', requireAuth, (req, res) => {
  try {
    const { privateKey: privateKeyStr, passphrase, keyName = DEFAULT_KEY_NAME } = req.body;
    const nodeKey = createPrivateKey({ key: privateKeyStr.trim(), ...(passphrase ? { passphrase } : {}) });
    res.json({ success: true, result: { publicKeySSH: getOpenSSHFormat(createPublicKey(nodeKey), keyName) } });
  } catch (error) { res.status(400).json({ success: false, error: error.message }); }
});

io.on('connection', (socket) => {
  const ssh = new Client();
  socket.on('ssh-connect', (data) => {
    const { host, port = 22, username, privateKey, passphrase, secretKey } = data;
    if (secretKey !== SECRET_KEY) return socket.disconnect();
    ssh.on('ready', () => {
      socket.emit('ssh-data', '\r\n\x1b[32mSSH Connection Established!\x1b[0m\r\n');
      ssh.shell({ term: 'xterm-256color' }, (err, stream) => {
        if (err) return socket.emit('ssh-data', '\r\n\x1b[31mError: ' + err.message + '\x1b[0m\r\n');
        socket.on('ssh-input', (input) => stream.write(input));
        socket.on('ssh-resize', (cols, rows) => stream.setWindow(rows, cols));
        stream.on('data', (d) => socket.emit('ssh-data', d.toString())).on('close', () => { socket.emit('ssh-data', '\r\n\x1b[31mStream Closed\x1b[0m\r\n'); ssh.end(); });
      });
    }).on('error', (err) => { socket.emit('ssh-data', '\r\n\x1b[31mSSH Error: ' + err.message + '\x1b[0m\r\n'); })
      .on('close', () => { socket.emit('ssh-data', '\r\n\x1b[31mSSH Connection Closed\x1b[0m\r\n'); });
    try {
      const finalKey = prepareKeyForSsh2(privateKey, passphrase);
      ssh.connect({ host, port, username, privateKey: finalKey });
    } catch (err) { socket.emit('ssh-data', '\r\n\x1b[31mInternal Error: ' + err.message + '\x1b[0m\r\n'); }
  });
  socket.on('disconnect', () => ssh.end());
});

// --- AGENT REGISTRY ---
const connectedAgents = new Map(); // vps_server_id -> socket

// --- ADMIN NAMESPACE ---
const adminIo = io.of('/admin');
adminIo.on('connection', (socket) => {
  const statuses = {};
  connectedAgents.forEach((_, id) => { statuses[id] = 'online'; });
  socket.emit('initial-agent-statuses', statuses);
});

// --- AGENT NAMESPACE ---
const agentIo = io.of('/agent');
agentIo.use((socket, next) => {
  const { token, serverId } = socket.handshake.auth;
  if (!token || !serverId) return next(new Error('Authentication failed: Missing token or serverId'));
  socket.serverId = serverId.toString();
  next();
});

agentIo.on('connection', (socket) => {
  const serverId = socket.serverId;
  console.log(`Agent connected for Server ID: ${serverId}`);
  connectedAgents.set(serverId, socket);
  
  adminIo.emit('agent-status-update', { serverId, status: 'online' });

  socket.on('disconnect', () => {
    console.log(`Agent disconnected for Server ID: ${serverId}`);
    if (connectedAgents.get(serverId) === socket) {
      connectedAgents.delete(serverId);
      adminIo.emit('agent-status-update', { serverId, status: 'offline' });
    }
  });

  socket.on('deploy-log', (data) => {
    adminIo.emit(`deploy-log-${serverId}`, data);
  });

  socket.on('agent-metrics', (data) => {
    // 1. Broadcast to admin
    adminIo.emit(`agent-metrics-${serverId}`, data);

    // 2. Save to SQLite with explicit ISO timestamp (UTC)
    try {
      const timestamp = new Date().toISOString();
      const stmt = db.prepare(`
        INSERT INTO metrics_history 
        (serverId, cpu, ram_percent, ram_used, ram_total, disk_percent, disk_used, disk_total, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        serverId, 
        data.cpu, 
        data.ram.percent, 
        data.ram.used, 
        data.ram.total, 
        data.disk?.percent || null, 
        data.disk?.used || null, 
        data.disk?.total || null,
        timestamp
      );
    } catch (err) {
      console.error("Failed to save metrics to DB:", err.message);
    }
  });

  socket.on('deploy-result', (data) => {
    const { deploymentId, status, logs } = data;
    if (deploymentId) {
      reportDeploymentStatus(deploymentId, status, logs);
    }
  });
});

// --- METRICS API ---
app.get('/api/agent/:serverId/metrics-history', requireAuth, (req, res) => {
  const { serverId } = req.params;
  const { range = '1h', since, until } = req.query;
  
  try {
    let query = `SELECT * FROM metrics_history WHERE serverId = ?`;
    const params = [serverId];

    if (since && until) {
      // Custom Range
      query += ` AND timestamp BETWEEN ? AND ?`;
      params.push(since, until);
    } else {
      // Predefined Ranges
      const rangeMap = {
        '1h': "-1 hour",
        '3h': "-3 hours",
        '6h': "-6 hours",
        '12h': "-12 hours",
        '24h': "-24 hours",
        '1d': "-1 day",
        '7d': "-7 days"
      };
      const sqlRange = rangeMap[range] || "-1 hour";
      query += ` AND timestamp >= datetime('now', ?)`;
      params.push(sqlRange);
    }

    // Downsampling logic: If range > 6h, take average per minute or more to keep chart light
    // For now, let's just use LIMIT to keep it simple but functional
    query += ` ORDER BY timestamp DESC LIMIT 200`;
    
    const rows = db.prepare(query).all(...params);
    res.json({ success: true, result: rows.reverse() });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- DEPLOYMENT API ---
app.post('/api/agent/deploy', requireAuth, (req, res) => {
  const { serverId, deployPath, buildScript, branch, deploymentId, repoUrl } = req.body;
  const agentSocket = connectedAgents.get(serverId.toString());

  if (!agentSocket) {
    return res.status(404).json({ success: false, error: 'Agent not connected for this server' });
  }

  agentSocket.emit('deploy-task', { deployPath, buildScript, branch, deploymentId, repoUrl }, (response) => {
    if (response?.success) {
      res.json({ success: true, message: 'Deployment task dispatched' });
    } else {
      if (deploymentId) {
        reportDeploymentStatus(deploymentId, 'failed', response?.error || 'Failed to dispatch task');
      }
      res.status(500).json({ success: false, error: response?.error || 'Failed to dispatch task' });
    }
  });
});

async function reportDeploymentStatus(deploymentId, status, logs) {
  try {
    const apiUrl = process.env.API_URL || 'http://localhost:8787';
    await fetch(`${apiUrl}/api/cicd-deployments/${deploymentId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, output_log: logs })
    });
    console.log(`Reported deployment ${deploymentId} as ${status}`);
  } catch (err) {
    console.error(`Failed to report deployment ${deploymentId} status:`, err.message);
  }
}

// --- AUTO CLEANUP TASK ---
setInterval(() => {
  console.log(`Running metrics cleanup (Retention: ${METRICS_RETENTION_DAYS} days)...`);
  try {
    const stmt = db.prepare("DELETE FROM metrics_history WHERE timestamp < datetime('now', ?)");
    const result = stmt.run(`-${METRICS_RETENTION_DAYS} days`);
    console.log(`Cleaned up ${result.changes} old metric records.`);
  } catch (err) {
    console.error("Cleanup failed:", err.message);
  }
}, 3600000); // Run every hour

server.listen(PORT, () => console.log(`VPS Helper running on port ${PORT}`));
