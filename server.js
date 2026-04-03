require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const { Client } = require('ssh2');
const { generateKeyPairSync, createPrivateKey, createPublicKey } = require('node:crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"], credentials: true }
});

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3005;
const SECRET_KEY = process.env.SECRET_KEY || 'your-secure-secret-key';
const DEFAULT_KEY_NAME = process.env.DEFAULT_KEY_NAME || 'anaba-hexagon-key';

const requireAuth = (req, res, next) => {
  const userAgent = req.headers['user-agent'];
  const secretKey = req.headers['x-anaba-secret-key'];
  if (userAgent !== 'Anaba-Admin-App') return res.status(403).json({ success: false, error: 'Forbidden' });
  if (secretKey !== SECRET_KEY) return res.status(401).json({ success: false, error: 'Unauthorized' });
  next();
};

// Helper to construct OpenSSH Public Key string
function getOpenSSHFormat(publicKey, keyName) {
  const keyType = publicKey.asymmetricKeyType;
  if (keyType === 'ed25519') {
    const spkiBuffer = publicKey.export({ type: 'spki', format: 'der' });
    const rawPublicKey = spkiBuffer.subarray(spkiBuffer.length - 32);
    const name = Buffer.from("ssh-ed25519");
    const nameLen = Buffer.alloc(4); nameLen.writeUInt32BE(name.length);
    const keyLen = Buffer.alloc(4); keyLen.writeUInt32BE(rawPublicKey.length);
    const combined = Buffer.concat([nameLen, name, keyLen, rawPublicKey]);
    return `ssh-ed25519 ${combined.toString("base64")} ${keyName}`;
  }
  try {
    return publicKey.export({ type: 'openssh', format: 'string' }).toString().trim();
  } catch (e) {
    return publicKey.export({ type: 'spki', format: 'pem' }).toString().trim();
  }
}

// --- ADVANCED: Manual Ed25519 OpenSSH Private Key Construction ---
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

  // Actually, cipherName and kdfName need their lengths explicitly
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
  // Send initial status of all connected agents
  const statuses = {};
  connectedAgents.forEach((_, id) => { statuses[id] = 'online'; });
  socket.emit('initial-agent-statuses', statuses);
});

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
  
  // Notify admins
  adminIo.emit('agent-status-update', { serverId, status: 'online' });

  socket.on('disconnect', () => {
    console.log(`Agent disconnected for Server ID: ${serverId}`);
    if (connectedAgents.get(serverId) === socket) {
      connectedAgents.delete(serverId);
      // Notify admins
      adminIo.emit('agent-status-update', { serverId, status: 'offline' });
    }
  });

  socket.on('deploy-log', (data) => {
    // Broadcast logs to any monitoring admin if needed
    io.emit(`deploy-log-${serverId}`, data);
  });
});

// --- DEPLOYMENT API ---
app.post('/api/agent/deploy', requireAuth, (req, res) => {
  const { serverId, deployPath, buildScript, branch } = req.body;
  const agentSocket = connectedAgents.get(serverId.toString());

  if (!agentSocket) {
    return res.status(404).json({ success: false, error: 'Agent not connected for this server' });
  }

  agentSocket.emit('deploy-task', { deployPath, buildScript, branch }, (response) => {
    if (response?.success) {
      res.json({ success: true, message: 'Deployment task dispatched' });
    } else {
      res.status(500).json({ success: false, error: response?.error || 'Failed to dispatch task' });
    }
  });
});

server.listen(PORT, () => console.log(`VPS Helper running on port ${PORT}`));
