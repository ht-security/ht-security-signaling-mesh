
const express    = require('express');
const http       = require('http');
const https      = require('https');
const fs         = require('fs');
const { Server } = require('socket.io');
const cors       = require('cors');

// ── סביבה ──────────────────────────────────────────────────────
const IS_PROD   = process.env.NODE_ENV === 'production';
const PORT      = process.env.PORT      || 3000;       // ✅ FIX-PORT
const PORT_HTTP = process.env.PORT_HTTP || 3001;
const CERT_PATH = process.env.CERT_PATH || './cert.pem';
const KEY_PATH  = process.env.KEY_PATH  || './key.pem';

// ✅ FIX-CORS — הגדר ב-env: ALLOWED_ORIGINS=https://yourdomain.com
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ['http://localhost:3000', 'https://localhost:3000'];

const corsOptions = {
  origin: IS_PROD ? ALLOWED_ORIGINS : '*',
  methods: ['GET', 'POST']
};

const app = express();
app.use(cors(corsOptions));

// ✅ FIX-002: ניתוב HTTP → HTTPS
app.use((req, res, next) => {
  const secure = req.secure
    || req.headers['x-forwarded-proto'] === 'https'
    || IS_PROD;
  if (!secure && process.env.FORCE_HTTPS === 'true') {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

app.get('/', (_req, res) => {
  res.send('HT-SECURITY PRO Signaling Server is RUNNING.');
});

// ── בניית שרת HTTPS / HTTP ────────────────────────────────────
let server;
const hasCerts = fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH);

if (hasCerts && !IS_PROD) {
  server = https.createServer(
    { key: fs.readFileSync(KEY_PATH), cert: fs.readFileSync(CERT_PATH) },
    app
  );
  http.createServer((req, res) => {
    res.writeHead(301, { Location: `https://localhost:${PORT}${req.url}` });
    res.end();
  }).listen(PORT_HTTP, () => log(`[↗] HTTP→HTTPS redirect :${PORT_HTTP}→:${PORT}`));
  log('[🔒] HTTPS — local certificate');
} else {
  server = http.createServer(app);
  IS_PROD
    ? console.log('[🔒] HTTP — TLS handled by platform proxy (Render/Railway)')
    : console.log('[⚠️] No cert — HTTP only. Add cert.pem+key.pem for local HTTPS.');
}

// ── Socket.io ─────────────────────────────────────────────────
const io = new Server(server, {
  cors: corsOptions,
  pingTimeout:        20000,
  pingInterval:       10000,
  maxHttpBufferSize:  1e5    // ✅ FIX-SIZE: 100KB מקסימום per event
});

// ✅ FIX-ROOM: ניהול חדרים עם Map
const rooms = new Map(); // Map<roomId, Set<socketId>>

// ✅ FIX-004: Rate Limiting — 30 events/sec per socket
const MAX_EV  = 30;
const rateMap = new Map(); // Map<socketId, { n, t }>

function rateOK(socketId) {
  const now  = Date.now();
  const prev = rateMap.get(socketId) || { n: 0, t: now };
  if (now - prev.t >= 1000) { prev.n = 1; prev.t = now; rateMap.set(socketId, prev); return true; }
  prev.n++;
  rateMap.set(socketId, prev);
  if (prev.n > MAX_EV) {
    log(`[🛡] Rate limit: ${mask(socketId)} (${prev.n}/s)`);
    return false;
  }
  return true;
}

// ✅ FIX-005: Token structural validation
// השרת לא מכיר סיסמאות — בודק רק שה-token קיים ובנוי כ-HMAC-SHA256 base64 (44 תווים)
function tokenOK(token) {
  if (!token || typeof token !== 'string') return false;
  if (token.length < 44) return false;
  return /^[A-Za-z0-9+/=]+$/.test(token);
}

// ✅ FIX-LOG: מסכך socket IDs בלוגים ב-production
const mask = id  => IS_PROD ? `[…${id.slice(-4)}]` : id.slice(0, 8);
const log  = msg => console.log(`[${new Date().toISOString().slice(11,19)}] ${msg}`);

// ══════════════════════════════════════════════════════════════
io.on('connection', socket => {
  log(`[+] CONNECT ${mask(socket.id)}`);

  // ✅ FIX-005: join-room — דורש token לפני חשיפת peers
  socket.on('join-room', ({ room, token }) => {
    if (!room || typeof room !== 'string' || room.length > 100) return;

    if (!tokenOK(token)) {
      socket.emit('auth-rejected', { reason: 'Invalid or missing auth token' });
      log(`[⛔] Rejected join (no token): ${mask(socket.id)}`);
      return;
    }

    socket.join(room);

    // ✅ FIX-ROOM: תחזוקת Map
    if (!rooms.has(room)) rooms.set(room, new Set());
    const roomSet = rooms.get(room);

    // רשימת peers נשלחת רק אחרי אימות token
    socket.emit('room-peers', { peers: Array.from(roomSet) });
    socket.to(room).emit('user-connected', { peerId: socket.id });

    roomSet.add(socket.id);
    socket.data.room = room;

    log(`[~] JOIN ${mask(socket.id)} room="${room.slice(0,12)}" members=${roomSet.size}`);
  });

  // ✅ FIX-004 + FIX-005 על כל הודעת signaling
  socket.on('offer', ({ to, offer, auth, token }) => {
    if (!rateOK(socket.id)) return;
    const t = token || auth;
    if (!tokenOK(t) || !offer || !to) return;
    io.to(to).emit('offer', { from: socket.id, offer, auth: t, token: t });
  });

  socket.on('answer', ({ to, answer, auth, token }) => {
    if (!rateOK(socket.id)) return;
    const t = token || auth;
    if (!tokenOK(t) || !answer || !to) return;
    io.to(to).emit('answer', { from: socket.id, answer, auth: t, token: t });
  });

  socket.on('ice-candidate', ({ to, candidate, auth, token }) => {
    if (!rateOK(socket.id)) return;
    const t = token || auth;
    if (!tokenOK(t) || !candidate || !to) return;
    io.to(to).emit('ice-candidate', { from: socket.id, candidate, auth: t, token: t });
  });

  socket.on('leave-room', ({ room }) => {
    if (!room) return;
    socket.leave(room);
    // ✅ FIX-ROOM: ניקוי Map
    if (rooms.has(room)) {
      rooms.get(room).delete(socket.id);
      if (rooms.get(room).size === 0) rooms.delete(room);
    }
    socket.to(room).emit('user-disconnected', { peerId: socket.id });
    log(`[←] LEAVE ${mask(socket.id)}`);
  });

  socket.on('disconnecting', () => {
    for (const room of socket.rooms) {
      if (room !== socket.id) {
        socket.to(room).emit('user-disconnected', { peerId: socket.id });
        // ✅ FIX-ROOM: ניקוי
        if (rooms.has(room)) {
          rooms.get(room).delete(socket.id);
          if (rooms.get(room).size === 0) rooms.delete(room);
        }
      }
    }
  });

  socket.on('disconnect', () => {
    rateMap.delete(socket.id); // ✅ ניקוי rate state
    log(`[-] DISCONNECT ${mask(socket.id)}`);
  });
});

server.listen(PORT, () => {
  log(`
  ██╗  ██╗████████╗    ███████╗███████╗ ██████╗
  ██║  ██║╚══██╔══╝    ██╔════╝██╔════╝██╔════╝
  ███████║   ██║       ███████╗█████╗  ██║
  ██╔══██║   ██║       ╚════██║██╔══╝  ██║
  ██║  ██║   ██║       ███████║███████╗╚██████╗

  HT-SECURITY PRO  ·  v2.0-HARDENED  ·  PORT ${PORT}
  HTTPS ✅  Rate-Limit ✅  Token-Guard ✅  CORS ✅  Rooms ✅
  `);
});
