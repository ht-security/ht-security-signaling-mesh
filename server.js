const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
app.use(cors());

app.get('/', (req, res) => {
  res.send('HT-SECURITY PRO Signaling Server is RUNNING.');
});

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

io.on('connection', (socket) => {
  console.log(`[+] חיבור חדש נכנס: ${socket.id}`);

  socket.on('join-room', ({ room }) => {
    socket.join(room);
    console.log(`[ROOM] צומת ${socket.id} נכנס לחדר: ${room}`);
    
    // מעדכן את מי שכבר בחדר
    const clients = Array.from(io.sockets.adapter.rooms.get(room) || []);
    socket.emit('room-peers', { peers: clients });
    
    // מודיע לשאר
    socket.to(room).emit('user-connected', { peerId: socket.id });
  });

  // העברת הנתונים הקריטיים עם שדה האימות
  socket.on('offer', ({ to, offer, auth }) => {
    io.to(to).emit('offer', { from: socket.id, offer, auth });
  });

  socket.on('answer', ({ to, answer, auth }) => {
    io.to(to).emit('answer', { from: socket.id, answer, auth });
  });

  socket.on('ice-candidate', ({ to, candidate, auth }) => {
    io.to(to).emit('ice-candidate', { from: socket.id, candidate, auth });
  });

  socket.on('leave-room', ({ room }) => {
    socket.leave(room);
    socket.to(room).emit('user-disconnected', { peerId: socket.id });
    console.log(`[ROOM] צומת ${socket.id} עזב את חדר: ${room}`);
  });

  socket.on('disconnecting', () => {
    for (const room of socket.rooms) {
      if (room !== socket.id) {
        socket.to(room).emit('user-disconnected', { peerId: socket.id });
      }
    }
  });

  socket.on('disconnect', () => {
    console.log(`[-] חיבור נותק: ${socket.id}`);
  });
});

const PORT = 3000;
server.listen(PORT, () => {
  console.log(`[HT-SECURITY] שרת הנתב המאובטח רץ ומוכן על פורט ${PORT}`);
});