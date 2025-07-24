// realtime-node/server.js

const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: { origin: '*' }
});

app.use(express.json());
app.use(cors());

const connectedUsers = {}; // userId: socketId

// ===== JWT Auth for Socket.IO handshake =====
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error("No token provided"));
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return next(new Error("Token invalid"));
    socket.userId = decoded.user_id || decoded.id; // adjust per your JWT payload
    next();
  });
});

// ===== Socket.IO events =====
io.on('connection', (socket) => {
  connectedUsers[socket.userId] = socket.id;
  console.log(`User ${socket.userId} connected (${socket.id})`);

  // --- Private messages ---
  socket.on('disconnect', () => {
    delete connectedUsers[socket.userId];
    console.log(`User ${socket.userId} disconnected`);
  });

  // --- Group chat: join room ---
  socket.on('join_group', (groupId) => {
    socket.join('group_' + groupId);
    // Optionally: console.log(`User ${socket.userId} joined group_${groupId}`);
  });

  // --- Real-time group message relay ---
  socket.on('group_message', (data) => {
    // Optionally: validate data.group_id and user is in group!
    io.to('group_' + data.group_id).emit('new_group_message', data);
  });

  // --- Optionally, handle private 1:1 messages (if needed) ---
  socket.on('private_message', (data) => {
    // { to_user_id, ... }
    const toSocket = connectedUsers[data.to_user_id];
    if (toSocket) {
      io.to(toSocket).emit('new_message', data);
    }
  });
});

// ===== HTTP endpoint for Django to trigger real-time events =====
app.post('/notify', (req, res) => {
  const { recipient_id } = req.body;
  const recipientSocket = connectedUsers[recipient_id];
  if (recipientSocket) {
    io.to(recipientSocket).emit('new_message');
    res.json({ success: true });
  } else {
    res.json({ success: false, error: "User not connected" });
  }
});

const PORT = process.env.PORT || 5000;
const jwtSecret = process.env.JWT_SECRET;
server.listen(PORT, () => {
  console.log('Realtime server running on port', PORT);
});
