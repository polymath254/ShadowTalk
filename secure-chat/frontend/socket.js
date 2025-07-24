// socket.js

// NOTE: Be sure to include <script src="/socket.io/socket.io.js"></script> BEFORE this script in your HTML

const SOCKET_URL = 'http://localhost:5000'; // Update as needed for production
let socket = null;

/**
 * Connects to Socket.IO server with JWT auth.
 * @param {string} token - JWT access token
 * @param {function} onNewMessage - Callback for 'new_message'
 * @param {function} onNewGroupMessage - Callback for 'new_group_message' (optional)
 * @returns {Socket}
 */
function connectSocket(token, onNewMessage, onNewGroupMessage) {
  if (socket) return socket;
  socket = io(SOCKET_URL, {
    auth: { token },
    transports: ['websocket'],
    reconnection: true,
    reconnectionAttempts: 6,
    timeout: 20000
  });

  socket.on('connect', () => console.log('Socket.IO connected:', socket.id));
  socket.on('disconnect', reason => console.warn('Socket.IO disconnected:', reason));
  socket.on('connect_error', err => console.error('Socket.IO error:', err));

  socket.on('new_message', () => {
    if (typeof onNewMessage === 'function') onNewMessage();
  });

  socket.on('new_group_message', msg => {
    if (typeof onNewGroupMessage === 'function') onNewGroupMessage(msg);
  });

  return socket;
}

/**
 * Disconnects the Socket.IO connection.
 */
function disconnectSocket() {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
}

// For use in app.js:
window.connectSocket = connectSocket;
window.disconnectSocket = disconnectSocket;

// ===== Usage pattern for group events (in app.js, not here): =====
//   After connecting, to join a group:
//     socket.emit('join_group', groupId);
//   To send a group message:
//     socket.emit('group_message', { group_id, ciphertext, nonce, sender, ... });
//   To handle new group messages, pass a callback as 3rd arg to connectSocket:
//     connectSocket(accessToken, fetchInbox, function(msg) { ... });

// ===== Example handler in app.js: =====
// window.connectSocket(accessToken, fetchInbox, function(msg) {
//   if (msg.group_id === currentGroupId) {
//     const group = groups[currentGroupId];
//     const keyBytes = nacl.util.decodeBase64(group.groupKey);
//     const box = nacl.util.decodeBase64(msg.ciphertext);
//     const nonce = nacl.util.decodeBase64(msg.nonce);
//     const plainBytes = nacl.secretbox.open(box, nonce, keyBytes);
//     let plain = plainBytes ? nacl.util.encodeUTF8(plainBytes) : '[Could not decrypt]';
//     groupChatLog.innerHTML += `<div class="chat-msg ${msg.sender === username ? "me" : msg.sender}"><span class="chat-txt">${plain}</span></div>`;
//   }
// });

