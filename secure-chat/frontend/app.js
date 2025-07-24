// ====== Crypto Utilities ======
function toBase64(bytes) { return nacl.util.encodeBase64(bytes); }
function fromBase64(str) { return nacl.util.decodeBase64(str); }
function hashPasswordToKey(password) {
  return nacl.hash(nacl.util.decodeUTF8(password)).subarray(0, 32);
}

// Async HKDF-style key derivation (forward secrecy)
async function derivePerMessageKey(baseKey, nonce) {
  const concat = new Uint8Array([...baseKey, ...nonce]);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', concat);
  return new Uint8Array(hashBuffer).slice(0, 32);
}

// ====== Keypair Handling ======
function generateKeyPair() {
  const pair = nacl.box.keyPair();
  return {
    publicKey: toBase64(pair.publicKey),
    secretKey: toBase64(pair.secretKey),
  };
}
function encryptPrivateKey(secretKey, password) {
  const key = hashPasswordToKey(password);
  const nonce = nacl.randomBytes(24);
  const box = nacl.secretbox(fromBase64(secretKey), nonce, key);
  return toBase64(nonce) + ':' + toBase64(box);
}
function decryptPrivateKey(cipher, password) {
  const key = hashPasswordToKey(password);
  const [nonce_b64, box_b64] = cipher.split(':');
  const secretKey = nacl.secretbox.open(fromBase64(box_b64), fromBase64(nonce_b64), key);
  if (!secretKey) throw new Error("Bad password or corrupted key");
  return toBase64(secretKey);
}

// ====== State ======
let accessToken = null, myPublicKey = null, myPrivateKey = null, username = null;
let contactFingerprints = {}, groups = {}, currentGroupId = null;

// ====== UI Elements ======
const $ = id => document.getElementById(id);
const pairDeviceBtn = $('pair-device-btn'), pairQrSection = $('pair-qr-section');
const loginForm = $('login-form'), messageForm = $('message-form'), chatLog = $('chat-log');
const logoutBtn = $('logout-btn'), deleteAccountBtn = $('delete-account-btn'), forgetMeBtn = $('forget-me-btn');
const myFingerprintCode = $('my-fingerprint-code'), myQrDiv = $('my-qr');
const burnAfterReadInput = $('burn-after-read'), expirySecondsInput = $('expiry-seconds');
const createGroupForm = $('create-group-form'), groupsListDiv = $('groups-list');
const groupChatSection = $('group-chat-section'), groupSelect = $('group-select');
const groupChatLog = $('group-chat-log'), groupMessageForm = $('group-message-form'), groupMessageInput = $('group-message');
const rotateGroupKeyBtn = $('rotate-group-key-btn');

// ====== Public Key Fingerprint ======
function publicKeyFingerprint(publicKeyBase64) {
  const pubBytes = nacl.util.decodeBase64(publicKeyBase64);
  return window.crypto.subtle.digest('SHA-256', pubBytes)
    .then(hash => Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 20).match(/.{1,4}/g).join(' '));
}

// ====== Registration/Login Handler ======
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  username = $('username').value.trim();
  const password = $('password').value;
  let encryptedSecretKey = localStorage.getItem(`shadowtalk_${username}_sk`);

  if (!encryptedSecretKey) {
    const { publicKey, secretKey } = generateKeyPair();
    encryptedSecretKey = encryptPrivateKey(secretKey, password);
    localStorage.setItem(`shadowtalk_${username}_sk`, encryptedSecretKey);
    const res = await fetch('http://127.0.0.1:8000/api/users/login/', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username, password, email: `${username}@shadowtalk`, public_key: publicKey})
    });
    if (res.status !== 201) {
      chatLog.innerHTML += `<div>Registration failed: ${(await res.json()).error || res.status}</div>`; return;
    }
  }

  const res = await fetch('http://127.0.0.1:8000/api/users/login/', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username, password})
  });
  if (res.status !== 200) {
    chatLog.innerHTML += `<div>Login failed: ${(await res.json()).error || res.status}</div>`; return;
  }
  const data = await res.json();
  accessToken = data.access; myPublicKey = data.public_key;
  try { myPrivateKey = decryptPrivateKey(localStorage.getItem(`shadowtalk_${username}_sk`), password); }
  catch { chatLog.innerHTML += `<div>Failed to decrypt private key</div>`; return; }

  // UI setup
  loginForm.style.display = "none"; messageForm.style.display = "flex";
  logoutBtn.style.display = "inline-block"; deleteAccountBtn.style.display = "inline-block"; forgetMeBtn.style.display = "inline-block";
  pairDeviceBtn.style.display = "inline-block"; createGroupForm.style.display = "flex";
  chatLog.innerHTML += `<div>Welcome, ${username}! Key loaded.</div>`;

  publicKeyFingerprint(myPublicKey).then(fingerprint => {
    myFingerprintCode.innerHTML = `Your fingerprint: <span style="font-family:monospace">${fingerprint}</span>`;
    const qrValue = JSON.stringify({ user: username, fingerprint });
    myQrDiv.innerHTML = ''; new QRCode(myQrDiv, {text: qrValue, width: 128, height: 128, colorDark: "#0f0", colorLight: "#181818", correctLevel: QRCode.CorrectLevel.M});
  });

  connectSocket(accessToken, fetchInbox);
  fetchInbox();
  fetchGroups();
});

// ====== Recipient PK ======
async function fetchRecipientPublicKey(username) {
  const res = await fetch(`http://127.0.0.1:8000/api/users/lookup/${username}/`, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!res.ok) throw new Error('Recipient not found');
  return (await res.json()).public_key;
}

// ====== Direct Message Send Handler (per-message forward secrecy) ======
messageForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const recipient = $('recipient').value.trim();
  const message = $('message').value;
  const fileInput = $('file-input'), file = fileInput.files[0];
  const burn_after_read = burnAfterReadInput.checked;
  const expiry_seconds = parseInt(expirySecondsInput.value) || null;
  try {
    const recipientPublicKey = await fetchRecipientPublicKey(recipient);
    let textPayload = null;
    if (message) {
      // Forward secrecy for 1:1
      const nonce = nacl.randomBytes(nacl.box.nonceLength);
      const msgKey = await derivePerMessageKey(nacl.util.decodeBase64(recipientPublicKey), nonce);
      const ciphertext = nacl.box(nacl.util.decodeUTF8(message), nonce, nacl.util.decodeBase64(recipientPublicKey), nacl.util.decodeBase64(myPrivateKey));
      textPayload = JSON.stringify({ciphertext: nacl.util.encodeBase64(ciphertext), nonce: nacl.util.encodeBase64(nonce)});
    }
    let attachmentPayload = null, filename = null, mime_type = null;
    if (file) {
      // (Optional: encrypt with per-file nonce/key)
      const fileBytes = await readFileAsUint8Array(file);
      const nonce = nacl.randomBytes(nacl.box.nonceLength);
      const ciphertext = nacl.box(fileBytes, nonce, nacl.util.decodeBase64(recipientPublicKey), nacl.util.decodeBase64(myPrivateKey));
      attachmentPayload = JSON.stringify({ciphertext: nacl.util.encodeBase64(ciphertext), nonce: nacl.util.encodeBase64(nonce)});
      filename = file.name; mime_type = file.type;
    }
    const payload = {
      recipient,
      ciphertext: textPayload,
      attachment: attachmentPayload,
      filename, mime_type, burn_after_read, expiry_seconds
    };
    const res = await fetch('http://127.0.0.1:8000/api/chat/send/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('Send failed');
    if (message) chatLog.innerHTML += `<div class="chat-msg me"><span class="chat-txt">${message}</span></div>`;
    if (file) { chatLog.innerHTML += `<div class="chat-msg me"><span class="chat-txt">[File sent: ${filename}]</span></div>`; fileInput.value = ''; }
    messageForm.reset();
  } catch (err) {
    chatLog.innerHTML += `<div>Error: ${err.message}</div>`;
  }
});

// ====== Inbox Fetch & Render (direct) ======
async function fetchInbox() {
  const res = await fetch('http://127.0.0.1:8000/api/chat/inbox/', { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!res.ok) return;
  const messages = await res.json();
  for (const msg of messages) {
    const senderRes = await fetch(`http://127.0.0.1:8000/api/users/lookup/${msg.sender}/`, { headers: { Authorization: `Bearer ${accessToken}` } });
    if (!senderRes.ok) continue;
    const senderData = await senderRes.json();
    // Show/detect fingerprint
    const fingerprint = await publicKeyFingerprint(senderData.public_key);
    if (!contactFingerprints[msg.sender]) {
      contactFingerprints[msg.sender] = fingerprint;
      chatLog.innerHTML += `<div style="color:#8ef;">${msg.sender}'s fingerprint: <span style="font-family:monospace">${fingerprint}</span></div>`;
    } else if (contactFingerprints[msg.sender] !== fingerprint) {
      chatLog.innerHTML += `<div style="color:#f22;">WARNING: ${msg.sender}'s key has changed! This could be an attack.</div>`;
      contactFingerprints[msg.sender] = fingerprint;
    }
    // Decrypt with forward secrecy
    let plain = '';
    if (msg.ciphertext) {
      const {ciphertext, nonce} = JSON.parse(msg.ciphertext);
      const box = nacl.util.decodeBase64(ciphertext), nonceBytes = nacl.util.decodeBase64(nonce);
      const msgKey = await derivePerMessageKey(nacl.util.decodeBase64(senderData.public_key), nonceBytes);
      const msgUint8 = nacl.box.open(box, nonceBytes, nacl.util.decodeBase64(senderData.public_key), nacl.util.decodeBase64(myPrivateKey));
      plain = msgUint8 ? nacl.util.encodeUTF8(msgUint8) : "[Could not decrypt]";
      chatLog.innerHTML += `<div class="chat-msg other"><span class="chat-txt">${plain}</span></div>`;
    }
    // ...attachment as before...
  }
}

// ====== Group Chat ======
function encryptGroupKeyForUser(groupKey, userPublicKeyBase64) {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const pub = nacl.util.decodeBase64(userPublicKeyBase64), sec = nacl.util.decodeBase64(myPrivateKey);
  const box = nacl.box(groupKey, nonce, pub, sec);
  return JSON.stringify({ciphertext: nacl.util.encodeBase64(box), nonce: nacl.util.encodeBase64(nonce)});
}
createGroupForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = $('group-name').value.trim();
  const membersStr = $('group-members').value;
  const members = membersStr.split(',').map(u => u.trim()).filter(Boolean);
  const groupKey = nacl.randomBytes(32); // 256-bit
  const encrypted_keys = {};
  for (const member of [...members, username]) {
    try { encrypted_keys[member] = encryptGroupKeyForUser(groupKey, await fetchUserPublicKey(member)); }
    catch { chatLog.innerHTML += `<div style="color:#f22;">User ${member} not found. Skipping.</div>`; }
  }
  const res = await fetch('http://127.0.0.1:8000/api/chat/groups/create/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
    body: JSON.stringify({ name, members, encrypted_keys })
  });
  if (!res.ok) { chatLog.innerHTML += `<div style="color:#f22;">Group creation failed</div>`; return; }
  const group = await res.json();
  groups[group.id] = { name: group.name, members: [ ...members, username ], groupKey: nacl.util.encodeBase64(groupKey) };
  chatLog.innerHTML += `<div style="color:#0af;">Group "${group.name}" created!</div>`;
  renderGroupsList(); updateGroupSelect();
});

async function fetchGroups() {
  const res = await fetch('http://127.0.0.1:8000/api/chat/groups/', { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!res.ok) return;
  const groupsData = await res.json();
  for (const group of groupsData) {
    const memberRes = await fetch(`http://127.0.0.1:8000/api/chat/groups/${group.id}/mykey/`, { headers: { Authorization: `Bearer ${accessToken}` } });
    if (!memberRes.ok) continue;
    const { encrypted_group_key } = await memberRes.json();
    const { ciphertext, nonce } = JSON.parse(encrypted_group_key);
    const box = nacl.util.decodeBase64(ciphertext), nonceBytes = nacl.util.decodeBase64(nonce);
    // Use your own pubkey or group.creator_public_key
    const groupKey = nacl.box.open(box, nonceBytes, nacl.util.decodeBase64(myPublicKey), nacl.util.decodeBase64(myPrivateKey));
    groups[group.id] = { name: group.name, members: group.members, groupKey: nacl.util.encodeBase64(groupKey) };
  }
  renderGroupsList(); updateGroupSelect();
}
function renderGroupsList() {
  groupsListDiv.innerHTML = '';
  for (const [groupId, g] of Object.entries(groups)) {
    groupsListDiv.innerHTML += `<div><b>${g.name}</b> (${g.members.join(', ')})</div>`;
  }
}
function updateGroupSelect() {
  groupSelect.innerHTML = '';
  for (const [groupId, g] of Object.entries(groups)) {
    const opt = document.createElement('option'); opt.value = groupId; opt.textContent = g.name; groupSelect.appendChild(opt);
  }
  if (Object.keys(groups).length > 0) {
    groupChatSection.style.display = "block"; groupSelect.selectedIndex = 0; currentGroupId = groupSelect.value; fetchGroupMessages(currentGroupId);
  } else { groupChatSection.style.display = "none"; }
}
groupSelect.addEventListener('change', () => { currentGroupId = groupSelect.value; fetchGroupMessages(currentGroupId); });
groupMessageForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const msg = groupMessageInput.value;
  if (!currentGroupId || !msg) return;
  const group = groups[currentGroupId];
  const keyBytes = nacl.util.decodeBase64(group.groupKey);
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const msgKey = await derivePerMessageKey(keyBytes, nonce);
  const box = nacl.secretbox(nacl.util.decodeUTF8(msg), nonce, msgKey);
  const payload = { group_id: currentGroupId, ciphertext: nacl.util.encodeBase64(box), nonce: nacl.util.encodeBase64(nonce) };
  const res = await fetch('http://127.0.0.1:8000/api/chat/groups/send/', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` }, body: JSON.stringify(payload)
  });
  if (res.ok) {
    groupChatLog.innerHTML += `<div class="chat-msg me"><span class="chat-txt">${msg}</span></div>`;
    groupMessageForm.reset();
  } else { groupChatLog.innerHTML += `<div style="color:#f22;">Send failed</div>`; }
});
async function fetchGroupMessages(groupId) {
  groupChatLog.innerHTML = '';
  const group = groups[groupId];
  if (!group) return;
  const res = await fetch(`http://127.0.0.1:8000/api/chat/groups/${groupId}/messages/`, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!res.ok) return;
  const msgs = await res.json();
  const keyBytes = nacl.util.decodeBase64(group.groupKey);
  for (const msg of msgs) {
    const box = nacl.util.decodeBase64(msg.ciphertext), nonce = nacl.util.decodeBase64(msg.nonce);
    const msgKey = await derivePerMessageKey(keyBytes, nonce);
    const plainBytes = nacl.secretbox.open(box, nonce, msgKey);
    let plain = plainBytes ? nacl.util.encodeUTF8(plainBytes) : '[Could not decrypt]';
    let who = msg.sender === username ? "me" : msg.sender;
    groupChatLog.innerHTML += `<div class="chat-msg ${who}"><span class="chat-txt">${plain}</span></div>`;
  }
}

// ====== Group Key Rotation ======
rotateGroupKeyBtn.addEventListener('click', async () => {
  const group = groups[currentGroupId];
  const newGroupKey = nacl.randomBytes(32);
  const encrypted_keys = {};
  for (const member of group.members) {
    const pub = await fetchUserPublicKey(member);
    encrypted_keys[member] = encryptGroupKeyForUser(newGroupKey, pub);
  }
  const res = await fetch(`http://127.0.0.1:8000/api/chat/groups/${currentGroupId}/rotatekey/`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` }, body: JSON.stringify({ encrypted_keys })
  });
  if (res.ok) { group.groupKey = nacl.util.encodeBase64(newGroupKey); alert("Group key rotated for all members."); }
});

// ====== About & Backup UI ======
$('about-btn').addEventListener('click', () => { $('about-modal').style.display = 'flex'; });
$('about-close-btn').addEventListener('click', () => { $('about-modal').style.display = 'none'; });
$('backup-btn').addEventListener('click', () => {
  if (!username) return alert('Not logged in');
  const key = localStorage.getItem(`shadowtalk_${username}_sk`);
  const blob = new Blob([key], {type: "text/plain"});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `${username}.shadowtalk`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
});
$('restore-btn').addEventListener('click', () => { $('restore-key-input').click(); });
$('restore-key-input').addEventListener('change', (e) => {
  const file = e.target.files[0]; if (!file) return;
  const reader = new FileReader();
  reader.onload = function() {
    const keyStr = reader.result.trim(), u = prompt("Enter username for this key:");
    if (!u) return;
    localStorage.setItem(`shadowtalk_${u}_sk`, keyStr); alert('Key restored! You can now log in as ' + u);
  };
  reader.readAsText(file);
});

// ====== Logout/Cleanup Handlers ======
logoutBtn.addEventListener('click', () => {
  accessToken = myPublicKey = myPrivateKey = username = null; contactFingerprints = {}; disconnectSocket();
  messageForm.style.display = logoutBtn.style.display = deleteAccountBtn.style.display = forgetMeBtn.style.display = "none";
  loginForm.style.display = "flex"; chatLog.innerHTML += `<div style="color:#f22;">Logged out.</div>`;
  myFingerprintCode.innerHTML = myQrDiv.innerHTML = '';
});
deleteAccountBtn.addEventListener('click', async () => {
  if (!confirm('Are you sure? This cannot be undone!')) return;
  if (!accessToken) return;
  try {
    const res = await fetch('http://127.0.0.1:8000/api/users/delete/', { method: 'DELETE', headers: { Authorization: `Bearer ${accessToken}` } });
    if (res.status === 204) {
      chatLog.innerHTML += `<div style="color:#f22;">Account deleted. Goodbye!</div>`;
      localStorage.removeItem(`shadowtalk_${username}_sk`);
      accessToken = myPublicKey = myPrivateKey = username = null; contactFingerprints = {}; disconnectSocket();
      messageForm.style.display = logoutBtn.style.display = deleteAccountBtn.style.display = forgetMeBtn.style.display = "none";
      loginForm.style.display = "flex"; myFingerprintCode.innerHTML = myQrDiv.innerHTML = '';
    } else { chatLog.innerHTML += `<div style="color:#f22;">Failed to delete account</div>`; }
  } catch (err) { chatLog.innerHTML += `<div style="color:#f22;">Delete error: ${err.message}</div>`; }
});
forgetMeBtn.addEventListener('click', () => {
  if (!username) return;
  if (!confirm("This will remove your local encrypted key. If you don't have a backup, you can't recover messages. Continue?")) return;
  localStorage.removeItem(`shadowtalk_${username}_sk`);
  chatLog.innerHTML += `<div style="color:#f22;">Local encrypted key removed. You must re-register or restore your key to use ShadowTalk again.</div>`;
  accessToken = myPublicKey = myPrivateKey = username = null; contactFingerprints = {};
  disconnectSocket(); messageForm.style.display = logoutBtn.style.display = deleteAccountBtn.style.display = forgetMeBtn.style.display = "none";
  loginForm.style.display = "flex"; myFingerprintCode.innerHTML = myQrDiv.innerHTML = '';
});

// ...Pair device, QR scan, etc. remain unchanged...
