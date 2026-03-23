const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'mih-gg-secret-key-2026-troca-isso-em-producao';

// ─── MIDDLEWARES ─────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Upload de avatares
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'public', 'avatars');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `avatar-${uuidv4()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Só imagens são permitidas'));
  }
});

// ─── DATABASE HELPERS ────────────────────────────────
const DB_PATH = path.join(__dirname, 'database.json');

function readDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch {
    return { users: [], siteConfig: {}, posts: [], schedule: [] };
  }
}

function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// ─── AUTH MIDDLEWARE ─────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token não fornecido' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Apenas a Mih pode fazer isso!' });
    next();
  });
}

// ─── AUTH ROUTES ─────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Usuário e senha são obrigatórios' });

  const db = readDB();
  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Senha incorreta' });

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      profile: user.profile
    }
  });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  const { password, ...safeUser } = user;
  res.json(safeUser);
});

// ─── USER MANAGEMENT (Admin only) ────────────────────
app.post('/api/admin/users/create', adminMiddleware, async (req, res) => {
  const { username, password, displayName, color, nameEffect } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Usuário e senha são obrigatórios' });

  const db = readDB();
  if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: 'Esse usuário já existe' });
  }

  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    id: uuidv4(),
    username,
    password: hashed,
    role: 'viewer',
    createdAt: new Date().toISOString(),
    profile: {
      displayName: displayName || username,
      color: color || '#a8f0b0',
      nameEffect: nameEffect || 'none',
      avatar: null,
      bio: '',
      badges: ['🎮']
    }
  };

  db.users.push(newUser);
  writeDB(db);

  const { password: _, ...safeUser } = newUser;
  res.status(201).json({ message: 'Usuário criado com sucesso!', user: safeUser });
});

app.get('/api/admin/users', adminMiddleware, (req, res) => {
  const db = readDB();
  const users = db.users.map(({ password, ...u }) => u);
  res.json(users);
});

app.delete('/api/admin/users/:id', adminMiddleware, (req, res) => {
  const db = readDB();
  const idx = db.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Usuário não encontrado' });
  if (db.users[idx].role === 'admin') return res.status(403).json({ error: 'Não pode deletar a admin!' });
  db.users.splice(idx, 1);
  writeDB(db);
  res.json({ message: 'Usuário removido' });
});

app.patch('/api/admin/users/:id', adminMiddleware, async (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

  const { displayName, color, nameEffect, bio, badges, newPassword } = req.body;
  if (displayName) user.profile.displayName = displayName;
  if (color) user.profile.color = color;
  if (nameEffect) user.profile.nameEffect = nameEffect;
  if (bio !== undefined) user.profile.bio = bio;
  if (badges) user.profile.badges = badges;
  if (newPassword) user.password = await bcrypt.hash(newPassword, 10);

  writeDB(db);
  const { password, ...safeUser } = user;
  res.json({ message: 'Usuário atualizado!', user: safeUser });
});

// ─── PROFILE (self) ──────────────────────────────────
app.patch('/api/profile', authMiddleware, async (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

  const { bio, color, nameEffect } = req.body;
  if (bio !== undefined) user.profile.bio = bio;
  if (color) user.profile.color = color;
  if (nameEffect) user.profile.nameEffect = nameEffect;

  writeDB(db);
  const { password, ...safeUser } = user;
  res.json(safeUser);
});

app.post('/api/profile/avatar', authMiddleware, upload.single('avatar'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Nenhuma imagem enviada' });
  const db = readDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

  // delete old avatar
  if (user.profile.avatar) {
    const old = path.join(__dirname, 'public', user.profile.avatar);
    if (fs.existsSync(old)) fs.unlinkSync(old);
  }

  user.profile.avatar = '/avatars/' + req.file.filename;
  writeDB(db);
  res.json({ avatar: user.profile.avatar });
});

// ─── SITE CONFIG (public read, admin write) ──────────
app.get('/api/config', (req, res) => {
  const db = readDB();
  res.json(db.siteConfig);
});

app.patch('/api/admin/config', adminMiddleware, (req, res) => {
  const db = readDB();
  const allowed = ['status', 'currentGame', 'statusMessage', 'streamUrl', 'isLive'];
  allowed.forEach(k => { if (req.body[k] !== undefined) db.siteConfig[k] = req.body[k]; });
  db.siteConfig.lastUpdated = new Date().toISOString();
  writeDB(db);
  res.json({ message: 'Config atualizada!', config: db.siteConfig });
});

app.patch('/api/admin/config/games/:game', adminMiddleware, (req, res) => {
  const { game } = req.params;
  const db = readDB();
  if (!db.siteConfig.games[game]) return res.status(404).json({ error: 'Jogo não encontrado' });
  Object.assign(db.siteConfig.games[game], req.body);
  db.siteConfig.lastUpdated = new Date().toISOString();
  writeDB(db);
  res.json({ message: `${game} atualizado!`, data: db.siteConfig.games[game] });
});

// ─── POSTS ───────────────────────────────────────────
app.get('/api/posts', (req, res) => {
  const db = readDB();
  // non-logged see only public posts
  const token = req.headers.authorization?.split(' ')[1];
  let isLoggedIn = false;
  try { jwt.verify(token, JWT_SECRET); isLoggedIn = true; } catch {}

  const posts = isLoggedIn
    ? db.posts
    : db.posts.filter(p => !p.exclusive);

  res.json(posts.map(p => ({ ...p, likedBy: undefined })));
});

app.post('/api/admin/posts', adminMiddleware, (req, res) => {
  const { title, content, game, emoji, exclusive } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'Título e conteúdo são obrigatórios' });

  const db = readDB();
  const post = {
    id: uuidv4(),
    title, content,
    game: game || 'Geral',
    emoji: emoji || '📝',
    exclusive: !!exclusive,
    likes: 0,
    likedBy: [],
    comments: [],
    createdAt: new Date().toISOString()
  };
  db.posts.unshift(post);
  writeDB(db);
  res.status(201).json(post);
});

app.delete('/api/admin/posts/:id', adminMiddleware, (req, res) => {
  const db = readDB();
  const idx = db.posts.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Post não encontrado' });
  db.posts.splice(idx, 1);
  writeDB(db);
  res.json({ message: 'Post deletado' });
});

app.post('/api/posts/:id/like', authMiddleware, (req, res) => {
  const db = readDB();
  const post = db.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ error: 'Post não encontrado' });

  const uid = req.user.id;
  const liked = post.likedBy.includes(uid);
  if (liked) {
    post.likedBy = post.likedBy.filter(id => id !== uid);
    post.likes = Math.max(0, post.likes - 1);
  } else {
    post.likedBy.push(uid);
    post.likes++;
  }
  writeDB(db);
  res.json({ likes: post.likes, liked: !liked });
});

app.post('/api/posts/:id/comment', authMiddleware, (req, res) => {
  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: 'Comentário vazio' });

  const db = readDB();
  const post = db.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ error: 'Post não encontrado' });

  const user = db.users.find(u => u.id === req.user.id);
  const comment = {
    id: uuidv4(),
    userId: req.user.id,
    username: user.profile.displayName || user.username,
    color: user.profile.color,
    nameEffect: user.profile.nameEffect,
    avatar: user.profile.avatar,
    badges: user.profile.badges,
    text: text.trim().substring(0, 500),
    createdAt: new Date().toISOString()
  };
  post.comments.push(comment);
  writeDB(db);
  res.status(201).json(comment);
});

app.delete('/api/posts/:postId/comment/:commentId', authMiddleware, (req, res) => {
  const db = readDB();
  const post = db.posts.find(p => p.id === req.params.postId);
  if (!post) return res.status(404).json({ error: 'Post não encontrado' });

  const idx = post.comments.findIndex(c => c.id === req.params.commentId);
  if (idx === -1) return res.status(404).json({ error: 'Comentário não encontrado' });

  const comment = post.comments[idx];
  if (comment.userId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Não autorizado' });
  }

  post.comments.splice(idx, 1);
  writeDB(db);
  res.json({ message: 'Comentário deletado' });
});

// ─── SCHEDULE ────────────────────────────────────────
app.get('/api/schedule', (req, res) => {
  const db = readDB();
  res.json(db.schedule);
});

app.post('/api/admin/schedule', adminMiddleware, (req, res) => {
  const db = readDB();
  const { day, time, icon, name, desc, game } = req.body;
  db.schedule.push({ day, time, icon: icon || '🎮', name, desc, game: game || 'Geral' });
  db.schedule.sort((a, b) => a.day - b.day);
  writeDB(db);
  res.status(201).json({ message: 'Evento adicionado!', schedule: db.schedule });
});

app.delete('/api/admin/schedule/:day', adminMiddleware, (req, res) => {
  const db = readDB();
  db.schedule = db.schedule.filter(e => e.day !== parseInt(req.params.day));
  writeDB(db);
  res.json({ message: 'Evento removido', schedule: db.schedule });
});

// ─── STATIC FALLBACK ─────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ─── ERROR HANDLER ───────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err.message);
  res.status(500).json({ error: err.message || 'Erro interno do servidor' });
});

app.listen(PORT, () => {
  console.log(`MIH.GG rodando em http://localhost:${PORT}`);
  console.log(`Login da Mih: usuario "Mih" / senha "1234"`);
});
