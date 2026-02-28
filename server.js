const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const url    = require('url');
const crypto = require('crypto');

const PORT = process.env.PORT || 4000;
const DIR  = __dirname;

const CONFIG = {
  OPERATORS: {
    'demo': {
      apiKey:      'demo-api-key-change-me',
      secret:      'demo-secret-change-me-32chars!!!',
      name:        'Demo Casino',
      callbackUrl: null,
      walletUrl:   null,
      allowedOrigins: ['*'],
      maxBet:      10000,
      minBet:      0.01,
      currency:    'USD'
    }
  },
  SESSION_TTL:       1000 * 60 * 60 * 4,
  RATE_LIMIT_WINDOW: 1000,
  RATE_LIMIT_MAX:    15,
  IP_RATE_WINDOW:    60000,
  IP_RATE_MAX:       300,
  MAX_SESSIONS_IP:   20,
  MIN_REVEAL_DELAY:  50,
  MAX_BODY_SIZE:     4096,
  HOUSE_EDGE:        0.01
};

const SERVER_SECRET = process.env.SERVER_SECRET || crypto.randomBytes(32).toString('hex');

function randomHex(bytes = 32)  { return crypto.randomBytes(bytes).toString('hex'); }
function sha256(msg)            { return crypto.createHash('sha256').update(msg).digest('hex'); }
function hmacSHA256(key, msg)   { return crypto.createHmac('sha256', key).update(msg).digest(); }
function hmacSign(data, secret) { return crypto.createHmac('sha256', secret).update(data).digest('hex'); }

function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function generateMinePositions(serverSeed, clientSeed, nonce, mineCount, gridSize = 25) {
  const tiles = Array.from({ length: gridSize }, (_, i) => i);
  for (let i = tiles.length - 1; i > 0; i--) {
    const hmac = hmacSHA256(serverSeed, `${clientSeed}:${nonce}:${i}`);
    const val  = hmac.readUInt32BE(0);
    const j    = val % (i + 1);
    [tiles[i], tiles[j]] = [tiles[j], tiles[i]];
  }
  return new Set(tiles.slice(0, mineCount));
}

function calcMultiplier(revealed, mines, gridSize = 25) {
  if (revealed === 0) return 1;
  let m = 1;
  for (let i = 0; i < revealed; i++) m *= (gridSize - i) / (gridSize - mines - i);
  return parseFloat((m * (1 - CONFIG.HOUSE_EDGE)).toFixed(4));
}

function createSignedToken() {
  const id = randomHex(32);
  const sig = hmacSign(id, SERVER_SECRET);
  return `${id}.${sig}`;
}

function verifySignedToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [id, sig] = parts;
  const expected = hmacSign(id, SERVER_SECRET);
  if (!safeCompare(sig, expected)) return null;
  return id;
}

const rateLimits = new Map();

function checkRateLimit(key, windowMs, maxReqs) {
  const now = Date.now();
  let entry = rateLimits.get(key);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + windowMs };
    rateLimits.set(key, entry);
  }
  entry.count++;
  return entry.count <= maxReqs;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimits) {
    if (now > entry.resetAt) rateLimits.delete(key);
  }
}, 30000);

const sessions = new Map();
const ipSessions = new Map();

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    || req.headers['x-real-ip']
    || req.socket.remoteAddress
    || '0.0.0.0';
}

function createSession(operatorId, playerId, balance, ip, ua) {
  const token = createSignedToken();
  const tokenId = token.split('.')[0];
  const serverSeed = randomHex(32);

  const session = {
    token,
    tokenId,
    operatorId,
    playerId,
    balance:        parseFloat(balance) || 1000,
    initialBalance: parseFloat(balance) || 1000,
    serverSeed,
    serverSeedHash: sha256(serverSeed),
    clientSeed:     randomHex(16),
    nonce:          0,
    game:           null,
    history:        [],
    ip,
    ua:             ua || '',
    createdAt:      Date.now(),
    lastActive:     Date.now(),
    lastRevealAt:   0,
    locked:         false,
    totalBet:       0,
    totalWon:       0,
    gamesPlayed:    0
  };

  sessions.set(tokenId, session);

  if (!ipSessions.has(ip)) ipSessions.set(ip, new Set());
  ipSessions.get(ip).add(tokenId);

  return session;
}

function getSession(req) {
  const token = req.headers['x-session-token'];
  if (!token) return null;

  const tokenId = verifySignedToken(token);
  if (!tokenId) return null;

  const s = sessions.get(tokenId);
  if (!s) return null;

  if (!safeCompare(s.token, token)) return null;

  // if (s.ip !== getClientIP(req)) return null;

  s.lastActive = Date.now();
  return s;
}

function destroySession(tokenId) {
  const s = sessions.get(tokenId);
  if (s) {
    const ipSet = ipSessions.get(s.ip);
    if (ipSet) { ipSet.delete(tokenId); if (ipSet.size === 0) ipSessions.delete(s.ip); }
    sessions.delete(tokenId);
  }
}

setInterval(() => {
  const now = Date.now();
  for (const [tokenId, s] of sessions) {
    if (now - s.lastActive > CONFIG.SESSION_TTL) destroySession(tokenId);
  }
}, 600_000);

async function withLock(session, fn) {
  if (session.locked) {
    throw { status: 429, error: 'request in progress, please wait' };
  }
  session.locked = true;
  try {
    return await fn();
  } finally {
    session.locked = false;
  }
}

function audit(session, action, details = {}) {
  const entry = {
    ts:         new Date().toISOString(),
    operator:   session.operatorId,
    player:     session.playerId,
    action,
    balance:    session.balance,
    ...details
  };
  console.log('[AUDIT]', JSON.stringify(entry));
}

async function notifyOperator(session, event, data) {
  const operator = CONFIG.OPERATORS[session.operatorId];
  if (!operator || !operator.callbackUrl) return;

  const payload = JSON.stringify({
    event,
    playerId:   session.playerId,
    sessionId:  session.tokenId,
    timestamp:  Date.now(),
    ...data
  });

  const signature = hmacSign(payload, operator.secret);

  try {
    const cbUrl = new URL(operator.callbackUrl);
    const opts = {
      method: 'POST',
      hostname: cbUrl.hostname,
      port: cbUrl.port,
      path: cbUrl.pathname,
      headers: {
        'Content-Type':    'application/json',
        'Content-Length':  Buffer.byteLength(payload),
        'X-Signature':     signature,
        'X-Operator-Id':   session.operatorId
      }
    };
    const req = http.request(opts);
    req.on('error', () => {});
    req.write(payload);
    req.end();
  } catch (e) {
    console.error('[CALLBACK ERROR]', e.message);
  }
}

async function walletRequest(session, endpoint, data) {
  const operator = CONFIG.OPERATORS[session.operatorId];
  if (!operator || !operator.walletUrl) return null;

  const payload = JSON.stringify({
    playerId:   session.playerId,
    sessionId:  session.tokenId,
    timestamp:  Date.now(),
    ...data
  });
  const signature = hmacSign(payload, operator.secret);

  return new Promise((resolve, reject) => {
    try {
      const walletUrl = new URL(operator.walletUrl + endpoint);
      const opts = {
        method: 'POST',
        hostname: walletUrl.hostname,
        port: walletUrl.port || (walletUrl.protocol === 'https:' ? 443 : 80),
        path: walletUrl.pathname,
        headers: {
          'Content-Type':   'application/json',
          'Content-Length':  Buffer.byteLength(payload),
          'X-Signature':     signature,
          'X-Operator-Id':   session.operatorId
        },
        timeout: 5000
      };

      const transport = walletUrl.protocol === 'https:' ? require('https') : http;
      const req = transport.request(opts, (res) => {
        let body = '';
        res.on('data', c => body += c);
        res.on('end', () => {
          try {
            const result = JSON.parse(body);
            if (res.statusCode === 200 && result.success) {
              resolve(result);
            } else {
              reject(new Error(result.error || 'wallet request failed'));
            }
          } catch { reject(new Error('invalid wallet response')); }
        });
      });
      req.on('error', (e) => reject(new Error('wallet unreachable: ' + e.message)));
      req.on('timeout', () => { req.destroy(); reject(new Error('wallet timeout')); });
      req.write(payload);
      req.end();
    } catch (e) { reject(e); }
  });
}

async function walletDebit(session, amount, gameRound) {
  const operator = CONFIG.OPERATORS[session.operatorId];
  if (!operator?.walletUrl) {
    if (amount > session.balance) throw { status: 400, error: 'insufficient balance' };
    session.balance = Math.round((session.balance - amount) * 100) / 100;
    return session.balance;
  }

  const txId = randomHex(16);
  const result = await walletRequest(session, '/debit', {
    amount, txId, gameRound, type: 'bet'
  });
  session.balance = result.balance;
  audit(session, 'wallet_debit', { amount, txId, newBalance: result.balance });
  return result.balance;
}

async function walletCredit(session, amount, gameRound) {
  const operator = CONFIG.OPERATORS[session.operatorId];
  if (!operator?.walletUrl) {
    session.balance = Math.round((session.balance + amount) * 100) / 100;
    return session.balance;
  }

  const txId = randomHex(16);
  const result = await walletRequest(session, '/credit', {
    amount, txId, gameRound, type: 'win'
  });
  session.balance = result.balance;
  audit(session, 'wallet_credit', { amount, txId, newBalance: result.balance });
  return result.balance;
}

async function walletGetBalance(session) {
  const operator = CONFIG.OPERATORS[session.operatorId];
  if (!operator?.walletUrl) return session.balance;

  try {
    const result = await walletRequest(session, '/balance', {});
    session.balance = result.balance;
    return result.balance;
  } catch {
    return session.balance;
  }
}

function rotateSeed(session) {
  const oldSeed = session.serverSeed;
  session.serverSeed     = randomHex(32);
  session.serverSeedHash = sha256(session.serverSeed);
  return oldSeed;
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.json': 'application/json',
  '.png':  'image/png',  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.svg':  'image/svg+xml', '.webp': 'image/webp', '.gif': 'image/gif',
  '.ico':  'image/x-icon',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf',
  '.mp3':  'audio/mpeg', '.mp4': 'video/mp4',
};

function sendJSON(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type':                'application/json',
    'Cache-Control':               'no-store, no-cache, must-revalidate',
    'Pragma':                      'no-cache',
    'X-Content-Type-Options':      'nosniff',
    'X-Frame-Options':             'SAMEORIGIN',
    'X-XSS-Protection':           '1; mode=block',
    'Referrer-Policy':             'strict-origin-when-cross-origin',
    'Permissions-Policy':          'camera=(), microphone=(), geolocation=()'
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > CONFIG.MAX_BODY_SIZE) {
        reject({ status: 413, error: 'payload too large' });
      }
    });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

function setSecurityHeaders(res, allowFrameFrom) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cache-Control', 'no-store');
  if (allowFrameFrom && allowFrameFrom !== '*') {
    res.setHeader('Content-Security-Policy', `frame-ancestors 'self' ${allowFrameFrom}`);
  }
}

function clientState(session) {
  const g = session.game;
  const base = {
    balance:        session.balance,
    serverSeedHash: session.serverSeedHash,
    clientSeed:     session.clientSeed,
    nonce:          session.nonce,
    isActive:       !!g,
    currency:       CONFIG.OPERATORS[session.operatorId]?.currency || 'USD'
  };
  if (g) {
    base.betAmount       = g.betAmount;
    base.mineCount       = g.mineCount;
    base.revealedTiles   = g.revealedSafe;
    base.currentMultiplier = g.currentMultiplier;
    base.nextMultiplier  = calcMultiplier(g.revealedSafe.length + 1, g.mineCount, g.gridSize || 25);
  }
  return base;
}

async function handleOperatorAPI(req, res, pathname) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return sendJSON(res, 401, { error: 'missing api key' });

  let operator = null;
  let operatorId = null;
  for (const [id, op] of Object.entries(CONFIG.OPERATORS)) {
    if (safeCompare(op.apiKey, apiKey)) { operator = op; operatorId = id; break; }
  }
  if (!operator) return sendJSON(res, 401, { error: 'invalid api key' });

  if (pathname === '/operator/session' && req.method === 'POST') {
    const body = await readBody(req);
    const playerId = String(body.playerId || '').trim();
    const balance  = parseFloat(body.balance);
    const callbackUrl = body.callbackUrl || operator.callbackUrl;

    if (!playerId) return sendJSON(res, 400, { error: 'playerId required' });
    if (isNaN(balance) || balance < 0) return sendJSON(res, 400, { error: 'invalid balance' });

    const ip = getClientIP(req);
    const ua = req.headers['user-agent'] || '';

    const existing = ipSessions.get(ip);
    if (existing && existing.size >= CONFIG.MAX_SESSIONS_IP) {
      return sendJSON(res, 429, { error: 'too many sessions' });
    }

    if (callbackUrl) operator.callbackUrl = callbackUrl;

    const session = createSession(operatorId, playerId, balance, ip, ua);

    audit(session, 'session_created', { balance });

    return sendJSON(res, 200, {
      token:     session.token,
      sessionId: session.tokenId,
      gameUrl:   `/game?token=${encodeURIComponent(session.token)}`,
      expiresIn: CONFIG.SESSION_TTL
    });
  }

  if (pathname.startsWith('/operator/session/') && req.method === 'GET') {
    const tokenId = pathname.split('/operator/session/')[1];
    const session = sessions.get(tokenId);
    if (!session || session.operatorId !== operatorId) {
      return sendJSON(res, 404, { error: 'session not found' });
    }
    return sendJSON(res, 200, {
      sessionId:    session.tokenId,
      playerId:     session.playerId,
      balance:      session.balance,
      initialBalance: session.initialBalance,
      gamesPlayed:  session.gamesPlayed,
      totalBet:     session.totalBet,
      totalWon:     session.totalWon,
      netResult:    Math.round((session.totalWon - session.totalBet) * 100) / 100,
      isActive:     !!session.game,
      createdAt:    session.createdAt,
      lastActive:   session.lastActive
    });
  }

  if (pathname.match(/^\/operator\/session\/[^/]+\/close$/) && req.method === 'POST') {
    const tokenId = pathname.split('/operator/session/')[1].replace('/close', '');
    const session = sessions.get(tokenId);
    if (!session || session.operatorId !== operatorId) {
      return sendJSON(res, 404, { error: 'session not found' });
    }
    const finalBalance = session.balance;
    audit(session, 'session_closed', { finalBalance });
    destroySession(tokenId);
    return sendJSON(res, 200, {
      finalBalance,
      totalBet:    session.totalBet,
      totalWon:    session.totalWon,
      gamesPlayed: session.gamesPlayed
    });
  }

  if (pathname.match(/^\/operator\/session\/[^/]+\/balance$/) && req.method === 'POST') {
    const tokenId = pathname.split('/operator/session/')[1].replace('/balance', '');
    const session = sessions.get(tokenId);
    if (!session || session.operatorId !== operatorId) {
      return sendJSON(res, 404, { error: 'session not found' });
    }
    if (session.game) return sendJSON(res, 400, { error: 'cannot update during active game' });
    const body = await readBody(req);
    const newBalance = parseFloat(body.balance);
    if (isNaN(newBalance) || newBalance < 0) return sendJSON(res, 400, { error: 'invalid balance' });
    session.balance = Math.round(newBalance * 100) / 100;
    audit(session, 'balance_updated', { newBalance: session.balance });
    return sendJSON(res, 200, { balance: session.balance });
  }

  sendJSON(res, 404, { error: 'not found' });
}

async function handleGameAPI(req, res, pathname) {
  const ip = getClientIP(req);

  // if (!checkRateLimit(`ip:${ip}`, CONFIG.IP_RATE_WINDOW, CONFIG.IP_RATE_MAX)) {
  //   return sendJSON(res, 429, { error: 'rate limit exceeded' });
  // }

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Session-Token');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  if (pathname === '/api/state' && req.method === 'GET') {
    let session = getSession(req);
    if (!session) {
      session = createSession('demo', 'anonymous_' + randomHex(4), 1000, ip, req.headers['user-agent'] || '');
    }
    return sendJSON(res, 200, { token: session.token, ...clientState(session) });
  }

  const session = getSession(req);
  if (!session) return sendJSON(res, 401, { error: 'invalid session' });

  // if (!checkRateLimit(`sess:${session.tokenId}`, CONFIG.RATE_LIMIT_WINDOW, CONFIG.RATE_LIMIT_MAX)) {
  //   return sendJSON(res, 429, { error: 'too fast' });
  // }

  const operator = CONFIG.OPERATORS[session.operatorId] || {};

  if (pathname === '/api/start' && req.method === 'POST') {
    return withLock(session, async () => {
      if (session.game) return sendJSON(res, 400, { error: 'game already active' });
      const body  = await readBody(req);
      const bet      = Math.round((parseFloat(body.bet) || 0) * 100) / 100;
      const mines    = parseInt(body.mines) || 1;
      const gridSize = [25, 36, 49, 64].includes(parseInt(body.gridSize)) ? parseInt(body.gridSize) : 25;
      const maxMines = gridSize - 1;

      if (bet < (operator.minBet || 0.01)) return sendJSON(res, 400, { error: 'bet too low' });
      if (bet > Math.min(session.balance, operator.maxBet || 10000)) return sendJSON(res, 400, { error: 'bet too high' });
      if (mines < 1 || mines > maxMines) return sendJSON(res, 400, { error: 'invalid mine count' });

      const gameRound = `${session.tokenId}:${session.gamesPlayed}`;
      try {
        await walletDebit(session, bet, gameRound);
      } catch (e) {
        return sendJSON(res, 400, { error: e.error || 'insufficient balance' });
      }
      session.totalBet += bet;
      session.gamesPlayed++;

      const positions = generateMinePositions(
        session.serverSeed, session.clientSeed, session.nonce, mines, gridSize
      );

      session.game = {
        betAmount:         bet,
        mineCount:         mines,
        gridSize:          gridSize,
        minePositions:     positions,
        revealedSafe:      [],
        currentMultiplier: 1,
        serverSeed:        session.serverSeed,
        clientSeed:        session.clientSeed,
        nonce:             session.nonce,
        startedAt:         Date.now()
      };

      audit(session, 'game_start', { bet, mines });
      notifyOperator(session, 'game_start', { bet, mines, balance: session.balance });

      return sendJSON(res, 200, clientState(session));
    });
  }

  if (pathname === '/api/reveal' && req.method === 'POST') {
    return withLock(session, async () => {
      const g = session.game;
      if (!g) return sendJSON(res, 400, { error: 'no active game' });

      // const now = Date.now();
      // if (now - session.lastRevealAt < CONFIG.MIN_REVEAL_DELAY) {
      //   return sendJSON(res, 429, { error: 'too fast' });
      // }
      // session.lastRevealAt = now;

      const body  = await readBody(req);
      const index = parseInt(body.index);
      const maxIndex = (g.gridSize || 25) - 1;
      if (isNaN(index) || index < 0 || index > maxIndex) return sendJSON(res, 400, { error: 'invalid tile' });
      if (g.revealedSafe.some(t => t.index === index)) return sendJSON(res, 400, { error: 'already revealed' });

      const isMine = g.minePositions.has(index);

      if (isMine) {
        const allMines = Array.from(g.minePositions);
        const revealedServerSeed = g.serverSeed;

        session.history.unshift({
          serverSeed: revealedServerSeed, serverSeedHash: sha256(revealedServerSeed),
          clientSeed: g.clientSeed, nonce: g.nonce,
          mineCount: g.mineCount, bet: g.betAmount,
          multiplier: 0, payout: 0, won: false,
          minePositions: allMines,
          revealedTiles: g.revealedSafe.map(t => t.index),
          hitTile: index, timestamp: Date.now()
        });
        if (session.history.length > 50) session.history.pop();

        session.nonce++;
        rotateSeed(session);
        session.game = null;

        audit(session, 'game_loss', { bet: g.betAmount, hitTile: index });
        notifyOperator(session, 'game_end', {
          result: 'loss', bet: g.betAmount, payout: 0,
          balance: session.balance
        });

        return sendJSON(res, 200, {
          result: 'mine', hitTile: index,
          minePositions: allMines, serverSeed: revealedServerSeed,
          ...clientState(session)
        });
      }

      g.revealedSafe.push({ index, isMine: false });
      g.currentMultiplier = calcMultiplier(g.revealedSafe.length, g.mineCount, g.gridSize || 25);

      if (g.revealedSafe.length === (g.gridSize || 25) - g.mineCount) {
        return doCashout(res, session);
      }

      return sendJSON(res, 200, { result: 'safe', ...clientState(session) });
    });
  }

  if (pathname === '/api/cashout' && req.method === 'POST') {
    return withLock(session, async () => {
      const g = session.game;
      if (!g) return sendJSON(res, 400, { error: 'no active game' });
      if (g.revealedSafe.length === 0) return sendJSON(res, 400, { error: 'reveal at least one tile' });
      return doCashout(res, session);
    });
  }

  if (pathname === '/api/seeds/rotate' && req.method === 'POST') {
    if (session.game) return sendJSON(res, 400, { error: 'cannot rotate during game' });
    const oldSeed = rotateSeed(session);
    session.nonce = 0;
    audit(session, 'seed_rotate');
    return sendJSON(res, 200, { previousServerSeed: oldSeed, ...clientState(session) });
  }

  if (pathname === '/api/seeds/client' && req.method === 'POST') {
    if (session.game) return sendJSON(res, 400, { error: 'cannot change during game' });
    const body = await readBody(req);
    const newSeed = String(body.clientSeed || '').trim().replace(/[^a-zA-Z0-9]/g, '');
    if (!newSeed || newSeed.length > 64) return sendJSON(res, 400, { error: 'invalid client seed' });
    session.clientSeed = newSeed;
    audit(session, 'client_seed_change');
    return sendJSON(res, 200, clientState(session));
  }

  if (pathname === '/api/balance/refresh' && req.method === 'POST') {
    if (session.game) return sendJSON(res, 400, { error: 'cannot refresh during game' });
    const balance = await walletGetBalance(session);
    audit(session, 'balance_refresh', { balance });
    return sendJSON(res, 200, clientState(session));
  }

  if (pathname === '/api/balance/reset' && req.method === 'POST') {
    const op = CONFIG.OPERATORS[session.operatorId];
    if (op?.walletUrl) return sendJSON(res, 403, { error: 'use balance/refresh with wallet' });
    if (session.operatorId !== 'demo') return sendJSON(res, 403, { error: 'not allowed' });
    if (session.game) return sendJSON(res, 400, { error: 'cannot reset during game' });
    session.balance = 1000;
    audit(session, 'balance_reset');
    return sendJSON(res, 200, clientState(session));
  }

  if (pathname === '/api/history' && req.method === 'GET') {
    return sendJSON(res, 200, { history: session.history });
  }

  sendJSON(res, 404, { error: 'not found' });
}

async function doCashout(res, session) {
  const g      = session.game;
  const payout = Math.round(g.betAmount * g.currentMultiplier * 100) / 100;

  const gameRound = `${session.tokenId}:${session.gamesPlayed - 1}`;
  try {
    await walletCredit(session, payout, gameRound);
  } catch (e) {
    console.error('[WALLET CREDIT ERROR]', e.message);
    session.balance = Math.round((session.balance + payout) * 100) / 100;
  }
  session.totalWon += payout;

  const allMines     = Array.from(g.minePositions);
  const revealedSeed = g.serverSeed;

  session.history.unshift({
    serverSeed: revealedSeed, serverSeedHash: sha256(revealedSeed),
    clientSeed: g.clientSeed, nonce: g.nonce,
    mineCount: g.mineCount, bet: g.betAmount,
    multiplier: g.currentMultiplier, payout, won: true,
    minePositions: allMines,
    revealedTiles: g.revealedSafe.map(t => t.index),
    timestamp: Date.now()
  });
  if (session.history.length > 50) session.history.pop();

  session.nonce++;
  rotateSeed(session);
  session.game = null;

  audit(session, 'game_win', { bet: g.betAmount, payout, multiplier: g.currentMultiplier });
  notifyOperator(session, 'game_end', {
    result: 'win', bet: g.betAmount, payout,
    multiplier: g.currentMultiplier, balance: session.balance
  });

  return sendJSON(res, 200, {
    result: 'cashout', payout,
    multiplier: g.currentMultiplier,
    minePositions: allMines, serverSeed: revealedSeed,
    ...clientState(session)
  });
}

function serveGamePage(req, res, query) {
  const launchToken = query.token || '';

  if (launchToken) {
    const tokenId = verifySignedToken(launchToken);
    if (!tokenId || !sessions.has(tokenId)) {
      res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<h1>Session expired or invalid</h1><p>Please relaunch the game.</p>');
      return;
    }
  }

  const htmlPath = path.join(DIR, 'index.html');
  fs.readFile(htmlPath, 'utf8', (err, html) => {
    if (err) { res.writeHead(500); res.end('Internal error'); return; }

    const tokenScript = `<script>window.__LAUNCH_TOKEN__ = ${JSON.stringify(launchToken)};</script>`;
    html = html.replace('<title>', tokenScript + '\n  <title>');

    const integrationScript = `
<script>
(function() {
  const LAUNCH_TOKEN = window.__LAUNCH_TOKEN__ || '';

  function notifyHost(event, data) {
    if (window.parent && window.parent !== window) {
      window.parent.postMessage({
        source: 'mines-game',
        event: event,
        data: data
      }, '*');
    }
  }

  const _origShowResult = window.showResult;
  window.showResult = function(won) {
    _origShowResult(won);
    notifyHost(won ? 'game_win' : 'game_loss', {
      balance:    state.balance,
      bet:        state.betAmount,
      multiplier: state.currentMultiplier,
      payout:     won ? Math.round(state.betAmount * state.currentMultiplier * 100) / 100 : 0
    });
    notifyHost('balance_update', { balance: state.balance });
  };

  const _origStartGame = window.startGame;
  window.startGame = async function() {
    await _origStartGame();
    if (state.isActive) {
      notifyHost('game_start', { bet: state.betAmount, mines: state.mineCount });
      notifyHost('balance_update', { balance: state.balance });
    }
  };

  window.addEventListener('message', function(e) {
    if (!e.data || e.data.target !== 'mines-game') return;
    switch (e.data.action) {
      case 'get_balance':
        notifyHost('balance_update', { balance: state.balance });
        break;
      case 'refresh_balance':
        (async function() {
          try {
            const data = await api('/api/balance/refresh', 'POST');
            syncState(data);
            updateUI();
            notifyHost('balance_update', { balance: state.balance });
          } catch(e) {
            try {
              const data = await api('/api/state');
              syncState(data);
              updateUI();
              notifyHost('balance_update', { balance: state.balance });
            } catch(e2) {}
          }
        })();
        break;
      case 'get_state':
        notifyHost('state_update', {
          balance: state.balance,
          isActive: state.isActive,
          gamesPlayed: state.gameHistory.length
        });
        break;
      case 'close':
        notifyHost('game_close', { balance: state.balance });
        break;
    }
  });

  window.addEventListener('load', function() {
    notifyHost('game_ready', { balance: state.balance });
  });
})();
</script>`;

    html = html.replace('</body>', integrationScript + '\n</body>');

    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    });
    res.end(html);
  });
}

http.createServer(async (req, res) => {
  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const ip       = getClientIP(req);

  // if (!checkRateLimit(`global:${ip}`, CONFIG.IP_RATE_WINDOW, CONFIG.IP_RATE_MAX)) {
  //   res.writeHead(429); res.end('Too many requests'); return;
  // }

  if (pathname.startsWith('/operator/')) {
    try { await handleOperatorAPI(req, res, pathname); }
    catch (err) {
      const status = err.status || 500;
      sendJSON(res, status, { error: err.error || 'internal error' });
    }
    return;
  }

  if (pathname.startsWith('/api/')) {
    try { await handleGameAPI(req, res, pathname); }
    catch (err) {
      const status = err.status || 500;
      sendJSON(res, status, { error: err.error || 'internal error' });
    }
    return;
  }

  if (pathname === '/game') {
    serveGamePage(req, res, parsed.query);
    return;
  }

  let fp = pathname;
  if (fp === '/' || fp === '') fp = '/index.html';
  const safe = path.normalize(fp).replace(/^(\.\.(\/|\\|$))+/, '');
  const full = path.join(DIR, safe);

  if (!full.startsWith(DIR)) { res.writeHead(403); res.end('Forbidden'); return; }

  fs.stat(full, (err, stats) => {
    if (err || !stats.isFile()) { res.writeHead(404); res.end('Not found'); return; }
    const ct = MIME[path.extname(full).toLowerCase()] || 'application/octet-stream';
    setSecurityHeaders(res);
    res.writeHead(200, { 'Content-Type': ct });
    fs.createReadStream(full).pipe(res);
  });

}).listen(PORT, () => {
  console.log('');
  console.log('========================================');
  console.log(`  MINES SERVER – Port ${PORT}`);
  console.log('========================================');
  console.log('');
  console.log('OPERATOR API (backend del cliente):');
  console.log('  POST /operator/session              – Crea sessione giocatore');
  console.log('  GET  /operator/session/:id           – Info sessione');
  console.log('  POST /operator/session/:id/close     – Chiudi sessione');
  console.log('  POST /operator/session/:id/balance   – Aggiorna saldo');
  console.log('');
  console.log('GAME LAUNCH (iframe):');
  console.log('  GET  /game?token=xxx                 – Apri gioco in iframe');
  console.log('');
  console.log('GAME API (frontend dentro iframe):');
  console.log('  GET  /api/state     POST /api/start');
  console.log('  POST /api/reveal    POST /api/cashout');
  console.log('  POST /api/seeds/*   GET  /api/history');
  console.log('');
  console.log('STANDALONE (test):');
  console.log(`  http://localhost:${PORT}/`);
  console.log('');
});
