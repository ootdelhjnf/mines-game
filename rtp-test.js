// ============================================================
// RTP & RNG VERIFICATION — FAST MODE
//   - 1,000,000 round con Math.random() per verifica RTP
//   - 50,000 round con HMAC-SHA256 per verifica distribuzione
// ============================================================

const crypto = require('crypto');

const HOUSE_EDGE = 0.01;
const ROUNDS_RTP = 1_000_000;
const ROUNDS_RNG = 50_000;

// ── Multiplier (stessa formula del server) ──
function calcMultiplier(revealed, mines) {
  if (revealed === 0) return 1;
  let m = 1;
  for (let i = 0; i < revealed; i++) m *= (25 - i) / (25 - mines - i);
  return parseFloat((m * (1 - HOUSE_EDGE)).toFixed(4));
}

// ── Fast mine generation (Math.random, per RTP test) ──
function fastMines(mineCount) {
  const tiles = Array.from({ length: 25 }, (_, i) => i);
  for (let i = 24; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [tiles[i], tiles[j]] = [tiles[j], tiles[i]];
  }
  return new Set(tiles.slice(0, mineCount));
}

// ── HMAC mine generation (stessa del server, per RNG test) ──
function hmacMines(serverSeed, clientSeed, nonce, mineCount) {
  const tiles = Array.from({ length: 25 }, (_, i) => i);
  for (let i = 24; i > 0; i--) {
    const hmac = crypto.createHmac('sha256', serverSeed)
      .update(`${clientSeed}:${nonce}:${i}`).digest();
    const val = hmac.readUInt32BE(0);
    const j = val % (i + 1);
    [tiles[i], tiles[j]] = [tiles[j], tiles[i]];
  }
  return new Set(tiles.slice(0, mineCount));
}

// ── Test configs ──
const CONFIGS = [
  { mines: 1,  clicks: 1,  label: '1 mine, 1 click' },
  { mines: 1,  clicks: 5,  label: '1 mine, 5 clicks' },
  { mines: 3,  clicks: 1,  label: '3 mines, 1 click' },
  { mines: 3,  clicks: 3,  label: '3 mines, 3 clicks' },
  { mines: 5,  clicks: 1,  label: '5 mines, 1 click' },
  { mines: 5,  clicks: 5,  label: '5 mines, 5 clicks' },
  { mines: 10, clicks: 1,  label: '10 mines, 1 click' },
  { mines: 10, clicks: 3,  label: '10 mines, 3 clicks' },
  { mines: 20, clicks: 1,  label: '20 mines, 1 click' },
  { mines: 24, clicks: 1,  label: '24 mines, 1 click' },
];

// ══════════════════════════════════════════════
//  PART 1: RTP TEST (1M rounds, Math.random)
// ══════════════════════════════════════════════
console.log('');
console.log('================================================================');
console.log('  MINES RTP & RNG VERIFICATION');
console.log(`  RTP test:  ${(ROUNDS_RTP/1e6).toFixed(0)}M rounds (Math.random)`);
console.log(`  RNG test:  ${(ROUNDS_RNG/1e3).toFixed(0)}K rounds (HMAC-SHA256)`);
console.log(`  House Edge: ${(HOUSE_EDGE * 100).toFixed(1)}%  |  Target RTP: ${((1 - HOUSE_EDGE) * 100).toFixed(1)}%`);
console.log('================================================================');

const t0 = Date.now();
const rtpResults = [];

for (const cfg of CONFIGS) {
  let totalBet = 0, totalPayout = 0, wins = 0;

  for (let r = 0; r < ROUNDS_RTP; r++) {
    const positions = fastMines(cfg.mines);
    totalBet += 1;

    // Simula clicks random
    const avail = [];
    for (let i = 0; i < 25; i++) avail.push(i);
    let hit = false, revealed = 0;

    for (let c = 0; c < cfg.clicks; c++) {
      const idx = Math.floor(Math.random() * avail.length);
      const tile = avail[idx];
      avail.splice(idx, 1);
      if (positions.has(tile)) { hit = true; break; }
      revealed++;
    }

    if (!hit) {
      wins++;
      totalPayout += calcMultiplier(revealed, cfg.mines);
    }
  }

  // Theoretical
  let theoWinProb = 1;
  for (let i = 0; i < cfg.clicks; i++) theoWinProb *= (25 - cfg.mines - i) / (25 - i);

  const rtp = (totalPayout / totalBet) * 100;
  const theoRTP = theoWinProb * calcMultiplier(cfg.clicks, cfg.mines) * 100;
  const winPct = (wins / ROUNDS_RTP) * 100;
  const theoWinPct = theoWinProb * 100;

  rtpResults.push({
    ...cfg,
    rtp, theoRTP, rtpDev: Math.abs(rtp - theoRTP),
    winPct, theoWinPct, winDev: Math.abs(winPct - theoWinPct),
    mult: calcMultiplier(cfg.clicks, cfg.mines)
  });
}

console.log('');
console.log('  RTP RESULTS (1M rounds each)');
console.log('  ' + '-'.repeat(90));
console.log(
  '  ' +
  'Config'.padEnd(24) +
  'Win%'.padStart(8) +
  'Theo%'.padStart(8) +
  '  ' +
  'RTP%'.padStart(8) +
  'Target'.padStart(8) +
  'Dev'.padStart(8) +
  'Multi'.padStart(9) +
  'Status'.padStart(10)
);
console.log('  ' + '-'.repeat(90));

let allRtpPass = true;
for (const r of rtpResults) {
  const pass = r.rtpDev < 0.5;
  if (!pass) allRtpPass = false;
  const color = pass ? '\x1b[32m' : '\x1b[31m';
  console.log(
    '  ' +
    r.label.padEnd(24) +
    r.winPct.toFixed(2).padStart(8) +
    r.theoWinPct.toFixed(2).padStart(8) +
    '  ' +
    r.rtp.toFixed(2).padStart(8) +
    r.theoRTP.toFixed(2).padStart(8) +
    color + r.rtpDev.toFixed(3).padStart(8) + '\x1b[0m' +
    r.mult.toFixed(4).padStart(9) +
    (pass ? '\x1b[32m      PASS\x1b[0m' : '\x1b[31m      FAIL\x1b[0m')
  );
}

// ══════════════════════════════════════════════
//  PART 2: RNG DISTRIBUTION (50K, HMAC)
// ══════════════════════════════════════════════
console.log('');
console.log('  RNG DISTRIBUTION TEST (HMAC-SHA256, 50K rounds)');
console.log('  ' + '-'.repeat(90));

const rngConfigs = [
  { mines: 1,  label: '1 mine' },
  { mines: 3,  label: '3 mines' },
  { mines: 5,  label: '5 mines' },
  { mines: 12, label: '12 mines' },
];

let allRngPass = true;

for (const cfg of rngConfigs) {
  const freq = new Array(25).fill(0);
  const serverSeed = crypto.randomBytes(32).toString('hex');
  const clientSeed = crypto.randomBytes(16).toString('hex');

  for (let n = 0; n < ROUNDS_RNG; n++) {
    const positions = hmacMines(serverSeed, clientSeed, n, cfg.mines);
    for (const p of positions) freq[p]++;
  }

  const expected = (ROUNDS_RNG * cfg.mines) / 25;
  let chiSq = 0;
  for (let i = 0; i < 25; i++) chiSq += Math.pow(freq[i] - expected, 2) / expected;
  const pass = chiSq < 36.42; // df=24, p=0.05
  if (!pass) allRngPass = false;

  // Min/max deviation
  const devs = freq.map(f => ((f - expected) / expected * 100));
  const maxDev = Math.max(...devs.map(Math.abs));

  console.log(
    `  ${cfg.label.padEnd(12)} ` +
    `Chi2: ${chiSq.toFixed(2).padStart(7)}  ` +
    `Expected/tile: ${expected.toFixed(0).padStart(5)}  ` +
    `MaxDev: ${maxDev.toFixed(2).padStart(5)}%  ` +
    (pass ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m')
  );

  // Mostra griglia 5x5 per la config 3 mines
  if (cfg.mines === 3) {
    console.log('');
    console.log('  Position heatmap (3 mines, 50K rounds):');
    for (let row = 0; row < 5; row++) {
      let line = '    ';
      for (let col = 0; col < 5; col++) {
        const idx = row * 5 + col;
        const dev = devs[idx];
        const c = Math.abs(dev) < 1 ? '\x1b[32m' : (Math.abs(dev) < 2 ? '\x1b[33m' : '\x1b[31m');
        line += `${c}${freq[idx].toString().padStart(5)} (${dev >= 0 ? '+' : ''}${dev.toFixed(1)}%)\x1b[0m  `;
      }
      console.log(line);
    }
    console.log('');
  }
}

// ══════════════════════════════════════════════
//  PART 3: MATHEMATICAL PROOF
// ══════════════════════════════════════════════
console.log('');
console.log('  MATHEMATICAL RTP PROOF');
console.log('  ' + '-'.repeat(90));
console.log('  For ANY mines/clicks combo:');
console.log('    P(survive k clicks) = C(25-m, k) / C(25, k)');
console.log('    Multiplier(k, m)    = [product (25-i)/(25-m-i) for i=0..k-1] * 0.99');
console.log('    RTP = P(survive) * Multiplier = 0.99 = 99.00%');
console.log('');
console.log('  This is TRUE by construction: the multiplier IS the inverse');
console.log('  probability times (1 - house_edge). RTP is always exactly 99%.');
console.log('');

// Verify mathematically for each config
let mathPass = true;
for (const cfg of CONFIGS) {
  let prob = 1;
  for (let i = 0; i < cfg.clicks; i++) prob *= (25 - cfg.mines - i) / (25 - i);
  const mult = calcMultiplier(cfg.clicks, cfg.mines);
  const exactRTP = prob * mult * 100;
  if (Math.abs(exactRTP - 99.0) > 0.01) mathPass = false;
}
console.log(mathPass
  ? '  \x1b[32mAll configs: RTP = 99.00% exactly (mathematically proven)\x1b[0m'
  : '  \x1b[31mMath check FAILED\x1b[0m');

// ══════════════════════════════════════════════
//  SUMMARY
// ══════════════════════════════════════════════
const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
console.log('');
console.log('================================================================');
console.log(`  Completed in ${elapsed}s`);
console.log('');
console.log(`  RTP Test (1M rounds):   ${allRtpPass ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  — All configs converge to 99% RTP`);
console.log(`  RNG Test (50K HMAC):    ${allRngPass ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  — Mine positions uniformly distributed`);
console.log(`  Math Proof:             ${mathPass ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  — RTP = 99.00% by formula`);
console.log('================================================================');
console.log('');
