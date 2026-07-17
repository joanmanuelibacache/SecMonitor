/**
 * SecuMonitor - server.js
 * npm install express firebase-admin cors pdfkit dotenv
 */

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const PDF     = require('pdfkit');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore }        = require('firebase-admin/firestore');
const { getAuth }             = require('firebase-admin/auth');
const {
  generateEvent,
  generateBruteForceBurst,
  generatePortScanBurst,
  evaluateEvent,
  EventWindow
} = require('./index.js');

// ── FIREBASE ──────────────────────────────────────────────────────────────────
const svc = process.env.FIREBASE_SERVICE_ACCOUNT_JSON
  ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)
  : require('./serviceAccountKey.json');
initializeApp({ credential: cert(svc) });
const db        = getFirestore();
const eventsCol = db.collection('events');
const alertsCol = db.collection('alerts');
const risksCol  = db.collection('risks');

// ── HELPERS ───────────────────────────────────────────────────────────────────
const win5m = new EventWindow(5 * 60 * 1000);

function riskLevel(s) {
  if (s <= 4)  return 'bajo';
  if (s <= 9)  return 'medio';
  if (s <= 14) return 'alto';
  return 'critico';
}

function hmColor(p, i) {
  const s = p * i;
  if (s <= 4)  return '#bbf7d0';
  if (s <= 9)  return '#fef08a';
  if (s <= 14) return '#fed7aa';
  return '#fecaca';
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
// Acepta el token via header "Authorization: Bearer <idToken>" (fetch normal)
// o via query "?token=<idToken>" (necesario para descargas de PDF, que son
// navegaciones directas del navegador sin headers custom).
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const headerToken = header.startsWith('Bearer ') ? header.slice(7) : null;
    const token = headerToken || req.query.token;
    if (!token) return res.status(401).json({ error: 'No autenticado' });
    await getAuth().verifyIdToken(token);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token invalido o expirado' });
  }
}

// ── ABUSEIPDB ─────────────────────────────────────────────────────────────────
const ipCache = new Map();

async function checkAbuseIPDB(ip) {
  if (!process.env.ABUSEIPDB_KEY) return null;
  const cached = ipCache.get(ip);
  if (cached && Date.now() - cached.ts < 3600000) return cached.data;
  try {
    const r    = await fetch('https://api.abuseipdb.com/api/v2/check?ipAddress=' + encodeURIComponent(ip) + '&maxAgeInDays=90',
      { headers: { Key: process.env.ABUSEIPDB_KEY, Accept: 'application/json' } });
    const json = await r.json();
    if (!json.data) return null;
    const result = {
      score:        json.data.abuseConfidenceScore,
      totalReports: json.data.totalReports,
      country:      json.data.countryCode,
      isp:          json.data.isp,
      isTor:        json.data.isTor,
      usageType:    json.data.usageType
    };
    ipCache.set(ip, { data: result, ts: Date.now() });
    return result;
  } catch (e) { console.error('AbuseIPDB error:', e.message); return null; }
}

// ── GEOLOCALIZACION (ip-api.com, gratuito, sin key) ──────────────────────────
const geoCache = new Map();

async function checkGeoIP(ip) {
  const cached = geoCache.get(ip);
  if (cached && Date.now() - cached.ts < 86400000) return cached.data; // TTL 24h
  try {
    const r    = await fetch('http://ip-api.com/json/' + encodeURIComponent(ip) + '?fields=status,country,countryCode,city,lat,lon,query');
    const json = await r.json();
    if (json.status !== 'success') return null;
    const result = {
      country:     json.country,
      countryCode: json.countryCode,
      city:        json.city,
      lat:         json.lat,
      lon:         json.lon
    };
    geoCache.set(ip, { data: result, ts: Date.now() });
    return result;
  } catch (e) { console.error('GeoIP error:', e.message); return null; }
}

// ── TELEGRAM ──────────────────────────────────────────────────────────────────
const tgCooldown = new Map();

async function sendTelegramAlert(a) {
  const token  = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;

  const key = (a.rule || '') + (a.sourceIp || '');
  const last = tgCooldown.get(key);
  if (last && (Date.now() - last) < 300000) return;
  tgCooldown.set(key, Date.now());

  const ab     = a.abuse || null;
  const abLine = ab ? ('\nAbuseIPDB: ' + ab.score + '% | ' + (ab.country || 'N/A') + (ab.isTor ? ' | TOR' : '')) : '';

  const msg =
    '<b>ALERTA ALTA - SecuMonitor</b>\n' +
    '<b>Regla:</b> <code>' + (a.rule || 'N/A') + '</code>\n' +
    '<b>Detalle:</b> ' + (a.message || 'N/A') + '\n' +
    '<b>IP:</b> <code>' + (a.sourceIp || 'N/A') + '</code>' + abLine + '\n' +
    '<b>Hora:</b> ' + new Date(a.timestamp).toLocaleString('es-CL');

  try {
    const r = await fetch('https://api.telegram.org/bot' + token + '/sendMessage', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ chat_id: chatId, text: msg, parse_mode: 'HTML' })
    });
    const d = await r.json();
    if (d.ok) console.log('Telegram OK -> ' + (a.rule || '') + ' | ' + (a.sourceIp || ''));
    else      console.error('Telegram API error:', d.description);
  } catch (err) { console.error('Telegram fetch error:', err.message); }
}

// ── PROCESS EVENT ─────────────────────────────────────────────────────────────
async function processEvent(evt) {
  await eventsCol.doc(evt.id).set(evt);
  win5m.add(evt);
  const alerts = evaluateEvent(evt, win5m);
  for (const a of alerts) {
    const abuse    = await checkAbuseIPDB(a.sourceIp);
    const geo      = await checkGeoIP(a.sourceIp);
    const alertDoc = Object.assign({}, a, {
      timestamp: new Date().toISOString(),
      status:    'nuevo'
    });
    if (abuse) alertDoc.abuse = abuse;
    if (geo)   alertDoc.geo   = geo;
    await alertsCol.add(alertDoc);
    console.log('[' + a.severity.toUpperCase() + '] ' + a.message + (abuse ? ' | AbuseIPDB: ' + abuse.score + '%' : ''));
    if ((a.severity || '').toLowerCase() === 'alta') await sendTelegramAlert(alertDoc);
  }
  return alerts;
}

// ── PDF TEMPLATE ──────────────────────────────────────────────────────────────
const C = {
  bg: '#0d1b2a', navy: '#1b2838', accent: '#00b4d8', accent2: '#3b82f6',
  white: '#ffffff', light: '#f0f4f8', border: '#dde3ea',
  text: '#1a1a2e', muted: '#6b7280', dim: '#4a6580',
  alta: '#ef4444', media: '#f59e0b', baja: '#3b82f6', ok: '#22c55e', purple: '#6366f1'
};

function PW(doc) { return doc.page.width; }
function PH(doc) { return doc.page.height; }

function cover(doc, title, period, date) {
  doc.rect(0, 0, PW(doc), PH(doc)).fill(C.bg);
  doc.rect(0, 0, PW(doc), 5).fill(C.accent);
  for (let i = 0; i < 6; i++) doc.rect(0, 210 + i * 6, PW(doc), 0.8).fill('#0d2035');
  doc.fontSize(8).fillColor(C.accent).font('Helvetica').text('SISTEMA DE MONITOREO DE SEGURIDAD', 0, PH(doc) * 0.30, { align: 'center', width: PW(doc) });
  doc.fontSize(30).fillColor(C.white).font('Helvetica-Bold').text('SecuMonitor', 0, PH(doc) * 0.35, { align: 'center', width: PW(doc) });
  doc.rect(PW(doc) / 2 - 50, PH(doc) * 0.435, 100, 2).fill(C.accent);
  doc.fontSize(16).fillColor(C.accent).font('Helvetica').text(title, 0, PH(doc) * 0.46, { align: 'center', width: PW(doc) });
  if (period) doc.fontSize(10).fillColor('#8ba3c1').text(period, 0, PH(doc) * 0.53, { align: 'center', width: PW(doc) });
  if (date)   doc.fontSize(9).fillColor(C.muted).text(date, 0, PH(doc) * 0.57, { align: 'center', width: PW(doc) });
  doc.rect(0, PH(doc) - 44, PW(doc), 44).fill('#06101a');
  doc.fontSize(8).fillColor(C.dim).text('DOCUMENTO CONFIDENCIAL - SOLO USO INTERNO', 0, PH(doc) - 26, { align: 'center', width: PW(doc) });
}

function pageHeader(doc, sub) {
  doc.rect(0, 0, PW(doc), 47).fill(C.bg);
  doc.rect(0, 47, PW(doc), 3).fill(C.accent);
  doc.fontSize(13).fillColor(C.white).font('Helvetica-Bold').text('SECUMONITOR', 28, 14);
  if (sub) doc.fontSize(8).fillColor(C.accent).font('Helvetica').text('  >  ' + sub.toUpperCase(), 120, 18);
  doc.fontSize(8).fillColor(C.muted).text(new Date().toLocaleDateString('es-CL'), 0, 19, { align: 'right', width: PW(doc) - 28 });
  doc.y = 64;
}

function pageFooter(doc, n) {
  doc.rect(0, PH(doc) - 28, PW(doc), 28).fill(C.bg);
  doc.rect(0, PH(doc) - 31, PW(doc), 3).fill(C.accent2);
  doc.fontSize(7).fillColor(C.dim).font('Helvetica').text('SECUMONITOR - INFORME CONFIDENCIAL', 28, PH(doc) - 17);
  doc.fillColor(C.accent).text('PAG. ' + n, 0, PH(doc) - 17, { align: 'right', width: PW(doc) - 28 });
}

function sectionTitle(doc, title) {
  const y = doc.y;
  doc.rect(28, y, 4, 18).fill(C.accent);
  doc.fontSize(10).fillColor(C.text).font('Helvetica-Bold').text(title.toUpperCase(), 40, y + 3);
  doc.font('Helvetica');
  doc.y = y + 24;
  doc.rect(28, doc.y, PW(doc) - 56, 0.5).fill(C.border);
  doc.y += 10;
}

function statBoxes(doc, items) {
  const n   = items.length;
  const gap = 7;
  const bW  = Math.floor((PW(doc) - 56 - gap * (n - 1)) / n);
  const bH  = 54;
  const bY  = doc.y;
  items.forEach(function(item, i) {
    const x = 28 + i * (bW + gap);
    doc.rect(x, bY, bW, bH).fill(C.light);
    doc.rect(x, bY, 4, bH).fill(item.color || C.accent);
    doc.fontSize(8).fillColor(C.muted).font('Helvetica').text(item.label.toUpperCase(), x + 10, bY + 10, { width: bW - 14 });
    doc.fontSize(22).fillColor(C.text).font('Helvetica-Bold').text(String(item.value), x + 10, bY + 24, { width: bW - 14 });
    doc.font('Helvetica');
  });
  doc.y = bY + bH + 16;
}

function drawTable(doc, headers, rows, widths, pg, sub) {
  const sx = 28, tW = PW(doc) - 56, rH = 22, hH = 27;
  let y = doc.y;
  function drawHead() {
    doc.rect(sx, y, tW, hH).fill(C.navy);
    let x = sx;
    doc.fontSize(8).fillColor(C.white).font('Helvetica-Bold');
    headers.forEach(function(h, i) { doc.text(h.toUpperCase(), x + 6, y + 9, { width: widths[i] - 10, ellipsis: true, lineBreak: false }); x += widths[i]; });
    y += hH;
    doc.font('Helvetica');
  }
  drawHead();
  rows.forEach(function(row, ri) {
    if (y + rH > PH(doc) - 45) { pageFooter(doc, pg.n); doc.addPage(); pg.n++; pageHeader(doc, sub); y = doc.y; drawHead(); }
    doc.rect(sx, y, tW, rH).fill(ri % 2 === 0 ? C.white : C.light);
    doc.fontSize(8.5).fillColor(C.text).font('Helvetica');
    let x = sx;
    row.forEach(function(cell, ci) { doc.text(String(cell != null ? cell : 'N/A'), x + 6, y + 6, { width: widths[ci] - 10, ellipsis: true, lineBreak: false }); x += widths[ci]; });
    y += rH;
  });
  doc.rect(sx, y, tW, 0.5).fill(C.border);
  doc.y = y + 14;
}

function riskBlock(doc, r, idx, pg, sub) {
  const sx = 28, bW = PW(doc) - 56, phW = (bW - 6) / 2, phH = 70, totalH = 34 + phH * 2 + 12 + 18;
  if (doc.y + totalH > PH(doc) - 45) { pageFooter(doc, pg.n); doc.addPage(); pg.n++; pageHeader(doc, sub); }
  const lvlColor = { bajo: C.ok, medio: C.media, alto: C.media, critico: C.alta };
  const color    = lvlColor[r.level || 'bajo'] || C.baja;
  const y0       = doc.y;
  doc.rect(sx, y0, bW, 28).fill(C.navy);
  doc.rect(sx, y0, 5, 28).fill(color);
  doc.fontSize(11).fillColor(C.white).font('Helvetica-Bold').text((idx + 1) + '. ' + (r.name || 'Sin nombre'), sx + 14, y0 + 8, { width: bW - 120, lineBreak: false });
  doc.fontSize(9).fillColor(color).text((r.level || 'bajo').toUpperCase(), sx + bW - 90, y0 + 10, { width: 80, align: 'right' });
  doc.font('Helvetica');
  const red    = r.score ? Math.round((1 - (r.residualScore || 0) / r.score) * 100) : 0;
  const phases = [
    { label: 'FASE 1 - IDENTIFICACION', txt: 'Categoria: ' + (r.category || 'N/A') + '\nActivos: ' + (r.assets || 'N/A') + '\n' + (r.description || '') },
    { label: 'FASE 2 - ANALISIS',       txt: 'Probabilidad: ' + (r.probability || 'N/A') + '/5  x  Impacto: ' + (r.impact || 'N/A') + '/5\nPuntuacion: ' + (r.score || 'N/A') + '  ->  ' + (r.level || 'N/A').toUpperCase() },
    { label: 'FASE 3 - MITIGACION',     txt: 'Estrategia: ' + (r.mitigation || 'No definida') + '\nResponsable: ' + (r.responsible || 'N/A') + '  |  ' + (r.deadline || 'N/A') + '\nEstado: ' + (r.status || 'pendiente').replace('_', ' ') },
    { label: 'FASE 4 - RIESGO RESIDUAL',txt: 'Prob: ' + (r.residualProbability || 'N/A') + '/5  x  Impacto: ' + (r.residualImpact || 'N/A') + '/5\nPuntuacion residual: ' + (r.residualScore || 'N/A') + '  ->  ' + (r.residualLevel || 'N/A').toUpperCase() + '\nReduccion: ' + red + '%' }
  ];
  const gridY = y0 + 34;
  [[0,0],[1,0],[0,1],[1,1]].forEach(function(pos, pi) {
    const px = sx + pos[0] * (phW + 6), py = gridY + pos[1] * (phH + 6);
    doc.rect(px, py, phW, phH).fill(C.light);
    doc.rect(px, py, 3, phH).fill(C.accent2);
    doc.fontSize(7).fillColor(C.accent).font('Helvetica-Bold').text(phases[pi].label, px + 8, py + 8, { width: phW - 14, lineBreak: false });
    doc.fontSize(8.5).fillColor(C.text).font('Helvetica').text(phases[pi].txt, px + 8, py + 20, { width: phW - 14, height: phH - 24, ellipsis: true });
  });
  doc.y = gridY + 2 * (phH + 6) + 4;
  doc.rect(sx, doc.y, bW, 0.5).fill(C.border);
  doc.y += 13;
}

// ── EXPRESS ───────────────────────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ── ROUTES ────────────────────────────────────────────────────────────────────
app.get('/api/health', function(req, res) { res.json({ status: 'ok', ts: new Date().toISOString() }); });

// Todo lo que sigue requiere sesion valida de Firebase Auth
app.use('/api', requireAuth);

app.post('/api/events', async function(req, res) {
  try {
    const evt = Object.assign({ id: 'evt_' + Date.now() + '_' + Math.floor(Math.random() * 9999), timestamp: new Date().toISOString() }, req.body);
    const alerts = await processEvent(evt);
    res.status(201).json({ evt: evt, alertsGenerated: alerts.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/events/simulate', async function(req, res) {
  try {
    const evts = [].concat(Array.from({ length: 5 }, function() { return generateEvent(); }), generateBruteForceBurst(), generatePortScanBurst());
    let total = 0;
    for (const e of evts) total += (await processEvent(e)).length;
    res.json({ eventsGenerated: evts.length, alertsGenerated: total });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/events', async function(req, res) {
  try {
    const snap = await eventsCol.orderBy('timestamp', 'desc').limit(parseInt(req.query.limit) || 50).get();
    res.json(snap.docs.map(function(d) { return d.data(); }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/alerts', async function(req, res) {
  try {
    const snap = await alertsCol.orderBy('timestamp', 'desc').limit(parseInt(req.query.limit) || 50).get();
    res.json(snap.docs.map(function(d) { return Object.assign({ id: d.id }, d.data()); }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ip-check/:ip', async function(req, res) {
  try {
    const result = await checkAbuseIPDB(req.params.ip);
    if (!result) return res.status(503).json({ error: 'AbuseIPDB no disponible - configura ABUSEIPDB_KEY' });
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/geo-check/:ip', async function(req, res) {
  try {
    const result = await checkGeoIP(req.params.ip);
    if (!result) return res.status(503).json({ error: 'Geolocalizacion no disponible para esta IP' });
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/telegram/test', async function(req, res) {
  try {
    await sendTelegramAlert({ rule: 'test', message: 'Mensaje de prueba desde SecuMonitor. Todo funciona correctamente.', sourceIp: '127.0.0.1', severity: 'alta', timestamp: new Date().toISOString() });
    res.json({ ok: true, message: 'Mensaje enviado - revisa tu bot de Telegram' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/stats', async function(req, res) {
  try {
    const es = await eventsCol.where('timestamp', '>=', new Date(Date.now() - 86400000).toISOString()).get();
    const as = await alertsCol.where('timestamp', '>=', new Date(Date.now() - 604800000).toISOString()).get();
    const evtHr = Array(24).fill(0);
    es.docs.forEach(function(d) { const h = Math.floor((Date.now() - new Date(d.data().timestamp)) / 3600000); if (h < 24) evtHr[23 - h]++; });
    const alta = Array(7).fill(0), media = Array(7).fill(0), baja = Array(7).fill(0), lbls = [];
    for (let i = 6; i >= 0; i--) lbls.push(new Date(Date.now() - i * 86400000).toLocaleDateString('es-CL', { weekday: 'short', day: 'numeric' }));
    as.docs.forEach(function(d) {
      const data = d.data(), di = Math.floor((Date.now() - new Date(data.timestamp)) / 86400000);
      if (di < 7) { const idx = 6 - di, s = (data.severity || 'baja').toLowerCase(); if (s === 'alta') alta[idx]++; else if (s === 'media') media[idx]++; else baja[idx]++; }
    });
    const hourLabels = [];
    for (let j = 0; j < 24; j++) hourLabels.push(new Date(Date.now() - (23 - j) * 3600000).getHours() + ':00');
    res.json({ eventsByHour: { labels: hourLabels, data: evtHr }, alertsByDay: { labels: lbls, alta: alta, media: media, baja: baja } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/risks', async function(req, res) {
  try {
    const snap = await risksCol.orderBy('createdAt', 'desc').get();
    res.json(snap.docs.map(function(d) { return Object.assign({ id: d.id }, d.data()); }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/risks', async function(req, res) {
  try {
    const d = req.body, score = (d.probability || 1) * (d.impact || 1), rScore = (d.residualProbability || d.probability || 1) * (d.residualImpact || d.impact || 1);
    const risk = Object.assign({}, d, { score: score, level: riskLevel(score), residualScore: rScore, residualLevel: riskLevel(rScore), status: d.status || 'pendiente', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
    const ref = await risksCol.add(risk);
    res.status(201).json(Object.assign({ id: ref.id }, risk));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/risks/:id', async function(req, res) {
  try {
    const d = req.body, upd = Object.assign({}, d, { updatedAt: new Date().toISOString() });
    if (d.probability && d.impact) { upd.score = d.probability * d.impact; upd.level = riskLevel(upd.score); }
    if (d.residualProbability && d.residualImpact) { upd.residualScore = d.residualProbability * d.residualImpact; upd.residualLevel = riskLevel(upd.residualScore); }
    await risksCol.doc(req.params.id).update(upd);
    res.json(Object.assign({ id: req.params.id }, upd));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/risks/:id', async function(req, res) {
  try { await risksCol.doc(req.params.id).delete(); res.json({ deleted: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PDF: MONITORING ───────────────────────────────────────────────────────────
app.get('/api/reports/generate', async function(req, res) {
  try {
    const range = req.query.range || '7d';
    const days  = { '1d': 1, '7d': 7, '30d': 30 }[range] || 7;
    const since = new Date(Date.now() - days * 86400000).toISOString();
    const lbl   = { '1d': 'Ultimas 24 horas', '7d': 'Ultimos 7 dias', '30d': 'Ultimos 30 dias' }[range] || '';
    const eS    = await eventsCol.where('timestamp', '>=', since).get();
    const aS    = await alertsCol.where('timestamp', '>=', since).get();
    const events = eS.docs.map(function(d) { return d.data(); });
    const alerts = aS.docs.map(function(d) { return d.data(); });
    const cnt = { alta: 0, media: 0, baja: 0 }, ips = {};
    alerts.forEach(function(a) {
      const s = (a.severity || 'baja').toLowerCase();
      if (cnt[s] !== undefined) cnt[s]++;
      if (a.sourceIp) ips[a.sourceIp] = (ips[a.sourceIp] || 0) + 1;
    });
    const topIps = Object.entries(ips).sort(function(a, b) { return b[1] - a[1]; }).slice(0, 8);
    const altas  = alerts.filter(function(a) { return (a.severity || '').toLowerCase() === 'alta'; });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="secumonitor-monitoreo-' + new Date().toISOString().slice(0, 10) + '.pdf"');
    const doc = new PDF({ margin: 0, size: 'A4' });
    doc.pipe(res);
    const pg = { n: 0 };

    cover(doc, 'Informe de Monitoreo de Seguridad', lbl, 'Generado el ' + new Date().toLocaleString('es-CL'));
    doc.addPage(); pg.n++;
    pageHeader(doc, 'Monitoreo de Seguridad');
    sectionTitle(doc, 'Resumen Ejecutivo');
    statBoxes(doc, [
      { label: 'Eventos Totales', value: events.length, color: C.accent2 },
      { label: 'Alertas Totales', value: alerts.length, color: C.purple  },
      { label: 'Severidad Alta',  value: cnt.alta,      color: C.alta    },
      { label: 'Severidad Media', value: cnt.media,     color: C.media   }
    ]);

    if (topIps.length) {
      sectionTitle(doc, 'Top IPs Sospechosas');
      drawTable(doc, ['IP Origen', 'Alertas', 'Abuse Score', 'Pais', 'ISP'],
        topIps.map(function(entry) {
          const ip = entry[0], n = entry[1];
          let ab = null;
          for (let i = 0; i < alerts.length; i++) { if (alerts[i].sourceIp === ip && alerts[i].abuse) { ab = alerts[i].abuse; break; } }
          return [ip, n, ab ? ab.score + '%' : 'N/A', ab ? (ab.country || 'N/A') : 'N/A', ab ? (ab.isp || 'N/A') : 'N/A'];
        }),
        [148, 50, 72, 50, 215], pg, 'Monitoreo de Seguridad');
    }

    if (altas.length) {
      if (doc.y > PH(doc) - 130) { pageFooter(doc, pg.n); doc.addPage(); pg.n++; pageHeader(doc, 'Monitoreo de Seguridad'); }
      sectionTitle(doc, 'Alertas de Severidad Alta');
      drawTable(doc, ['Regla', 'Tecnica MITRE', 'Mensaje', 'IP Origen', 'Fecha'],
        altas.map(function(a) {
          const mt = a.mitre ? (a.mitre.id + ' - ' + a.mitre.name) : 'N/A';
          return [a.rule || 'N/A', mt, a.message || 'N/A', a.sourceIp || 'N/A', new Date(a.timestamp).toLocaleString('es-CL')];
        }),
        [80, 130, 132, 90, 103], pg, 'Monitoreo de Seguridad');
    }

    pageFooter(doc, pg.n);
    doc.end();
  } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

// ── PDF: RISKS ────────────────────────────────────────────────────────────────
app.get('/api/reports/risks', async function(req, res) {
  try {
    const snap  = await risksCol.orderBy('createdAt', 'asc').get();
    const risks = snap.docs.map(function(d) { return Object.assign({ id: d.id }, d.data()); });
    const lvlC  = { bajo: 0, medio: 0, alto: 0, critico: 0 };
    risks.forEach(function(r) { if (lvlC[r.level] !== undefined) lvlC[r.level]++; });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="secumonitor-riesgos-' + new Date().toISOString().slice(0, 10) + '.pdf"');
    const doc = new PDF({ margin: 0, size: 'A4' });
    doc.pipe(res);
    const pg = { n: 0 };

    cover(doc, 'Informe de Gestion de Riesgos', risks.length + ' riesgo(s) registrado(s)', 'Generado el ' + new Date().toLocaleString('es-CL'));
    doc.addPage(); pg.n++;
    pageHeader(doc, 'Gestion de Riesgos');
    sectionTitle(doc, 'Resumen Ejecutivo');
    statBoxes(doc, [
      { label: 'Total Riesgos', value: risks.length,           color: C.accent },
      { label: 'Critico',       value: lvlC.critico,           color: C.alta   },
      { label: 'Alto',          value: lvlC.alto,              color: C.media  },
      { label: 'Medio / Bajo',  value: lvlC.medio + lvlC.bajo, color: C.ok     }
    ]);

    sectionTitle(doc, 'Mapa de Calor - Probabilidad x Impacto');
    const csz = 42, hmX = 80, hmY = doc.y;
    for (let p = 5; p >= 1; p--) {
      doc.fontSize(9).fillColor(C.muted).text(String(p), hmX - 22, hmY + (5 - p) * csz + csz / 2 - 6);
      for (let imp = 1; imp <= 5; imp++) {
        const cx = hmX + (imp - 1) * csz, cy = hmY + (5 - p) * csz;
        doc.rect(cx, cy, csz - 2, csz - 2).fill(hmColor(p, imp));
        doc.fontSize(8).fillColor('#555').text(String(p * imp), cx + 4, cy + 5);
      }
    }
    for (let ii = 1; ii <= 5; ii++) doc.fontSize(9).fillColor(C.muted).text(String(ii), hmX + (ii - 1) * csz + csz / 2 - 4, hmY + 5 * csz + 6);
    doc.fontSize(8).fillColor(C.muted).text('Impacto ->', hmX, hmY + 5 * csz + 20, { width: 5 * csz, align: 'center' });
    risks.forEach(function(r, idx) {
      if (!r.probability || !r.impact) return;
      const dotX = hmX + (r.impact - 1) * csz + csz / 2, dotY = hmY + (5 - r.probability) * csz + csz / 2;
      doc.circle(dotX, dotY, 10).fill(C.navy);
      doc.fontSize(7).fillColor(C.white).text(String(idx + 1), dotX - 9, dotY - 5, { width: 18, align: 'center' });
    });
    [['#bbf7d0','Bajo'],['#fef08a','Medio'],['#fed7aa','Alto'],['#fecaca','Critico']].forEach(function(leg, i) {
      const lx = hmX + i * 90;
      doc.rect(lx, hmY + 5 * csz + 34, 10, 10).fill(leg[0]);
      doc.fontSize(8).fillColor(C.muted).text(leg[1], lx + 14, hmY + 5 * csz + 36);
    });
    doc.y = hmY + 5 * csz + 56;

    pageFooter(doc, pg.n);
    doc.addPage(); pg.n++;
    pageHeader(doc, 'Detalle de Riesgos');
    sectionTitle(doc, 'Detalle de Riesgos por Fase');
    risks.forEach(function(r, idx) { riskBlock(doc, r, idx, pg, 'Detalle de Riesgos'); });
    pageFooter(doc, pg.n);
    doc.end();
  } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

// ── START ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, function() { console.log('SecuMonitor corriendo en http://localhost:' + PORT); });
