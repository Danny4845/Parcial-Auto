/* ══════════════════════════════════════════════════════════════════
   SCADA — Estacionamiento Automatizado · III Parcial
   app.js — Sistema Unificado: Auth, PBKDF2, HMAC, HMI Canvas, Admin
   Equipo: Daniel Colmenares & Hernaldo Pérez Roa
   ══════════════════════════════════════════════════════════════════ */

'use strict';

/* ═══════════════════════════════════════════════════════════════════
   1. CREDENCIALES & USUARIOS DEMO (PBKDF2 · 100k iter · SHA-256)
   ═══════════════════════════════════════════════════════════════════ */
const USUARIOS_DEMO = [
  { nombre: 'operador1',  rol: 'Operador',  salt: '2JtnQIWcXshs7ACnm/WLIg==', hash: '0o27iaUjLJI0dky6k1dDlX0FYDKmDSu9pf/EG9zVMdU=' },
  { nombre: 'ingeniero1', rol: 'Ingeniero', salt: 'SgR45c2jLqkLntsarS5lOw==', hash: '1Vo6oGqM3Kc1wHnFk213ijAdjpy/9ALfbWts6AgO5lg=' },
  { nombre: 'gerente1',   rol: 'Gerente',   salt: '/bqIJqzIw+av+Gya6nS4nA==', hash: 'F3ukZ6SQYi2FlGTU7DSCYMktQXCuVDSrWokXkCFS7Ik=' }
];

let USUARIOS_BD   = [...USUARIOS_DEMO];
let usandoDemo    = true;
const CODIGO_ACT  = 'admin2026';
const LS_KEY      = 'scada_usuarios_registrados';

/* ═══════════════════════════════════════════════════════════════════
   2. CRIPTOGRAFÍA — HMAC & PBKDF2 (Web Crypto API)
   ═══════════════════════════════════════════════════════════════════ */
let hmacKey = null;

async function initHmacKey() {
  hmacKey = await crypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  );
}

async function signCommand(accion) {
  const nonce = crypto.randomUUID(), timestamp = Date.now();
  const payload = JSON.stringify({ accion, timestamp, nonce });
  const sig = await crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode(payload));
  return { payload, firma: btoa(String.fromCharCode(...new Uint8Array(sig))) };
}

async function verifyCommand(payload, firma) {
  const sigBytes = Uint8Array.from(atob(firma), c => c.charCodeAt(0));
  return crypto.subtle.verify('HMAC', hmacKey, sigBytes, new TextEncoder().encode(payload));
}

function b64ToBuf(b64) {
  const bin = atob(b64), buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function bufToB64(buffer) { return btoa(String.fromCharCode(...new Uint8Array(buffer))); }

async function derivePBKDF2(password, saltB64) {
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: b64ToBuf(saltB64), iterations: 100_000, hash: 'SHA-256' },
    km, 256
  );
  return bufToB64(bits);
}

async function hashPassword(password) {
  const saltBuf = crypto.getRandomValues(new Uint8Array(16));
  const salt = bufToB64(saltBuf.buffer);
  const hash = await derivePBKDF2(password, salt);
  return { salt, hash };
}

async function autenticar(nombre, password) {
  const u = USUARIOS_BD.find(u => u.nombre === nombre.trim().toLowerCase());
  if (!u) return null;
  const h = await derivePBKDF2(password, u.salt);
  return h === u.hash ? u : null;
}

/* LocalStorage Manager */
function cargarUsuariosLocales() {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return;
    const guardados = JSON.parse(raw);
    if (!Array.isArray(guardados)) return;
    const setNombres = new Set(USUARIOS_BD.map(u => u.nombre));
    for (const u of guardados) {
      if (!setNombres.has(u.nombre)) USUARIOS_BD.push(u);
    }
    if (guardados.length > 0) actualizarSourceLabel();
  } catch (_) {}
}

function persistirUsuariosLocales() {
  const reg = USUARIOS_BD.filter(u => !USUARIOS_DEMO.some(d => d.nombre === u.nombre));
  localStorage.setItem(LS_KEY, JSON.stringify(reg));
}

async function registrarUsuario(nombre, rol, password) {
  const n = nombre.toLowerCase().trim();
  if (USUARIOS_BD.some(u => u.nombre === n)) throw new Error(`El usuario "${n}" ya existe`);
  const { salt, hash } = await hashPassword(password);
  const u = { nombre: n, rol, salt, hash, id: crypto.randomUUID(), creado: new Date().toISOString() };
  USUARIOS_BD.push(u);
  persistirUsuariosLocales();
  return u;
}

function evaluarFuerza(pwd) {
  let s = 0;
  if (pwd.length >= 8) s++; if (pwd.length >= 12) s++;
  if (/[A-Z]/.test(pwd)) s++; if (/[0-9]/.test(pwd)) s++; if (/[^A-Za-z0-9]/.test(pwd)) s++;
  const niveles = [
    { pct: 0, color: 'transparent', label: '' },
    { pct: 20, color: '#ff1744', label: 'Muy débil' },
    { pct: 40, color: '#ff6d00', label: 'Débil' },
    { pct: 60, color: '#ffd740', label: 'Aceptable' },
    { pct: 80, color: '#69f0ae', label: 'Fuerte' },
    { pct: 100, color: '#00e676', label: 'Muy fuerte ✅' }
  ];
  return niveles[Math.min(s, 5)];
}

/* ═══════════════════════════════════════════════════════════════════
   3. ESTADO GLOBAL DE SIMULACIÓN Y SCADA
   ═══════════════════════════════════════════════════════════════════ */
let sesion = null;

const EST = {
  sistemaActivo: false,
  plazasOcupadas: 0,
  semEntrada:  'rojo',
  semSalida:   'rojo',
  semPeatonal: 'rojo',
  portonEstado: 'cerrado',
  E1: false, E2: false, S1: false, S2: false,
  FCA: false, FCC: true,
  demandaEntrada: false, demandaSalida: false,
  portonParaEntrada: false, portonParaSalida: false,
  spTimer: null, _spBarInterval: null, _paTimer: null, _paOffTimer: null,
  spSegRestantes: 40, spFase: 'rojo', spVerdeMs: 20000, spRojoMs: 40000,
  paActivo: false,
  vehiculos: [],
  totalEntradas: 0, totalSalidas: 0, ciclosPorton: 0
};

/* Log de auditoría */
const auditEntries = [];
function log(msg, tipo = 'info') {
  const ts = new Date().toLocaleTimeString('es-VE', { hour12: false });
  auditEntries.push({ ts, msg, tipo, rol: sesion?.rol ?? '—' });
  const el = document.getElementById('auditLog');
  if (!el) return;
  const div = document.createElement('div');
  div.className = `log-entry ${tipo}`;
  div.textContent = `[${ts}] ${sesion?.rol?.[0] ?? '?'} • ${msg}`;
  el.prepend(div);
  while (el.children.length > 60) el.removeChild(el.lastChild);
}

/* RBAC Permisos */
const PERMISOS = {
  Operador:  ['inicio', 'reset', 'simE1', 'simS1'],
  Ingeniero: ['inicio', 'reset', 'simE1', 'simS1', 'forzarPorton', 'ajustarTiempos', 'verLog'],
  Gerente:   ['verLog', 'verMetricas']
};
function puedeDo(accion) { return sesion && (PERMISOS[sesion.rol] || []).includes(accion); }

/* ═══════════════════════════════════════════════════════════════════
   4. CANVAS SCADA (Dibujo cenital)
   ═══════════════════════════════════════════════════════════════════ */
const canvas = document.getElementById('scadaCanvas');
const ctx    = canvas.getContext('2d');

function resizeCanvas() {
  const wr = canvas.parentElement;
  if (!wr) return;
  canvas.width  = Math.min(wr.clientWidth  - 16, 720);
  canvas.height = Math.min(wr.clientHeight - 20, 520);
}

function drawScene() {
  const W = canvas.width, H = canvas.height;
  if (!W || !H) return;
  ctx.clearRect(0, 0, W, H);

  const gW  = W * 0.36;
  const cwX = gW, cwW = W * 0.22, cwX2 = cwX + cwW;
  const entY = H * 0.36, salY = H * 0.64, lH = H * 0.13;

  // Fondo garaje & calle
  ctx.fillStyle = '#0e1420'; ctx.fillRect(0, 0, W, H);
  ctx.fillStyle = '#080d18'; ctx.fillRect(0, 0, gW, H);

  // Borde Naranja Garaje
  ctx.strokeStyle = '#ff8c00'; ctx.lineWidth = 3;
  ctx.beginPath(); ctx.moveTo(gW, 0); ctx.lineTo(gW, H); ctx.stroke();
  ctx.strokeRect(1.5, 1.5, gW - 1.5, H - 3); ctx.lineWidth = 1;

  drawParkingGrid(gW, H);

  ctx.fillStyle = '#ff8c0055'; ctx.font = `bold ${Math.floor(W * 0.022)}px system-ui`;
  ctx.textAlign = 'center'; ctx.fillText('100 PLAZAS', gW / 2, H / 2);

  drawCarril(0, entY, gW, lH, '#1a2d44', '← ENTRADA', '#448aff40', 'left');
  drawCarril(0, salY, gW, lH, '#1a2d35', 'SALIDA →',  '#ff910040', 'right');

  ctx.fillStyle = '#1e2840'; ctx.fillRect(cwX2, 0, W - cwX2, H);

  drawDiagonalLane(cwX2, entY, W, H * 0.08, lH, '#1a2d44', '← ENTRADA', '#448aff30');
  drawDiagonalLane(cwX2, salY, W, H * 0.92, lH, '#1a2d35', 'SALIDA →',  '#ff910030');

  drawCrosswalk(cwX, entY - lH / 2, cwW, lH + (salY - entY) + lH);
  drawPorton(cwX, entY - lH / 2, cwW, lH + (salY - entY) + lH);

  drawTrafficLight(cwX + cwW * 0.18, H * 0.03, 'S.P.', EST.semPeatonal, false);
  drawTrafficLight(cwX + cwW * 0.72, H * 0.03, 'S.E.', EST.semEntrada, true);
  drawTrafficLight(cwX + cwW * 0.45, H * 0.80, 'S.S.', EST.semSalida, false);

  const e1x = cwX2 + (W - cwX2) * 0.55, e1y = entY;
  const e2x = gW * 0.82, e2y = entY;
  const s1x = gW * 0.82, s1y = salY;
  const s2x = cwX2 + (W - cwX2) * 0.55, s2y = salY;

  drawSensor(e1x, e1y, 'E1', EST.E1, '#448aff');
  drawSensor(e2x, e2y, 'E2', EST.E2, '#448aff');
  drawSensor(s1x, s1y, 'S1', EST.S1, '#ff9100');
  drawSensor(s2x, s2y, 'S2', EST.S2, '#ff9100');

  ctx.font = `bold ${Math.floor(W * 0.016)}px monospace`; ctx.textAlign = 'left';
  ctx.fillStyle = EST.FCA ? '#00e676' : '#2a3f5e'; ctx.fillText('FCA', cwX + 4, entY - lH / 2 - 5);
  ctx.fillStyle = EST.FCC ? '#00e676' : '#2a3f5e'; ctx.fillText('FCC', cwX + 4, salY + lH / 2 + 14);

  for (const v of EST.vehiculos) drawVehiculo(v);
  drawPaIndicator(W, H);
  drawCounter(W, H);
}

function drawParkingGrid(gW, H) {
  const cols = 5, rows = 3;
  const margin = gW * 0.06;
  const areaW = gW - margin * 2;
  const spotW = (areaW - (cols - 1) * 4) / cols;
  const spotH = (H * 0.30 - (rows - 1) * 4) / rows;

  let idx = 0;
  [H * 0.12, H * 0.56].forEach(startY => {
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const x = margin + c * (spotW + 4), y = startY + r * (spotH + 4);
        const ocu = idx < EST.plazasOcupadas;
        ctx.fillStyle   = ocu ? '#ff17441a' : '#0d1a2a';
        ctx.strokeStyle = ocu ? '#ff174455' : '#1e2d40';
        roundRect(ctx, x, y, spotW, spotH, 3); ctx.fill(); ctx.stroke();
        if (ocu) {
          ctx.fillStyle = '#ff444466';
          roundRect(ctx, x + spotW * 0.1, y + spotH * 0.15, spotW * 0.8, spotH * 0.7, 2); ctx.fill();
        }
        idx++;
      }
    }
  });
}

function drawCarril(x, centerY, w, h, fillColor, label, labelColor, dir) {
  ctx.fillStyle = fillColor; ctx.fillRect(x, centerY - h / 2, w, h);
  ctx.strokeStyle = '#ffffff08'; ctx.lineWidth = 1; ctx.setLineDash([12, 10]);
  ctx.beginPath(); ctx.moveTo(x, centerY); ctx.lineTo(x + w, centerY); ctx.stroke(); ctx.setLineDash([]);
  ctx.font = `bold ${Math.floor(h * 0.28)}px system-ui`; ctx.fillStyle = labelColor;
  ctx.textAlign = dir === 'left' ? 'left' : 'right';
  ctx.fillText(label, dir === 'left' ? x + w * 0.08 : x + w * 0.92, centerY + h * 0.12);
}

function drawDiagonalLane(startX, startY, endX, endY, lH, fillColor, label, labelColor) {
  ctx.beginPath();
  ctx.moveTo(startX, startY - lH / 2); ctx.lineTo(endX, endY - lH);
  ctx.lineTo(endX, endY + lH); ctx.lineTo(startX, startY + lH / 2); ctx.closePath();
  ctx.fillStyle = fillColor; ctx.fill();
}

function drawCrosswalk(x, y, w, h) {
  ctx.fillStyle = '#151f30'; ctx.fillRect(x, y, w, h);
  const stripeH = h / 13, active = EST.semPeatonal === 'verde';
  for (let i = 0; i < 7; i++) {
    ctx.fillStyle = active ? '#e8f0fe18' : '#e8f0fe0e';
    ctx.fillRect(x + w * 0.08, y + i * stripeH * 2, w * 0.84, stripeH);
  }
  ctx.strokeStyle = '#2a3f5e'; ctx.lineWidth = 1.5; ctx.strokeRect(x, y, w, h);
}

function drawPorton(x, y, w, h) {
  const barCount = 6;
  let apertura = EST.portonEstado === 'abierto' ? 1 : (EST.portonEstado === 'abriendo' || EST.portonEstado === 'cerrando') ? 0.55 : 0;
  const color = EST.portonEstado === 'cerrado' ? '#ff1744' : EST.portonEstado === 'abierto' ? '#00e676' : '#ffd740';

  ctx.fillStyle = '#2a3f5e';
  ctx.fillRect(x + w * 0.1, y, w * 0.05, h); ctx.fillRect(x + w * 0.85, y, w * 0.05, h);

  const barW = (w * 0.65) / barCount, barStartX = x + w * 0.175, barH = h * (1 - apertura);
  for (let i = 0; i < barCount; i++) {
    ctx.fillStyle = color + 'cc'; ctx.shadowColor = color; ctx.shadowBlur = 6;
    roundRect(ctx, barStartX + i * barW, y, barW * 0.65, barH, 2); ctx.fill(); ctx.shadowBlur = 0;
  }

  ctx.font = `bold ${Math.floor(w * 0.14)}px system-ui`; ctx.textAlign = 'center'; ctx.fillStyle = color;
  const estado = { cerrado: '🔒', abriendo: '⬆', abierto: '✓', cerrando: '⬇' };
  ctx.fillText(estado[EST.portonEstado], x + w / 2, y + h / 2);
}

function drawTrafficLight(x, y, label, estado, hasAzul) {
  const R = canvas.width * 0.020, pad = R * 0.6;
  const lights = hasAzul
    ? [{ color: '#ff1744', on: estado === 'rojo' }, { color: '#00e676', on: estado === 'verde' }, { color: '#448aff', on: estado === 'azul' }]
    : [{ color: '#ff1744', on: estado === 'rojo' }, { color: '#00e676', on: estado === 'verde' }];

  const bH = pad * 2 + lights.length * R * 2 + (lights.length - 1) * pad, bW = R * 2 + pad * 2;

  ctx.fillStyle = '#111b2e'; roundRect(ctx, x - bW / 2, y, bW, bH, 5); ctx.fill();
  ctx.strokeStyle = '#2a3f5e'; ctx.lineWidth = 1.5; roundRect(ctx, x - bW / 2, y, bW, bH, 5); ctx.stroke();

  lights.forEach((l, i) => {
    const ly = y + pad + i * (R * 2 + pad) + R;
    ctx.beginPath(); ctx.arc(x, ly, R, 0, Math.PI * 2);
    ctx.fillStyle = l.on ? l.color : l.color + '22';
    if (l.on) { ctx.shadowColor = l.color; ctx.shadowBlur = 14; }
    ctx.fill(); ctx.shadowBlur = 0;
  });

  ctx.font = `bold ${Math.floor(R * 0.9)}px system-ui`; ctx.fillStyle = '#8eacc8'; ctx.textAlign = 'center';
  ctx.fillText(label, x, y + bH + R * 0.9);
}

function drawSensor(x, y, label, activo, color) {
  const R = canvas.width * 0.013;
  ctx.beginPath(); ctx.arc(x, y, R, 0, Math.PI * 2);
  ctx.fillStyle = activo ? color + 'bb' : color + '22';
  if (activo) { ctx.shadowColor = color; ctx.shadowBlur = 14; }
  ctx.fill(); ctx.shadowBlur = 0;
  ctx.strokeStyle = activo ? color : '#2a3f5e'; ctx.lineWidth = 1.5; ctx.stroke();
  ctx.font = `bold ${Math.floor(R * 1.1)}px system-ui`; ctx.fillStyle = activo ? color : '#4a6080'; ctx.textAlign = 'center';
  ctx.fillText(label, x, y - R - 4);
}

function drawPaIndicator(W, H) {
  const x = W * 0.37, y = H * 0.52, w = W * 0.19;
  ctx.fillStyle = EST.paActivo ? 'rgba(0,230,118,0.15)' : 'rgba(255,23,68,0.1)';
  ctx.strokeStyle = EST.paActivo ? '#00e67660' : '#ff174440';
  roundRect(ctx, x, y, w, H * 0.06, 4); ctx.fill(); ctx.stroke();
  ctx.font = `bold ${Math.floor(W * 0.014)}px system-ui`; ctx.fillStyle = EST.paActivo ? '#00e676' : '#ff1744';
  ctx.textAlign = 'center'; ctx.fillText(EST.paActivo ? 'PA ACTIVO' : 'PA INACTIVO', x + w / 2, y + H * 0.038);
}

function drawCounter(W, H) {
  const cW = W * 0.20, cH = H * 0.07, x = W - cW - 10, y = H - cH - 10;
  ctx.fillStyle = 'rgba(8,12,20,0.88)'; roundRect(ctx, x, y, cW, cH, 6); ctx.fill();
  ctx.strokeStyle = '#2a3f5e'; ctx.lineWidth = 1; roundRect(ctx, x, y, cW, cH, 6); ctx.stroke();
  const libre = 100 - EST.plazasOcupadas;
  const color = libre > 20 ? '#00e5ff' : libre > 5 ? '#ffd740' : '#ff1744';
  ctx.font = `bold ${Math.floor(cH * 0.48)}px monospace`; ctx.fillStyle = color; ctx.textAlign = 'center';
  ctx.fillText(`${libre} LIBRES`, x + cW / 2, y + cH * 0.68);
}

function drawVehiculo(v) {
  const vW = canvas.width * 0.06, vH = canvas.height * 0.05;
  ctx.save(); ctx.translate(v.x, v.y);
  ctx.fillStyle = v.color; roundRect(ctx, -vW / 2, -vH / 2, vW, vH, 4); ctx.fill();
  ctx.fillStyle = 'rgba(0,229,255,0.25)'; roundRect(ctx, -vW * 0.22, -vH * 0.26, vW * 0.44, vH * 0.36, 2); ctx.fill();
  ctx.restore();
}

function roundRect(ctx, x, y, w, h, r) {
  ctx.beginPath(); ctx.moveTo(x + r, y); ctx.lineTo(x + w - r, y); ctx.arcTo(x + w, y, x + w, y + r, r);
  ctx.lineTo(x + w, y + h - r); ctx.arcTo(x + w, y + h, x + w - r, y + h, r);
  ctx.lineTo(x + r, y + h); ctx.arcTo(x, y + h, x, y + h - r, r);
  ctx.lineTo(x, y + r); ctx.arcTo(x, y, x + r, y, r); ctx.closePath();
}

/* ═══════════════════════════════════════════════════════════════════
   5. LÓGICA DE SIMULACIÓN & PROCESO
   ═══════════════════════════════════════════════════════════════════ */
const COLORES_CARRO = ['#4488ff','#ff6644','#44dd88','#ffcc44','#cc44ff','#00e5ff'];

function crearVehiculoEntrada() {
  const W = canvas.width, H = canvas.height;
  return { id: crypto.randomUUID(), tipo: 'entrada', x: W * 0.96, y: H * 0.36, color: COLORES_CARRO[Math.floor(Math.random()*COLORES_CARRO.length)], fase: 'llegando', speed: 2.2 };
}
function crearVehiculoSalida() {
  const W = canvas.width, H = canvas.height;
  return { id: crypto.randomUUID(), tipo: 'salida', x: W * 0.20, y: H * 0.64, color: COLORES_CARRO[Math.floor(Math.random()*COLORES_CARRO.length)], fase: 'esperandoVerde', speed: 2.2 };
}

function updateVehiculos() {
  const W = canvas.width, gW = W * 0.36, cwX2 = gW + W * 0.22;
  const e1X = cwX2 + (W - cwX2) * 0.55, e2X = gW * 0.82, s2X = cwX2 + (W - cwX2) * 0.55;

  for (let i = EST.vehiculos.length - 1; i >= 0; i--) {
    const v = EST.vehiculos[i];
    if (v.tipo === 'entrada') {
      if (v.fase === 'llegando') {
        if (v.x > e1X) { v.x -= v.speed; if (v.x <= e1X) { activarSensor('E1'); v.fase = 'esperandoVerde'; } }
      } else if (v.fase === 'esperandoVerde') {
        if (EST.semEntrada === 'verde' && EST.portonEstado === 'abierto') v.fase = 'pasandoPorton';
      } else if (v.fase === 'pasandoPorton') {
        if (v.x > e2X) v.x -= v.speed; else { activarSensor('E2'); EST.vehiculos.splice(i, 1); }
      }
    } else if (v.tipo === 'salida') {
      if (v.fase === 'esperandoVerde') {
        if (EST.semSalida === 'verde' && EST.portonEstado === 'abierto') v.fase = 'saliendo';
      } else if (v.fase === 'saliendo') {
        if (v.x < s2X) v.x += v.speed; else { activarSensor('S2'); EST.vehiculos.splice(i, 1); }
      }
    }
  }
}

function iniciarCicloSP() {
  clearTimeout(EST.spTimer); clearInterval(EST._spBarInterval);
  clearTimeout(EST._paTimer); clearTimeout(EST._paOffTimer);
  setFaseSP('rojo');
}

function setFaseSP(fase) {
  EST.spFase = fase; EST.semPeatonal = fase;
  clearTimeout(EST._paTimer); clearTimeout(EST._paOffTimer);

  const duracion = fase === 'verde' ? EST.spVerdeMs : EST.spRojoMs;
  const siguienteFase = fase === 'verde' ? 'rojo' : 'verde';

  if (fase === 'rojo') {
    EST.paActivo = false;
    EST._paTimer = setTimeout(() => {
      EST.paActivo = true; actualizarUI();
      log('Ventana PA activada (portón puede operar)', 'ok');
      procesarDemandas();

      const paDuration = duracion - 4000 - 6000;
      EST._paOffTimer = setTimeout(() => {
        EST.paActivo = false; actualizarUI();
        log('Ventana PA cerrada (6s previas a SP→verde)', 'warn');
        if (EST.portonEstado === 'abierto') cerrarPorton();
      }, Math.max(paDuration, 1000));
    }, 4000);
  } else {
    EST.paActivo = false;
  }

  const inicio = Date.now();
  clearInterval(EST._spBarInterval);
  EST._spBarInterval = setInterval(() => {
    const elapsed = Date.now() - inicio, restante = Math.max(0, duracion - elapsed);
    EST.spSegRestantes = Math.ceil(restante / 1000);
    updateTimerUI(fase, restante, duracion);
    if (restante <= 0) clearInterval(EST._spBarInterval);
  }, 250);

  EST.spTimer = setTimeout(() => {
    setFaseSP(siguienteFase);
    if (siguienteFase === 'rojo') setTimeout(procesarDemandas, 4200);
  }, duracion);

  actualizarUI();
  log(`Semáforo peatonal → ${fase.toUpperCase()} (${duracion / 1000}s)`, 'info');
}

function procesarDemandas() {
  if (!EST.sistemaActivo || !EST.paActivo || EST.semPeatonal === 'verde' || EST.portonEstado !== 'cerrado') return;
  if (EST.demandaSalida) {
    iniciarManiobra('salida');
  } else if (EST.demandaEntrada && EST.plazasOcupadas < 100) {
    iniciarManiobra('entrada');
  }
}

function iniciarManiobra(tipo) {
  EST.portonParaEntrada = tipo === 'entrada';
  EST.portonParaSalida  = tipo === 'salida';
  abrirPorton();
  log(`Portón abriéndose para ${tipo}`, 'ok');
}

function abrirPorton() {
  EST.portonEstado = 'abriendo'; EST.FCA = false; EST.FCC = false;
  actualizarUI();
  setTimeout(() => {
    EST.portonEstado = 'abierto'; EST.FCA = true; EST.ciclosPorton++;
    if (EST.portonParaEntrada) {
      EST.semEntrada = 'verde'; EST.demandaEntrada = false;
      const v = EST.vehiculos.find(v => v.tipo === 'entrada' && v.fase === 'esperandoVerde');
      if (v) v.fase = 'pasandoPorton';
    }
    if (EST.portonParaSalida) {
      EST.semSalida = 'verde'; EST.demandaSalida = false;
      const v = EST.vehiculos.find(v => v.tipo === 'salida' && v.fase === 'esperandoVerde');
      if (v) v.fase = 'saliendo';
    }
    actualizarUI(); log('FCA activado — portón abierto', 'ok');
  }, 1600);
}

function cerrarPorton() {
  if (EST.portonEstado === 'cerrando' || EST.portonEstado === 'cerrado') return;
  EST.portonEstado = 'cerrando'; EST.FCA = false; actualizarUI();
  setTimeout(() => {
    EST.portonEstado = 'cerrado'; EST.FCC = true;
    EST.semEntrada = (EST.sistemaActivo && EST.plazasOcupadas < 100) ? 'azul' : 'rojo';
    EST.semSalida = 'rojo'; EST.portonParaEntrada = false; EST.portonParaSalida = false;
    actualizarUI(); log('FCC activado — portón cerrado', 'info');
    setTimeout(procesarDemandas, 300);
  }, 1600);
}

function activarSensor(sensor) {
  EST[sensor] = true; actualizarUI(); log(`Sensor ${sensor} activado`, 'info');
  if (sensor === 'E2') {
    if (EST.plazasOcupadas < 100) EST.plazasOcupadas++;
    EST.totalEntradas++;
    setTimeout(() => { EST.E1 = false; EST.E2 = false; actualizarUI(); }, 500);
    setTimeout(cerrarPorton, 200);
  } else if (sensor === 'S2') {
    if (EST.plazasOcupadas > 0) EST.plazasOcupadas--;
    EST.totalSalidas++;
    setTimeout(() => { EST.S1 = false; EST.S2 = false; actualizarUI(); }, 500);
    setTimeout(cerrarPorton, 200);
  } else if (sensor === 'E1') {
    EST.demandaEntrada = true; procesarDemandas();
  } else if (sensor === 'S1') {
    EST.demandaSalida = true; procesarDemandas();
  }
}

function resetSistema() {
  clearTimeout(EST.spTimer); clearInterval(EST._spBarInterval);
  clearTimeout(EST._paTimer); clearTimeout(EST._paOffTimer);

  Object.assign(EST, {
    sistemaActivo: false, plazasOcupadas: 0, semEntrada: 'rojo', semSalida: 'rojo', semPeatonal: 'rojo',
    portonEstado: 'cerrado', E1: false, E2: false, S1: false, S2: false, FCA: false, FCC: true,
    demandaEntrada: false, demandaSalida: false, portonParaEntrada: false, portonParaSalida: false,
    paActivo: false, vehiculos: []
  });

  actualizarUI(); updateTimerUI('—', 0, 1);
  log('Sistema → Condiciones Iniciales (CI)', 'warn');
}

/* ═══════════════════════════════════════════════════════════════════
   6. UI DOM UPDATES
   ═══════════════════════════════════════════════════════════════════ */
function actualizarUI() {
  const libres = 100 - EST.plazasOcupadas, pct = EST.plazasOcupadas;
  const disp = document.getElementById('plazasDisplay');
  if (disp) {
    disp.textContent = libres;
    disp.className = 'plaza-counter' + (libres <= 5 ? ' critical' : libres <= 20 ? ' warning' : '');
  }
  const bar = document.getElementById('plazaBarFill');
  if (bar) { bar.style.width = pct + '%'; bar.style.backgroundColor = libres <= 5 ? '#ff1744' : libres <= 20 ? '#ffd740' : '#00e676'; }
  setEl('plazaPct', `${pct}% ocupado`);

  const ss = document.getElementById('systemStatus');
  if (ss) ss.className = 'system-status ' + (EST.sistemaActivo ? 'status-online' : 'status-offline');
  setEl('statusText', EST.sistemaActivo ? 'ACTIVO' : 'DETENIDO');

  const paB = document.getElementById('paHeaderBadge');
  if (paB) {
    paB.classList.toggle('active', EST.paActivo);
    setEl('paStateText', EST.paActivo ? 'PA: ACTIVO' : 'PA: INACTIVO');
  }

  setEl('metEntradas', EST.totalEntradas); setEl('metSalidas', EST.totalSalidas);
  setEl('metCiclos', EST.ciclosPorton); setEl('metEnergia', (EST.ciclosPorton * 45).toFixed(0) + ' Wh');

  const btnMap = { btnInicio: 'inicio', btnReset: 'reset', btnSimE1: 'simE1', btnSimS1: 'simS1' };
  Object.entries(btnMap).forEach(([id, accion]) => {
    const btn = document.getElementById(id);
    if (btn) btn.disabled = !puedeDo(accion);
  });
}

function setEl(id, val) { const e = document.getElementById(id); if (e) e.textContent = val; }

function updateTimerUI(fase, restanteMs, totalMs) {
  const label = document.getElementById('timerLabel'), bar = document.getElementById('timerBarFill'), val = document.getElementById('timerVal');
  if (!label || !bar || !val) return;
  if (fase === '—') { label.textContent = 'Sistema detenido'; bar.style.width = '0%'; val.textContent = '—'; return; }
  const pct = totalMs > 0 ? (restanteMs / totalMs) * 100 : 0;
  label.textContent = `SP en ${fase.toUpperCase()}`; bar.style.width = pct + '%';
  bar.className = 'timer-bar-fill timer-bar-' + fase; val.textContent = Math.ceil(restanteMs / 1000) + 's restantes';
}

let _snackT = null;
function snack(msg) {
  const el = document.getElementById('snackbar'); if (!el) return;
  el.textContent = msg; el.hidden = false; clearTimeout(_snackT);
  _snackT = setTimeout(() => { el.hidden = true; }, 3200);
}

function renderLoop() {
  if (EST.sistemaActivo || EST.vehiculos.length > 0) updateVehiculos();
  drawScene(); requestAnimationFrame(renderLoop);
}

function aplicarRBAC() {
  const rol = sesion?.rol;
  const pi = document.getElementById('panelIngeniero'); if (pi) pi.hidden = rol !== 'Ingeniero';
  const pg = document.getElementById('panelGerente'); if (pg) pg.hidden = rol !== 'Gerente';
  const pl = document.getElementById('panelLog'); if (pl) pl.hidden = !(rol === 'Ingeniero' || rol === 'Gerente');

  const av = document.getElementById('userAvatar'); if (av) av.textContent = (sesion?.nombre?.[0] ?? '?').toUpperCase();
  setEl('displayNombre', sesion?.nombre ?? '—');
  const re = document.getElementById('displayRol');
  if (re) { re.textContent = sesion?.rol ?? '—'; re.className = `user-rol rol-badge rol-${sesion?.rol ?? ''}`; }
  actualizarUI();
}

function mostrarApp() {
  document.getElementById('authOverlay').hidden = true;
  document.getElementById('app').hidden = false;
  aplicarRBAC(); log(`Sesión iniciada: ${sesion.nombre} [${sesion.rol}]`, 'ok');
}

function cerrarSesion() {
  log('Sesión cerrada', 'warn'); sesion = null; resetSistema();
  document.getElementById('authOverlay').hidden = false;
  document.getElementById('app').hidden = true;
  document.getElementById('inputUsuario').value = '';
  document.getElementById('inputPassword').value = '';
  document.getElementById('loginError').hidden = true;
}

/* ═══════════════════════════════════════════════════════════════════
   7. ADMIN MODAL LOGIC
   ═══════════════════════════════════════════════════════════════════ */
function renderAdminTabla() {
  const tbody = document.getElementById('adminUsersBody'), emptyRow = document.getElementById('adminEmptyRow');
  if (!tbody) return;
  Array.from(tbody.querySelectorAll('tr.user-row')).forEach(r => r.remove());

  if (USUARIOS_BD.length === 0) { emptyRow.hidden = false; } else {
    emptyRow.hidden = true;
    USUARIOS_BD.forEach((u, i) => {
      const tr = document.createElement('tr'); tr.className = 'user-row';
      tr.innerHTML = `
        <td>${i + 1}</td>
        <td style="font-weight:700">${u.nombre}</td>
        <td><span class="user-rol rol-badge rol-${u.rol}">${u.rol}</span></td>
        <td class="mono" title="${u.salt}">${u.salt.slice(0,10)}…</td>
        <td class="mono" title="${u.hash}">${u.hash.slice(0,14)}…</td>
        <td><button class="btn-del" data-nombre="${u.nombre}">🗑</button></td>
      `;
      tbody.appendChild(tr);
    });

    tbody.querySelectorAll('.btn-del').forEach(b => {
      b.addEventListener('click', () => {
        const nom = b.dataset.nombre;
        if (confirm(`¿Eliminar usuario "${nom}"?`)) {
          USUARIOS_BD = USUARIOS_BD.filter(u => u.nombre !== nom);
          persistirUsuariosLocales(); renderAdminTabla(); actualizarSourceLabel();
        }
      });
    });
  }

  setEl('totalUsuarios', USUARIOS_BD.length);
}

function actualizarSourceLabel() {
  const hint = document.getElementById('loginUserHint');
  if (hint) {
    hint.textContent = USUARIOS_BD.map(u => u.nombre).slice(0, 5).join(' · ');
  }
}

/* ═══════════════════════════════════════════════════════════════════
   8. EVENTOS & BINDINGS
   ═══════════════════════════════════════════════════════════════════ */
function bindEvents() {
  // Tabs Login/Registro
  document.querySelectorAll('.auth-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      document.querySelectorAll('.auth-tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('panelLogin').hidden    = tab !== 'login';
      document.getElementById('panelRegistro').hidden = tab !== 'registro';
    });
  });

  // Login Submit
  document.getElementById('loginForm').addEventListener('submit', async e => {
    e.preventDefault();
    const usr = document.getElementById('inputUsuario').value;
    const pwd = document.getElementById('inputPassword').value;
    const errEl = document.getElementById('loginError');
    const btnTxt = document.getElementById('loginBtnText');
    const spin   = document.getElementById('loginSpinner');

    errEl.hidden = true; btnTxt.textContent = 'Verificando…'; spin.hidden = false;
    const u = await autenticar(usr, pwd);
    spin.hidden = true; btnTxt.textContent = 'Iniciar Sesión';

    if (!u) { errEl.hidden = false; document.getElementById('inputPassword').value = ''; log(`Login fallido: "${usr}"`, 'error'); return; }
    sesion = { nombre: u.nombre, rol: u.rol };
    mostrarApp();
  });

  // Registro Submit
  document.getElementById('registroForm')?.addEventListener('submit', async e => {
    e.preventDefault();
    const regError = document.getElementById('regError'), regOk = document.getElementById('regOk');
    const btnTxt = document.getElementById('regBtnTxt'), btnSpin = document.getElementById('regSpinner'), btnReg = document.getElementById('btnRegistrar');
    regError.hidden = true; regOk.hidden = true;

    const nombre = document.getElementById('regNombre').value.trim();
    const rol    = document.getElementById('regRol').value;
    const pwd    = document.getElementById('regPwd').value;
    const conf   = document.getElementById('regPwdConf').value;
    const codigo = document.getElementById('regCodigo').value;

    if (!nombre || !/^[a-z0-9_]{3,30}$/i.test(nombre)) return showRegErr('Nombre inválido (3–30 chars)');
    if (!rol) return showRegErr('Selecciona un rol');
    if (pwd.length < 6) return showRegErr('Contraseña mínimo 6 caracteres');
    if (pwd !== conf) return showRegErr('Las contraseñas no coinciden');
    if (codigo !== CODIGO_ACT) return showRegErr('Código de activación incorrecto');

    btnReg.disabled = true; btnTxt.textContent = 'Derivando PBKDF2…'; btnSpin.hidden = false;
    try {
      const u = await registrarUsuario(nombre, rol, pwd);
      log(`Usuario registrado: ${u.nombre} [${u.rol}]`, 'ok');
      regOk.textContent = `✅ Usuario "${u.nombre}" creado [${u.rol}]`; regOk.hidden = false;
      setTimeout(() => {
        document.getElementById('tabLogin').click();
        document.getElementById('inputUsuario').value = u.nombre;
        document.getElementById('inputPassword').focus();
        actualizarSourceLabel(); snack(`✅ Usuario "${u.nombre}" registrado. Ahora inicia sesión.`);
      }, 1500);
    } catch (err) { showRegErr(err.message); }
    finally { btnReg.disabled = false; btnTxt.textContent = '🔐 Crear Cuenta con PBKDF2'; btnSpin.hidden = true; }

    function showRegErr(m) { regError.textContent = '⚠️ ' + m; regError.hidden = false; }
  });

  // Strength checkers
  const regPwd = document.getElementById('regPwd');
  regPwd?.addEventListener('input', () => {
    const f = evaluarFuerza(regPwd.value);
    const b = document.getElementById('regStrengthBar'), l = document.getElementById('regStrengthLabel');
    if (b) { b.style.width = f.pct + '%'; b.style.backgroundColor = f.color; }
    if (l) l.textContent = f.label;
  });

  document.getElementById('btnTogglePwd')?.addEventListener('click', () => {
    const i = document.getElementById('inputPassword'); i.type = i.type === 'password' ? 'text' : 'password';
  });
  document.getElementById('btnRegEye1')?.addEventListener('click', () => {
    const i = document.getElementById('regPwd'); i.type = i.type === 'password' ? 'text' : 'password';
  });
  document.getElementById('btnRegEye2')?.addEventListener('click', () => {
    const i = document.getElementById('regPwdConf'); i.type = i.type === 'password' ? 'text' : 'password';
  });

  document.getElementById('btnLogout')?.addEventListener('click', cerrarSesion);

  // SCADA Mandos
  document.getElementById('btnInicio')?.addEventListener('click', async () => {
    if (!puedeDo('inicio')) return;
    const { payload, firma } = await signCommand('INICIO');
    if (!await verifyCommand(payload, firma)) { snack('❌ Firma HMAC inválida'); return; }
    EST.sistemaActivo = true; EST.semEntrada = 'azul'; iniciarCicloSP(); actualizarUI();
    snack('▶ Sistema iniciado — ciclo SP activo'); log('Sistema iniciado', 'ok');
  });

  document.getElementById('btnReset')?.addEventListener('click', async () => {
    if (!puedeDo('reset')) return;
    const { payload, firma } = await signCommand('RESET');
    if (!await verifyCommand(payload, firma)) { snack('❌ Firma HMAC inválida'); return; }
    resetSistema(); snack('↺ Sistema en Condiciones Iniciales');
  });

  document.getElementById('btnSimE1')?.addEventListener('click', async () => {
    if (!puedeDo('simE1') || !EST.sistemaActivo) return;
    if (EST.plazasOcupadas >= 100) { snack('🅿️ Estacionamiento lleno'); return; }
    const { payload, firma } = await signCommand('SIM_E1');
    if (!await verifyCommand(payload, firma)) { snack('❌ Firma HMAC inválida'); return; }
    EST.vehiculos.push(crearVehiculoEntrada()); snack('🚗 Vehículo ingresando (E1)'); log('Simulación: vehículo en entrada', 'info');
  });

  document.getElementById('btnSimS1')?.addEventListener('click', async () => {
    if (!puedeDo('simS1') || !EST.sistemaActivo) return;
    if (EST.plazasOcupadas === 0) { snack('🅿️ Garaje vacío'); return; }
    const { payload, firma } = await signCommand('SIM_S1');
    if (!await verifyCommand(payload, firma)) { snack('❌ Firma HMAC inválida'); return; }
    EST.vehiculos.push(crearVehiculoSalida()); activarSensor('S1'); snack('🚗 Vehículo demandando salida (S1)'); log('Simulación: vehículo demanda salida', 'info');
  });

  document.getElementById('btnForzarPorton')?.addEventListener('click', async () => {
    if (!puedeDo('forzarPorton')) return;
    const { payload, firma } = await signCommand('FORZAR_PORTON');
    if (!await verifyCommand(payload, firma)) return;
    if (EST.portonEstado === 'cerrado') { EST.portonEstado = 'abriendo'; setTimeout(() => { EST.portonEstado = 'abierto'; EST.FCA = true; actualizarUI(); }, 1600); }
    else if (EST.portonEstado === 'abierto') cerrarPorton();
    snack('🚧 Portón forzado manualmente'); log('Portón forzado por el Ingeniero', 'warn'); actualizarUI();
  });

  document.getElementById('btnAplicarTiempos')?.addEventListener('click', async () => {
    if (!puedeDo('ajustarTiempos')) return;
    const tv = parseInt(document.getElementById('inputTiempoVerde').value) * 1000;
    const tr = parseInt(document.getElementById('inputTiempoRojo').value) * 1000;
    if (isNaN(tv) || isNaN(tr) || tv < 5000 || tr < 10000) { snack('⚠️ Tiempos fuera de rango'); return; }
    const { payload, firma } = await signCommand('AJUSTAR_TIEMPOS');
    if (!await verifyCommand(payload, firma)) return;
    EST.spVerdeMs = tv; EST.spRojoMs = tr;
    if (EST.sistemaActivo) iniciarCicloSP();
    snack(`⚙️ SP actualizado: Verde ${tv/1000}s / Rojo ${tr/1000}s`); log(`Tiempos SP ajustados (Verde:${tv/1000}s Rojo:${tr/1000}s)`, 'warn');
  });

  document.getElementById('btnExportLog')?.addEventListener('click', () => {
    const csv = ['timestamp,rol,mensaje,tipo', ...auditEntries.map(e => `"${e.ts}","${e.rol}","${e.msg}","${e.tipo}"`)].join('\n');
    const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([csv], { type: 'text/csv' })), download: `scada_log_${Date.now()}.csv` });
    a.click(); URL.revokeObjectURL(a.href); log('Log exportado a CSV', 'info');
  });

  // Admin Modal Trigger
  const modal = document.getElementById('adminModal');
  const openModal = () => { renderAdminTabla(); modal.hidden = false; };
  const closeModal = () => { modal.hidden = true; };

  document.getElementById('btnOpenAdminNav')?.addEventListener('click', openModal);
  document.getElementById('btnOpenAdminFromLogin')?.addEventListener('click', openModal);
  document.getElementById('btnCloseAdminModal')?.addEventListener('click', closeModal);

  // Admin Form Submit inside Modal
  document.getElementById('adminCrearForm')?.addEventListener('submit', async e => {
    e.preventDefault();
    const errE = document.getElementById('admError'), okE = document.getElementById('admOk');
    errE.hidden = true; okE.hidden = true;

    const nombre = document.getElementById('admNombre').value.trim();
    const rol    = document.getElementById('admRol').value;
    const pwd    = document.getElementById('admPwd').value;
    const conf   = document.getElementById('admPwdConf').value;

    if (!nombre || !/^[a-z0-9_]{3,30}$/i.test(nombre)) return showAdmErr('Nombre inválido');
    if (!rol) return showAdmErr('Selecciona un rol');
    if (pwd.length < 6) return showAdmErr('Contraseña mínimo 6 caracteres');
    if (pwd !== conf) return showAdmErr('Contraseñas no coinciden');

    try {
      const u = await registrarUsuario(nombre, rol, pwd);
      okE.textContent = `✅ Usuario "${u.nombre}" creado con hash PBKDF2`; okE.hidden = false;
      document.getElementById('adminCrearForm').reset();
      renderAdminTabla(); actualizarSourceLabel();
      setTimeout(() => { okE.hidden = true; }, 3000);
    } catch (err) { showAdmErr(err.message); }

    function showAdmErr(m) { errE.textContent = '⚠️ ' + m; errE.hidden = false; }
  });

  window.addEventListener('resize', resizeCanvas);
}

/* ═══════════════════════════════════════════════════════════════════
   9. INIT
   ═══════════════════════════════════════════════════════════════════ */
async function init() {
  await initHmacKey();
  resizeCanvas();
  bindEvents();
  cargarUsuariosLocales();
  resetSistema();
  renderLoop();
}

document.addEventListener('DOMContentLoaded', init);
