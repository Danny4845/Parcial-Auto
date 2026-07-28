/* SCADA Estacionamiento Automatizado — III Parcial (Daniel Colmenares & Hernaldo Pérez Roa) */

'use strict';

// Configuración y Datos Locales
const USUARIOS_DEMO = [];
let USUARIOS_BD = [];
const LS_KEY = 'scada_usuarios_registrados';

// Inicialización de Clave HMAC (Web Crypto API)
let hmacKey = null;

async function initHmacKey() {
  hmacKey = await crypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  );
}

// Firma y Verificación Criptográfica de Comandos
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

// Derivación PBKDF2 (100.000 iteraciones, SHA-256)
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

// Persistencia LocalStorage
function cargarUsuariosLocales() {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) { USUARIOS_BD = []; return; }
    const guardados = JSON.parse(raw);
    USUARIOS_BD = Array.isArray(guardados) ? guardados : [];
  } catch (_) { USUARIOS_BD = []; }
}

function persistirUsuariosLocales() {
  localStorage.setItem(LS_KEY, JSON.stringify(USUARIOS_BD));
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

function existeGerente() {
  return USUARIOS_BD.some(u => u.rol === 'Gerente');
}

function evaluarFuerza(pwd) {
  let s = 0;
  if (pwd.length >= 8) s++; if (pwd.length >= 12) s++;
  if (/[A-Z]/.test(pwd)) s++; if (/[0-9]/.test(pwd)) s++; if (/[^A-Za-z0-9]/.test(pwd)) s++;
  const niveles = [
    { pct: 0, color: 'transparent', label: '' },
    { pct: 20, color: '#ff3344', label: 'Muy débil' },
    { pct: 40, color: '#ffaa00', label: 'Débil' },
    { pct: 60, color: '#ffd740', label: 'Aceptable' },
    { pct: 80, color: '#4cd6c0', label: 'Fuerte' },
    { pct: 100, color: '#00e676', label: 'Muy fuerte' }
  ];
  return niveles[Math.min(s, 5)];
}

// Estado del Proceso SCADA
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

// Log de Auditoría
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

// Permisos y Matriz RBAC
const PERMISOS = {
  Operador:   ['inicio', 'reset', 'simE1', 'simS1'],
  Supervisor: ['inicio', 'reset', 'simE1', 'simS1', 'forzarPorton', 'ajustarTiempos', 'verLog', 'crearUsuario'],
  Ingeniero:  ['inicio', 'reset', 'simE1', 'simS1', 'forzarPorton', 'ajustarTiempos', 'verLog', 'crearUsuario'],
  Gerente:    ['inicio', 'reset', 'simE1', 'simS1', 'forzarPorton', 'ajustarTiempos', 'verLog', 'verMetricas', 'crearUsuario']
};
function puedeDo(accion) { return sesion && (PERMISOS[sesion.rol] || []).includes(accion); }

// Renderizado Canvas 2D
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

  ctx.fillStyle = '#1d212b'; ctx.fillRect(0, 0, W, H);
  ctx.fillStyle = '#14171f'; ctx.fillRect(0, 0, gW, H);

  ctx.strokeStyle = '#ffaa00'; ctx.lineWidth = 3;
  ctx.beginPath(); ctx.moveTo(gW, 0); ctx.lineTo(gW, H); ctx.stroke();
  ctx.strokeRect(1.5, 1.5, gW - 1.5, H - 3); ctx.lineWidth = 1;

  drawParkingGrid(gW, H);

  ctx.fillStyle = '#ffaa0066'; ctx.font = `bold ${Math.floor(W * 0.022)}px system-ui`;
  ctx.textAlign = 'center'; ctx.fillText('100 PLAZAS', gW / 2, H / 2);

  drawCarril(0, entY, gW, lH, '#172233', '← ENTRADA', '#3388ffaa', 'left');
  drawCarril(0, salY, gW, lH, '#262016', 'SALIDA →',  '#ffaa00aa', 'right');

  ctx.fillStyle = '#222736'; ctx.fillRect(cwX2, 0, W - cwX2, H);

  drawDiagonalLane(cwX2, entY, W, H * 0.08, lH, '#172233', '← ENTRADA', '#3388ffaa');
  drawDiagonalLane(cwX2, salY, W, H * 0.92, lH, '#262016', 'SALIDA →',  '#ffaa00aa');

  drawCrosswalk(cwX, entY - lH / 2, cwW, lH + (salY - entY) + lH);
  drawPorton(cwX, entY - lH / 2, cwW, lH + (salY - entY) + lH);

  drawTrafficLight(cwX + cwW * 0.18, H * 0.03, 'S.P.', EST.semPeatonal, false);
  drawTrafficLight(cwX + cwW * 0.72, H * 0.03, 'S.E.', EST.semEntrada, true);
  drawTrafficLight(cwX + cwW * 0.45, H * 0.80, 'S.S.', EST.semSalida, false);

  const e1x = cwX2 + (W - cwX2) * 0.55, e1y = entY;
  const e2x = gW * 0.82, e2y = entY;
  const s1x = gW * 0.82, s1y = salY;
  const s2x = cwX2 + (W - cwX2) * 0.55, s2y = salY;

  drawSensor(e1x, e1y, 'E1', EST.E1, '#3388ff');
  drawSensor(e2x, e2y, 'E2', EST.E2, '#3388ff');
  drawSensor(s1x, s1y, 'S1', EST.S1, '#ffaa00');
  drawSensor(s2x, s2y, 'S2', EST.S2, '#ffaa00');

  ctx.font = `bold ${Math.floor(W * 0.016)}px monospace`; ctx.textAlign = 'left';
  ctx.fillStyle = EST.FCA ? '#00e676' : '#353c4e'; ctx.fillText('FCA', cwX + 4, entY - lH / 2 - 5);
  ctx.fillStyle = EST.FCC ? '#00e676' : '#353c4e'; ctx.fillText('FCC', cwX + 4, salY + lH / 2 + 14);

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
        ctx.fillStyle   = ocu ? 'rgba(255, 51, 68, 0.2)' : '#1a1f2c';
        ctx.strokeStyle = ocu ? '#ff3344' : '#2d3548';
        roundRect(ctx, x, y, spotW, spotH, 3); ctx.fill(); ctx.stroke();
        if (ocu) {
          ctx.fillStyle = '#ff3344';
          roundRect(ctx, x + spotW * 0.15, y + spotH * 0.2, spotW * 0.7, spotH * 0.6, 2); ctx.fill();
        }
        idx++;
      }
    }
  });
}

function drawCarril(x, centerY, w, h, fillColor, label, labelColor, dir) {
  ctx.fillStyle = fillColor; ctx.fillRect(x, centerY - h / 2, w, h);
  ctx.strokeStyle = '#ffffff10'; ctx.lineWidth = 1; ctx.setLineDash([12, 10]);
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
  ctx.fillStyle = '#1c2230'; ctx.fillRect(x, y, w, h);
  const stripeH = h / 13, active = EST.semPeatonal === 'verde';
  for (let i = 0; i < 7; i++) {
    ctx.fillStyle = active ? '#00e67644' : '#ffffff12';
    ctx.fillRect(x + w * 0.08, y + i * stripeH * 2, w * 0.84, stripeH);
  }
  ctx.strokeStyle = '#353c4e'; ctx.lineWidth = 1.5; ctx.strokeRect(x, y, w, h);
}

function drawPorton(x, y, w, h) {
  const barCount = 6;
  let apertura = EST.portonEstado === 'abierto' ? 1 : (EST.portonEstado === 'abriendo' || EST.portonEstado === 'cerrando') ? 0.55 : 0;
  const color = EST.portonEstado === 'cerrado' ? '#ff3344' : EST.portonEstado === 'abierto' ? '#00e676' : '#ffaa00';

  ctx.fillStyle = '#353c4e';
  ctx.fillRect(x + w * 0.1, y, w * 0.05, h); ctx.fillRect(x + w * 0.85, y, w * 0.05, h);

  const barW = (w * 0.65) / barCount, barStartX = x + w * 0.175, barH = h * (1 - apertura);
  for (let i = 0; i < barCount; i++) {
    ctx.fillStyle = color; ctx.shadowColor = color; ctx.shadowBlur = 6;
    roundRect(ctx, barStartX + i * barW, y, barW * 0.65, barH, 2); ctx.fill(); ctx.shadowBlur = 0;
  }
}

function drawTrafficLight(x, y, label, estado, hasAzul) {
  const R = canvas.width * 0.020, pad = R * 0.6;
  const lights = hasAzul
    ? [{ color: '#ff3344', on: estado === 'rojo' }, { color: '#00e676', on: estado === 'verde' }, { color: '#3388ff', on: estado === 'azul' }]
    : [{ color: '#ff3344', on: estado === 'rojo' }, { color: '#00e676', on: estado === 'verde' }];

  const bH = pad * 2 + lights.length * R * 2 + (lights.length - 1) * pad, bW = R * 2 + pad * 2;

  ctx.fillStyle = '#14171f'; roundRect(ctx, x - bW / 2, y, bW, bH, 5); ctx.fill();
  ctx.strokeStyle = '#353c4e'; ctx.lineWidth = 1.5; roundRect(ctx, x - bW / 2, y, bW, bH, 5); ctx.stroke();

  lights.forEach((l, i) => {
    const ly = y + pad + i * (R * 2 + pad) + R;
    ctx.beginPath(); ctx.arc(x, ly, R, 0, Math.PI * 2);
    ctx.fillStyle = l.on ? l.color : l.color + '25';
    if (l.on) { ctx.shadowColor = l.color; ctx.shadowBlur = 12; }
    ctx.fill(); ctx.shadowBlur = 0;
  });

  ctx.font = `bold ${Math.floor(R * 0.9)}px system-ui`; ctx.fillStyle = '#9ba5b8'; ctx.textAlign = 'center';
  ctx.fillText(label, x, y + bH + R * 0.9);
}

function drawSensor(x, y, label, activo, color) {
  const R = canvas.width * 0.013;
  ctx.beginPath(); ctx.arc(x, y, R, 0, Math.PI * 2);
  ctx.fillStyle = activo ? color : color + '25';
  if (activo) { ctx.shadowColor = color; ctx.shadowBlur = 10; }
  ctx.fill(); ctx.shadowBlur = 0;
  ctx.strokeStyle = activo ? color : '#353c4e'; ctx.lineWidth = 1.5; ctx.stroke();
  ctx.font = `bold ${Math.floor(R * 1.1)}px system-ui`; ctx.fillStyle = activo ? color : '#647087'; ctx.textAlign = 'center';
  ctx.fillText(label, x, y - R - 4);
}

function drawPaIndicator(W, H) {
  const x = W * 0.37, y = H * 0.52, w = W * 0.19;
  ctx.fillStyle = EST.paActivo ? 'rgba(0,230,118,0.18)' : 'rgba(255,51,68,0.15)';
  ctx.strokeStyle = EST.paActivo ? '#00e676' : '#ff3344';
  roundRect(ctx, x, y, w, H * 0.06, 4); ctx.fill(); ctx.stroke();
  ctx.font = `bold ${Math.floor(W * 0.014)}px system-ui`; ctx.fillStyle = EST.paActivo ? '#00e676' : '#ff3344';
  ctx.textAlign = 'center'; ctx.fillText(EST.paActivo ? 'PA ACTIVO' : 'PA INACTIVO', x + w / 2, y + H * 0.038);
}

function drawCounter(W, H) {
  const cW = W * 0.20, cH = H * 0.07, x = W - cW - 10, y = H - cH - 10;
  ctx.fillStyle = 'rgba(29,33,43,0.92)'; roundRect(ctx, x, y, cW, cH, 6); ctx.fill();
  ctx.strokeStyle = '#353c4e'; ctx.lineWidth = 1; roundRect(ctx, x, y, cW, cH, 6); ctx.stroke();
  const libre = 100 - EST.plazasOcupadas;
  const color = libre > 20 ? '#4cd6c0' : libre > 5 ? '#ffaa00' : '#ff3344';
  ctx.font = `bold ${Math.floor(cH * 0.48)}px monospace`; ctx.fillStyle = color; ctx.textAlign = 'center';
  ctx.fillText(`${libre} LIBRES`, x + cW / 2, y + cH * 0.68);
}

function drawVehiculo(v) {
  const vW = canvas.width * 0.06, vH = canvas.height * 0.05;
  ctx.save(); ctx.translate(v.x, v.y);
  ctx.fillStyle = '#3388ff'; roundRect(ctx, -vW / 2, -vH / 2, vW, vH, 4); ctx.fill();
  ctx.fillStyle = '#14171f'; roundRect(ctx, -vW * 0.22, -vH * 0.26, vW * 0.44, vH * 0.36, 2); ctx.fill();
  ctx.restore();
}

function roundRect(ctx, x, y, w, h, r) {
  ctx.beginPath(); ctx.moveTo(x + r, y); ctx.lineTo(x + w - r, y); ctx.arcTo(x + w, y, x + w, y + r, r);
  ctx.lineTo(x + w, y + h - r); ctx.arcTo(x + w, y + h, x + w - r, y + h, r);
  ctx.lineTo(x + r, y + h); ctx.arcTo(x, y + h, x, y + h - r, r);
  ctx.lineTo(x, y + r); ctx.arcTo(x, y, x + r, y, r); ctx.closePath();
}

// Simulación y Control de Proceso
function crearVehiculoEntrada() {
  const W = canvas.width, H = canvas.height;
  return { id: crypto.randomUUID(), tipo: 'entrada', x: W * 0.96, y: H * 0.36, color: '#3388ff', fase: 'llegando', speed: 2.2 };
}
function crearVehiculoSalida() {
  const W = canvas.width, H = canvas.height;
  return { id: crypto.randomUUID(), tipo: 'salida', x: W * 0.20, y: H * 0.64, color: '#ffaa00', fase: 'esperandoVerde', speed: 2.2 };
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
        log('Ventana PA cerrada (6s previas a SP->verde)', 'warn');
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
  log(`Semáforo peatonal -> ${fase.toUpperCase()} (${duracion / 1000}s)`, 'info');
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
    actualizarUI(); log('FCA activado - portón abierto', 'ok');
  }, 1600);
}

function cerrarPorton() {
  if (EST.portonEstado === 'cerrando' || EST.portonEstado === 'cerrado') return;
  EST.portonEstado = 'cerrando'; EST.FCA = false; actualizarUI();
  setTimeout(() => {
    EST.portonEstado = 'cerrado'; EST.FCC = true;
    EST.semEntrada = (EST.sistemaActivo && EST.plazasOcupadas < 100) ? 'azul' : 'rojo';
    EST.semSalida = 'rojo'; EST.portonParaEntrada = false; EST.portonParaSalida = false;
    actualizarUI(); log('FCC activado - portón cerrado', 'info');
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
  log('Sistema -> Condiciones Iniciales (CI)', 'warn');
}

// Actualización DOM e Interfaz
function actualizarUI() {
  const libres = 100 - EST.plazasOcupadas, pct = EST.plazasOcupadas;
  const disp = document.getElementById('plazasDisplay');
  if (disp) {
    disp.textContent = libres;
    disp.className = 'plaza-counter' + (libres <= 5 ? ' critical' : libres <= 20 ? ' warning' : '');
  }
  const bar = document.getElementById('plazaBarFill');
  if (bar) { bar.style.width = pct + '%'; bar.style.backgroundColor = '#4cd6c0'; }
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
  const esSupervisor = (rol === 'Supervisor' || rol === 'Ingeniero');
  const esGerente    = (rol === 'Gerente');
  const esOperador   = (rol === 'Operador');

  const pi = document.getElementById('panelIngeniero'); if (pi) pi.hidden = !esSupervisor && !esGerente;
  const pg = document.getElementById('panelGerente');   if (pg) pg.hidden = !esGerente;
  const pl = document.getElementById('panelLog');       if (pl) pl.hidden = esOperador;

  const btnCrear = document.getElementById('btnOpenCrearUsuario');
  if (btnCrear) {
    btnCrear.hidden = esOperador;
  }

  const av = document.getElementById('userAvatar'); if (av) av.textContent = (sesion?.nombre?.[0] ?? '?').toUpperCase();
  setEl('displayNombre', sesion?.nombre ?? '—');
  const re = document.getElementById('displayRol');
  if (re) { re.textContent = sesion?.rol ?? '—'; re.className = `user-rol rol-badge rol-${sesion?.rol ?? ''}`; }

  configurarModalCrearRol();
  actualizarUI();
}

function configurarModalCrearRol() {
  const selRol = document.getElementById('admRol');
  const hint   = document.getElementById('admRolHint');
  if (!selRol) return;

  const rolActivo = sesion?.rol;

  if (rolActivo === 'Gerente') {
    selRol.innerHTML = `
      <option value="Supervisor">Supervisor / Ingeniero (Nivel Planta)</option>
      <option value="Operador">Operador (Nivel Control)</option>
    `;
    if (hint) hint.textContent = 'Como Gerente, puedes crear usuarios Supervisor u Operador.';
  } else if (rolActivo === 'Supervisor' || rolActivo === 'Ingeniero') {
    selRol.innerHTML = `
      <option value="Operador">Operador (Nivel Control)</option>
    `;
    if (hint) hint.textContent = 'Como Supervisor, únicamente puedes crear usuarios Operador.';
  } else {
    selRol.innerHTML = '';
    if (hint) hint.textContent = 'Los operadores no tienen permisos para crear ni ver usuarios.';
  }
}

function mostrarApp() {
  document.getElementById('authOverlay').hidden = true;
  document.getElementById('app').hidden = false;
  aplicarRBAC(); log(`Sesión iniciada: ${sesion.nombre} [${sesion.rol}]`, 'ok');
}

function cerrarSesion() {
  log('Sesión cerrada', 'warn'); sesion = null; resetSistema();
  verificarPantallaInicial();
}

function verificarPantallaInicial() {
  const authOverlay   = document.getElementById('authOverlay');
  const mainApp       = document.getElementById('app');
  const adminModal    = document.getElementById('adminModal');
  const panelBoot     = document.getElementById('panelBootstrapGerente');
  const panelLogin    = document.getElementById('panelLogin');

  if (authOverlay) authOverlay.hidden = false;
  if (mainApp)     mainApp.hidden = true;
  if (adminModal)  adminModal.hidden = true;

  if (!existeGerente()) {
    if (panelBoot)  panelBoot.hidden  = false;
    if (panelLogin) panelLogin.hidden = true;
  } else {
    if (panelBoot)  panelBoot.hidden  = true;
    if (panelLogin) panelLogin.hidden = false;
  }
}

// Gestión de Tablas de Usuarios por Rol
function renderAdminTabla() {
  const rolActivo = sesion?.rol;

  const secGer = document.getElementById('secGerentes');
  const secSup = document.getElementById('secSupervisores');
  const secOpe = document.getElementById('secOperadores');

  const bodyGer = document.getElementById('bodyGerentes');
  const bodySup = document.getElementById('bodySupervisores');
  const bodyOpe = document.getElementById('bodyOperadores');

  if (!bodyGer || !bodySup || !bodyOpe) return;

  const gerentes     = USUARIOS_BD.filter(u => u.rol === 'Gerente');
  const supervisores = USUARIOS_BD.filter(u => u.rol === 'Supervisor' || u.rol === 'Ingeniero');
  const operadores   = USUARIOS_BD.filter(u => u.rol === 'Operador');

  setEl('cntGerentes', gerentes.length);
  setEl('cntSupervisores', supervisores.length);
  setEl('cntOperadores', operadores.length);

  if (rolActivo === 'Gerente') {
    if (secGer) secGer.hidden = false;
    if (secSup) secSup.hidden = false;
    if (secOpe) secOpe.hidden = false;

    renderSubTabla(bodyGer, gerentes);
    renderSubTabla(bodySup, supervisores);
    renderSubTabla(bodyOpe, operadores);
  } else if (rolActivo === 'Supervisor' || rolActivo === 'Ingeniero') {
    if (secGer) secGer.hidden = true;
    if (secSup) secSup.hidden = true;
    if (secOpe) secOpe.hidden = false;

    renderSubTabla(bodyOpe, operadores);
  } else {
    if (secGer) secGer.hidden = true;
    if (secSup) secSup.hidden = true;
    if (secOpe) secOpe.hidden = true;
  }
}

function renderSubTabla(tbody, lista) {
  tbody.innerHTML = '';
  if (lista.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-msg">No hay usuarios registrados en este rol.</td></tr>';
    return;
  }

  lista.forEach((u, i) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${i + 1}</td>
      <td style="font-weight:700">${u.nombre}</td>
      <td class="mono" title="${u.salt}">${u.salt.slice(0,10)}…</td>
      <td class="mono" title="${u.hash}">${u.hash.slice(0,14)}…</td>
      <td><button class="btn-del" data-nombre="${u.nombre}">Eliminar</button></td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll('.btn-del').forEach(b => {
    b.addEventListener('click', () => {
      const nom = b.dataset.nombre;
      if (confirm(`¿Eliminar usuario "${nom}"?`)) {
        USUARIOS_BD = USUARIOS_BD.filter(u => u.nombre !== nom);
        persistirUsuariosLocales();
        renderAdminTabla();
        verificarPantallaInicial();
      }
    });
  });
}

// Vinculación de Eventos DOM
function bindEvents() {

  document.getElementById('bootstrapGerenteForm')?.addEventListener('submit', async e => {
    e.preventDefault();
    const bootErr = document.getElementById('bootError');
    const bootOk  = document.getElementById('bootOk');
    const nombre  = document.getElementById('bootNombre').value.trim();
    const pwd     = document.getElementById('bootPwd').value;
    const conf    = document.getElementById('bootPwdConf').value;

    bootErr.hidden = true; bootOk.hidden = true;

    if (!nombre || !/^[a-z0-9_]{3,30}$/i.test(nombre)) {
      bootErr.textContent = 'Nombre inválido (3-30 caracteres, letras/números/_)';
      bootErr.hidden = false; return;
    }
    if (pwd.length < 6) {
      bootErr.textContent = 'La contraseña debe tener al menos 6 caracteres';
      bootErr.hidden = false; return;
    }
    if (pwd !== conf) {
      bootErr.textContent = 'Las contraseñas no coinciden';
      bootErr.hidden = false; return;
    }

    try {
      const u = await registrarUsuario(nombre, 'Gerente', pwd);
      log(`Gerente Inicial creado: ${u.nombre}`, 'ok');
      bootOk.textContent = `Gerente Inicial "${u.nombre}" creado exitosamente. Ahora inicia sesión.`;
      bootOk.hidden = false;

      setTimeout(() => {
        verificarPantallaInicial();
        document.getElementById('inputUsuario').value = u.nombre;
        document.getElementById('inputPassword').focus();
        snack(`Gerente "${u.nombre}" registrado. Inicia sesión.`);
      }, 1500);
    } catch (err) {
      bootErr.textContent = err.message; bootErr.hidden = false;
    }
  });

  const bootPwd = document.getElementById('bootPwd');
  bootPwd?.addEventListener('input', () => {
    const f = evaluarFuerza(bootPwd.value);
    const b = document.getElementById('bootStrengthBar'), l = document.getElementById('bootStrengthLabel');
    if (b) { b.style.width = f.pct + '%'; b.style.backgroundColor = f.color; }
    if (l) l.textContent = f.label;
  });

  document.getElementById('btnBootEye1')?.addEventListener('click', () => {
    const i = document.getElementById('bootPwd'); i.type = i.type === 'password' ? 'text' : 'password';
  });
  document.getElementById('btnBootEye2')?.addEventListener('click', () => {
    const i = document.getElementById('bootPwdConf'); i.type = i.type === 'password' ? 'text' : 'password';
  });

  document.getElementById('loginForm')?.addEventListener('submit', async e => {
    e.preventDefault();
    const usr = document.getElementById('inputUsuario').value.trim();
    const pwd = document.getElementById('inputPassword').value;
    const errEl = document.getElementById('loginError');
    const btnTxt = document.getElementById('loginBtnText');
    const spin   = document.getElementById('loginSpinner');

    if (!usr) {
      errEl.textContent = 'Ingresa tu nombre de usuario';
      errEl.hidden = false; return;
    }
    if (!pwd) {
      errEl.textContent = 'Ingresa tu contraseña';
      errEl.hidden = false; return;
    }

    errEl.hidden = true; btnTxt.textContent = 'Verificando…'; spin.hidden = false;
    const u = await autenticar(usr, pwd);
    spin.hidden = true; btnTxt.textContent = 'Iniciar Sesión';

    if (!u) {
      errEl.textContent = 'Credenciales incorrectas';
      errEl.hidden = false;
      document.getElementById('inputPassword').value = '';
      log(`Login fallido: "${usr}"`, 'error');
      return;
    }
    sesion = { nombre: u.nombre, rol: u.rol };
    mostrarApp();
  });

  document.getElementById('btnTogglePwd')?.addEventListener('click', () => {
    const i = document.getElementById('inputPassword'); i.type = i.type === 'password' ? 'text' : 'password';
  });

  document.getElementById('btnLogout')?.addEventListener('click', cerrarSesion);

  document.getElementById('btnInicio')?.addEventListener('click', async () => {
    if (!puedeDo('inicio')) return;
    const { payload, firma } = await signCommand('INICIO');
    if (!await verifyCommand(payload, firma)) { snack('Firma HMAC inválida'); return; }
    EST.sistemaActivo = true; EST.semEntrada = 'azul'; iniciarCicloSP(); actualizarUI();
    snack('Sistema iniciado - ciclo SP activo'); log('Sistema iniciado', 'ok');
  });

  document.getElementById('btnReset')?.addEventListener('click', async () => {
    if (!puedeDo('reset')) return;
    const { payload, firma } = await signCommand('RESET');
    if (!await verifyCommand(payload, firma)) { snack('Firma HMAC inválida'); return; }
    resetSistema(); snack('Sistema en Condiciones Iniciales');
  });

  document.getElementById('btnSimE1')?.addEventListener('click', async () => {
    if (!puedeDo('simE1') || !EST.sistemaActivo) return;
    if (EST.plazasOcupadas >= 100) { snack('Estacionamiento lleno'); return; }
    const { payload, firma } = await signCommand('SIM_E1');
    if (!await verifyCommand(payload, firma)) { snack('Firma HMAC inválida'); return; }
    EST.vehiculos.push(crearVehiculoEntrada()); snack('Vehículo ingresando (E1)'); log('Simulación: vehículo en entrada', 'info');
  });

  document.getElementById('btnSimS1')?.addEventListener('click', async () => {
    if (!puedeDo('simS1') || !EST.sistemaActivo) return;
    if (EST.plazasOcupadas === 0) { snack('Garaje vacío'); return; }
    const { payload, firma } = await signCommand('SIM_S1');
    if (!await verifyCommand(payload, firma)) { snack('Firma HMAC inválida'); return; }
    EST.vehiculos.push(crearVehiculoSalida()); activarSensor('S1'); snack('Vehículo demandando salida (S1)'); log('Simulación: vehículo demanda salida', 'info');
  });

  document.getElementById('btnForzarPorton')?.addEventListener('click', async () => {
    if (!puedeDo('forzarPorton')) return;
    const { payload, firma } = await signCommand('FORZAR_PORTON');
    if (!await verifyCommand(payload, firma)) return;
    if (EST.portonEstado === 'cerrado') { EST.portonEstado = 'abriendo'; setTimeout(() => { EST.portonEstado = 'abierto'; EST.FCA = true; actualizarUI(); }, 1600); }
    else if (EST.portonEstado === 'abierto') cerrarPorton();
    snack('Portón forzado manualmente'); log('Portón forzado por el Supervisor', 'warn'); actualizarUI();
  });

  document.getElementById('btnAplicarTiempos')?.addEventListener('click', async () => {
    if (!puedeDo('ajustarTiempos')) return;
    const tv = parseInt(document.getElementById('inputTiempoVerde').value) * 1000;
    const tr = parseInt(document.getElementById('inputTiempoRojo').value) * 1000;
    if (isNaN(tv) || isNaN(tr) || tv < 5000 || tr < 10000) { snack('Tiempos fuera de rango'); return; }
    const { payload, firma } = await signCommand('AJUSTAR_TIEMPOS');
    if (!await verifyCommand(payload, firma)) return;
    EST.spVerdeMs = tv; EST.spRojoMs = tr;
    if (EST.sistemaActivo) iniciarCicloSP();
    snack(`SP actualizado: Verde ${tv/1000}s / Rojo ${tr/1000}s`); log(`Tiempos SP ajustados (Verde:${tv/1000}s Rojo:${tr/1000}s)`, 'warn');
  });

  document.getElementById('btnExportLog')?.addEventListener('click', () => {
    const csv = ['timestamp,rol,mensaje,tipo', ...auditEntries.map(e => `"${e.ts}","${e.rol}","${e.msg}","${e.tipo}"`)].join('\n');
    const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([csv], { type: 'text/csv' })), download: `scada_log_${Date.now()}.csv` });
    a.click(); URL.revokeObjectURL(a.href); log('Log exportado a CSV', 'info');
  });

  const modal = document.getElementById('adminModal');
  const openModal = () => {
    if (!puedeDo('crearUsuario')) { snack('Sin permisos para crear usuarios'); return; }
    configurarModalCrearRol();
    renderAdminTabla();
    modal.hidden = false;
  };
  const closeModal = () => { modal.hidden = true; };

  document.getElementById('btnOpenCrearUsuario')?.addEventListener('click', openModal);
  document.getElementById('btnCloseAdminModal')?.addEventListener('click', closeModal);
  document.getElementById('btnReturnToLogin')?.addEventListener('click', closeModal);

  modal?.addEventListener('click', e => {
    if (e.target === modal) closeModal();
  });

  document.getElementById('adminCrearForm')?.addEventListener('submit', async e => {
    e.preventDefault();
    const errE = document.getElementById('admError'), okE = document.getElementById('admOk');
    errE.hidden = true; okE.hidden = true;

    const nombre = document.getElementById('admNombre').value.trim();
    const rol    = document.getElementById('admRol').value;
    const pwd    = document.getElementById('admPwd').value;
    const conf   = document.getElementById('admPwdConf').value;

    if (!nombre || !/^[a-z0-9_]{3,30}$/i.test(nombre)) return showAdmErr('Nombre inválido (3-30 caracteres, letras/números/_)');
    if (!rol) return showAdmErr('Selecciona un rol válido');
    if (pwd.length < 6) return showAdmErr('Contraseña mínimo 6 caracteres');
    if (pwd !== conf) return showAdmErr('Las contraseñas no coinciden');

    const rolActivo = sesion?.rol;
    if (rolActivo === 'Gerente') {
      if (!['Supervisor', 'Operador'].includes(rol)) return showAdmErr('Un Gerente sólo puede crear usuarios Supervisor u Operador');
    } else if (rolActivo === 'Supervisor' || rolActivo === 'Ingeniero') {
      if (rol !== 'Operador') return showAdmErr('Un Supervisor sólo puede crear usuarios Operador');
    } else {
      return showAdmErr('No tienes permiso para crear usuarios');
    }

    try {
      const u = await registrarUsuario(nombre, rol, pwd);
      okE.textContent = `Usuario "${u.nombre}" [${u.rol}] creado exitosamente`; okE.hidden = false;
      document.getElementById('adminCrearForm').reset();
      renderAdminTabla();
      setTimeout(() => { okE.hidden = true; }, 3000);
    } catch (err) { showAdmErr(err.message); }

    function showAdmErr(m) { errE.textContent = m; errE.hidden = false; }
  });

  window.addEventListener('resize', resizeCanvas);
}

// Inicialización de la Aplicación
async function init() {
  await initHmacKey();
  resizeCanvas();
  cargarUsuariosLocales();
  bindEvents();
  verificarPantallaInicial();
  resetSistema();
  renderLoop();
}

document.addEventListener('DOMContentLoaded', init);
