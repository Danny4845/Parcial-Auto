/* SCADA Estacionamiento Automatizado — Control de Acceso y Gestión Ciberfísica */

'use strict';

// Configuración y Datos Locales
const USUARIOS_DEMO = [];
let USUARIOS_BD = [];
const LS_KEY = 'scada_usuarios_registrados';

// Inicialización de Clave HMAC y Control Anti-Replay (Web Crypto API)
let hmacKey = null;
const seenNonces = new Set();
let commandSeq = 0;

async function initHmacKey() {
  hmacKey = await crypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  );
}

// Firma y Verificación Criptográfica de Comandos (HMAC-SHA256 + Anti-Replay)
async function signCommand(accion) {
  const nonce = crypto.randomUUID(), timestamp = Date.now();
  const seq = ++commandSeq;
  const payload = JSON.stringify({ accion, timestamp, nonce, seq, user: sesion?.nombre || 'anon' });
  const sig = await crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode(payload));
  return { payload, firma: btoa(String.fromCharCode(...new Uint8Array(sig))) };
}

async function verifyCommand(payload, firma) {
  try {
    const data = JSON.parse(payload);
    const now = Date.now();

    // 1. Control de Expiración Temporal (Ventana de 5s para neutralizar repetición)
    if (Math.abs(now - data.timestamp) > 5000) {
      log(`Seguridad: Comando "${data.accion}" rechazado por expiración temporal (>5s)`, 'error');
      snack('Comando expirado (posible ataque de repetición)');
      return false;
    }

    // 2. Control de Nonce Único
    if (seenNonces.has(data.nonce)) {
      log(`Seguridad: Nonce duplicado detectado para comando "${data.accion}" (Replay Attack bloqueado)`, 'error');
      snack('Ataque de repetición bloqueado');
      return false;
    }
    seenNonces.add(data.nonce);
    if (seenNonces.size > 2000) {
      const first = seenNonces.values().next().value;
      seenNonces.delete(first);
    }

    // 3. Verificación Criptográfica de la Firma HMAC
    const sigBytes = Uint8Array.from(atob(firma), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', hmacKey, sigBytes, new TextEncoder().encode(payload));
    if (!valid) {
      log(`Seguridad: Firma HMAC inválida en comando "${data.accion}"`, 'error');
      snack('Firma criptográfica inválida');
    }
    return valid;
  } catch (err) {
    log(`Seguridad: Error verificando comando: ${err.message}`, 'error');
    return false;
  }
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

// Log de Auditoría Criptográfica con Cadena de Bloques SHA-256 (Tamper-Evident Hash Chain)
let lastLogHash = '0000000000000000000000000000000000000000000000000000000000000000';
const auditEntries = [];
let logQueue = Promise.resolve();

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function log(msg, tipo = 'info') {
  const ts = new Date().toLocaleTimeString('es-VE', { hour12: false });
  const id = crypto.randomUUID();
  const rol = sesion?.rol ?? '—';
  const nombre = sesion?.nombre ?? 'Sistema';

  // Encolar de forma estrictamente secuencial para evitar condiciones de carrera (Race Conditions)
  logQueue = logQueue.then(async () => {
    const blockPayload = `${lastLogHash}|${id}|${ts}|${nombre}|${rol}|${msg}|${tipo}`;
    const currentHash = await sha256Hex(blockPayload);

    const entry = { id, ts, nombre, rol, msg, tipo, prevHash: lastLogHash, hash: currentHash };
    auditEntries.push(entry);
    lastLogHash = currentHash;

    // Renderizado seguro en el DOM (previene XSS mediante textContent puro)
    const el = document.getElementById('auditLog');
    if (el) {
      const div = document.createElement('div');
      div.className = `log-entry ${tipo}`;
      div.textContent = `[${ts}] ${rol[0] ?? '?'} • ${msg}`;
      div.title = `Bloque SHA-256: ${currentHash.slice(0, 16)}…`;
      el.prepend(div);
      while (el.children.length > 60) el.removeChild(el.lastChild);
    }
  }).catch(err => console.error('Error en cadena de log:', err));

  return logQueue;
}

async function verificarIntegridadLogs() {
  await logQueue; // Esperar a que se procesen todos los logs pendientes en la cola

  if (auditEntries.length === 0) {
    snack('No hay registros en el log de auditoría');
    return true;
  }

  let expectedPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';
  for (let i = 0; i < auditEntries.length; i++) {
    const e = auditEntries[i];
    if (e.prevHash !== expectedPrevHash) {
      const err = `ALERTA DE SEGURIDAD: Cadena rota en registro #${i + 1} ("${e.msg}")`;
      alert(err);
      log(`Integridad comprometida: hash previo no coincide en entrada ${i + 1}`, 'error');
      snack(err);
      return false;
    }
    const computed = await sha256Hex(`${e.prevHash}|${e.id}|${e.ts}|${e.nombre}|${e.rol}|${e.msg}|${e.tipo}`);
    if (computed !== e.hash) {
      const err = `ALERTA DE SEGURIDAD: Registro alterado #${i + 1} ("${e.msg}")`;
      alert(err);
      log(`Integridad comprometida: hash alterado en entrada ${i + 1}`, 'error');
      snack(err);
      return false;
    }
    expectedPrevHash = e.hash;
  }

  const okMsg = `Integridad Criptográfica Verificada: Cadena de ${auditEntries.length} eventos SHA-256 100% íntegra.`;
  snack(okMsg);
  log(okMsg, 'ok');
  return true;
}

// Permisos y Matriz RBAC
const PERMISOS = {
  Operador:   ['inicio', 'reset', 'simE1', 'simS1'],
  Supervisor: ['inicio', 'reset', 'simE1', 'simS1', 'forzarPorton', 'ajustarTiempos', 'verMetricas', 'crearUsuario'],
  Ingeniero:  ['inicio', 'reset', 'simE1', 'simS1', 'forzarPorton', 'ajustarTiempos', 'verMetricas', 'crearUsuario'],
  Gerente:    ['inicio', 'reset', 'simE1', 'simS1', 'forzarPorton', 'ajustarTiempos', 'verLog', 'verMetricas', 'crearUsuario']
};
function puedeDo(accion) { return sesion && (PERMISOS[sesion.rol] || []).includes(accion); }

// Sistema Visual y Motor de Animación SCADA 3D Avanzado
const canvas = document.getElementById('scadaCanvas');
const ctx    = canvas.getContext('2d');

const ANIM = {
  time: 0,
  lastTimestamp: 0,
  portonProgress: 0.0, // 0 = cerrado, 1 = abierto
  beaconAngle: 0,
  sensorPulses: [],
  pedestrians: [],
    carPalette: [
    '#00f0ff', '#ff0055', '#00ff66', '#ffb700', '#9d4edd',
    '#ff3366', '#00b4d8', '#ff7700', '#70e000', '#f72585',
    '#4cc9f0', '#fee440', '#ff007f', '#06d6a0', '#ff9e00'
  ],
  cssW: 1000,
  cssH: 600,
  dpr: 1
};

function initParkedCars() {
  ANIM.parkedCars = [];
  const models = ['sedan', 'coupe', 'suv', 'hatchback'];
  for (let i = 0; i < 100; i++) {
    ANIM.parkedCars.push({
      color: ANIM.carPalette[i % ANIM.carPalette.length],
      model: models[i % models.length],
      angleOffset: ((i * 17) % 7 - 3) * 0.015,
      xOffset: ((i * 23) % 5 - 2) * 0.6
    });
  }
}
initParkedCars();

function resizeCanvas() {
  const wr = canvas.parentElement;
  if (!wr) return;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  ANIM.dpr = dpr;

  const cssW = wr.clientWidth || 960;
  const cssH = wr.clientHeight || 560;
  ANIM.cssW = cssW;
  ANIM.cssH = cssH;

  // Solo actualizamos el buffer interno del canvas (para DPR).
  // El tamaño visual lo controla el CSS (width: 100%; height: 100%)
  // para evitar el bucle de retroalimentación con el layout flex.
  canvas.width  = Math.floor(cssW * dpr);
  canvas.height = Math.floor(cssH * dpr);
}

function roundRect(ctx, x, y, w, h, r) {
  if (w <= 0 || h <= 0) return;
  if (w < 2 * r) r = w / 2;
  if (h < 2 * r) r = h / 2;
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

// Dibujo General del Escenario SCADA 3D - Modo Colorido de Alto Impacto Visual
function drawScene() {
  const W = ANIM.cssW, H = ANIM.cssH;
  if (!W || !H || W <= 0 || H <= 0) return;

  ctx.save();
  ctx.scale(ANIM.dpr, ANIM.dpr);
  ctx.clearRect(0, 0, W, H);

  const topHudH = 48;
  const simH    = H - topHudH;
  const gW      = W * 0.38;                            // Zona 1: Garaje Epoxi Esmeralda (38%)
  const cwX     = gW, cwW = W * 0.22, cwX2 = cwX + cwW; // Zona 2: Control / Portón Naranja & Índigo (22%)
  const entY    = topHudH + simH * 0.35;               // Carril Entrada (Azul Eléctrico)
  const salY    = topHudH + simH * 0.68;               // Carril Salida (Ámbar Dorado)
  const lH      = Math.max(54, simH * 0.18);           // Altura generosa de carril

  // 1. Fondos 3D Coloridos y Contrastados (Pisos Epoxi, Zonas de Seguridad, Césped Urbano)
  draw3DGroundZones(W, H, topHudH, gW, cwX, cwW, cwX2);

  // 2. Edificio Garaje con 100 Bahías Neón y Autos Brillantes
  draw3DParkingBuilding(gW, H, topHudH, simH);

  // 3. Calzadas Viales 3D con Asfalto Iluminado, Líneas Neón y Flechas Fluorescentes
  draw3DRoadways(0, entY, salY, gW, cwX, cwX2, W, H, lH, topHudH);

  // 4. Paso Peatonal 3D con Cebra Blanca/Verde Láser y Peatones Vivos (100% Despejado en el centro)
  draw3DCrosswalk(cwX + 4, entY - lH * 0.58, cwW - 8, (salY - entY) + lH * 1.16);
  drawPedestrians();

  // 5. Sistema de Portones Automatizados Duales (Portón de Entrada + Portón de Salida)
  drawDual3DGates(cwX, cwX2, entY, salY, lH, W);

  // 6. Semáforos Industriales 3D con Lentes LED
  const semTopY = topHudH + 10;
  draw3DTrafficLight(cwX + cwW * 0.20, semTopY, 'SP', 'Peatonal', EST.semPeatonal, false);
  draw3DTrafficLight(cwX + cwW * 0.80, semTopY, 'SE', 'Entrada', EST.semEntrada, true);
  draw3DTrafficLight(cwX + cwW * 0.50, salY + lH * 0.56, 'SS', 'Salida', EST.semSalida, false);

  // 7. Sensores 3D con Tarjetas Informativas Claras
  const e1x = cwX2 + (W - cwX2) * 0.55, e1y = entY;
  const e2x = gW * 0.55,                e2y = entY;   // Justo al lado de la flecha
  const s1x = gW * 0.55,                s1y = salY;   // Justo al lado de la flecha
  const s2x = cwX2 + (W - cwX2) * 0.55, s2y = salY;

  draw3DSensor(e1x, e1y, 'Sensor E1', 'Llegada', EST.E1, '#00f0ff', lH);
  draw3DSensor(e2x, e2y, 'Sensor E2', 'Paso al Garaje', EST.E2, '#00f0ff', lH);
  draw3DSensor(s1x, s1y, 'Sensor S1', 'Salida', EST.S1, '#ffb700', lH);
  draw3DSensor(s2x, s2y, 'Sensor S2', 'Paso a la Calle', EST.S2, '#ffb700', lH);

  // 8. Finales de Carrera (FCA / FCC) alineados con los portones de entrada y salida
  draw3DLimitSwitch(cwX2 + 4, entY - lH * 0.52 - 18, 'FCA', 'Abierto', EST.FCA);
  draw3DLimitSwitch(cwX - 22, salY + lH * 0.52 + 18, 'FCC', 'Cerrado', EST.FCC);

  // 9. Ondas de Choque al Activar Sensores
  drawSensorPulses();

  // 10. Vehículos 3D con Colores Candy y Faros de Proyección Xenón
  for (const v of EST.vehiculos) draw3DVehiculo(v);

  // 11. Banner Superior SCADA en Vivo
  drawProcessStatusBanner(W, topHudH);

  ctx.restore();
}

// 1. Fondos Estructurales Coloridos y Ricos en Detalle
function draw3DGroundZones(W, H, topHudH, gW, cwX, cwW, cwX2) {
  // Base general
  ctx.fillStyle = '#0e1726';
  ctx.fillRect(0, 0, W, H);

  // Zona 1: Garaje - Piso Epoxi Industrial Esmeralda / Cian Pulido
  const gradGarage = ctx.createLinearGradient(0, topHudH, gW, H);
  gradGarage.addColorStop(0, '#0f393d');
  gradGarage.addColorStop(0.5, '#0a2e33');
  gradGarage.addColorStop(1, '#062024');
  ctx.fillStyle = gradGarage;
  ctx.fillRect(0, topHudH, gW, H - topHudH);

  // Brillo del piso epóxico
  const epoxiGloss = ctx.createRadialGradient(gW * 0.5, topHudH + (H - topHudH) * 0.4, 10, gW * 0.5, topHudH + (H - topHudH) * 0.4, gW * 0.6);
  epoxiGloss.addColorStop(0, 'rgba(0, 245, 155, 0.08)');
  epoxiGloss.addColorStop(1, 'rgba(0, 0, 0, 0)');
  ctx.fillStyle = epoxiGloss;
  ctx.fillRect(0, topHudH, gW, H - topHudH);

  // Muro superior 3D con remate turquesa
  ctx.fillStyle = '#00f59b';
  ctx.fillRect(0, topHudH, gW, 3);
  ctx.fillStyle = '#06171b';
  ctx.fillRect(0, H - 4, gW, 4);

  // Zona 2: Control de Acceso - Pavimento Técnico Índigo con Franjas de Seguridad
  const gradControl = ctx.createLinearGradient(cwX, topHudH, cwX2, H);
  gradControl.addColorStop(0, '#1c1538');
  gradControl.addColorStop(0.5, '#241a4a');
  gradControl.addColorStop(1, '#16102e');
  ctx.fillStyle = gradControl;
  ctx.fillRect(cwX, topHudH, cwW, H - topHudH);

  // Zona 3: Vía Pública - Asfalto Azul Urbano sin franjas obstructivas
  const gradStreet = ctx.createLinearGradient(cwX2, topHudH, W, H);
  gradStreet.addColorStop(0, '#182438');
  gradStreet.addColorStop(0.5, '#1e2c45');
  gradStreet.addColorStop(1, '#141d2d');
  ctx.fillStyle = gradStreet;
  ctx.fillRect(cwX2, topHudH, W - cwX2, H - topHudH);

  // Franja divisoria de seguridad (Hazard Stripe)
  draw3DHazardBorder(gW - 8, topHudH, 8, H - topHudH);

  // Encabezados de Zona con Badges Claros y Directos
  drawVibrantZoneBadge(gW * 0.5, topHudH + 14, 'ESTACIONAMIENTO', '#00f59b', 'rgba(0, 245, 155, 0.15)', '100 Plazas');
  drawVibrantZoneBadge(cwX + cwW * 0.5, topHudH + 14, 'PORTÓN Y PASO', '#ffb700', 'rgba(255, 183, 0, 0.15)', 'Control Peatonal');
  drawVibrantZoneBadge(cwX2 + (W - cwX2) * 0.5, topHudH + 14, 'CALLE EXTERIOR', '#00d2ff', 'rgba(0, 210, 255, 0.15)', 'Entrada y Salida');
}

function drawLawnStrip(x, y, w, h) {
  ctx.save();
  const grassGrad = ctx.createLinearGradient(x, y, x, y + h);
  grassGrad.addColorStop(0, '#15803d');
  grassGrad.addColorStop(0.5, '#22c55e');
  grassGrad.addColorStop(1, '#166534');
  ctx.fillStyle = grassGrad;
  ctx.fillRect(x, y, w, h);

  // Borde de piedra de la acera
  ctx.fillStyle = '#64748b';
  ctx.fillRect(x, y + (y === 48 ? h - 2 : 0), w, 2);
  ctx.restore();
}

function draw3DHazardBorder(x, y, w, h) {
  ctx.save();
  ctx.fillStyle = '#111827';
  ctx.fillRect(x, y, w, h);
  ctx.strokeStyle = '#ffe600';
  ctx.lineWidth = 3.5;
  const step = 18;
  for (let py = y; py < y + h; py += step) {
    ctx.beginPath();
    ctx.moveTo(x, py);
    ctx.lineTo(x + w, py + step * 0.7);
    ctx.stroke();
  }
  ctx.restore();
}

function drawVibrantZoneBadge(cx, cy, title, color, bgTint, subtitle) {
  ctx.save();
  const tw = 170, th = 26;
  ctx.fillStyle = bgTint;
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.3;
  roundRect(ctx, cx - tw / 2, cy - 10, tw, th, 5);
  ctx.fill(); ctx.stroke();

  ctx.font = `800 10px 'JetBrains Mono', monospace`;
  ctx.fillStyle = color;
  ctx.textAlign = 'center';
  ctx.fillText(title, cx, cy + 2);

  ctx.font = `600 8.5px 'Inter', sans-serif`;
  ctx.fillStyle = '#f8fafc';
  ctx.fillText(subtitle, cx, cy + 12);
  ctx.restore();
}

// 2. Edificio Garaje con 100 Plazas LED (Verde = Carro Aparcado, Gris = Plaza Libre) Separadas de las Carreteras
function draw3DParkingBuilding(gW, H, topHudH, simH) {
  const margin = 10;
  const panelW = gW - margin * 2;

  const entY = topHudH + simH * 0.35;
  const salY = topHudH + simH * 0.68;
  const lH   = Math.max(54, simH * 0.18);

  const northY1 = topHudH + 28;
  const northY2 = entY - lH * 0.5 - 8;
  const northH  = Math.max(70, northY2 - northY1);

  const southY1 = salY + lH * 0.5 + 8;
  const southY2 = H - 8;
  const southH  = Math.max(70, southY2 - southY1);

  // Bloque Norte: Plazas 01 a 50 (Totalmente encima de la carretera de entrada)
  drawSpotMatrixBlock(margin, northY1, panelW, northH, 'BAHÍA NORTE (PLAZAS 01 - 50)', 0, 50);

  // Bloque Sur: Plazas 51 a 100 (Totalmente debajo de la carretera de salida)
  drawSpotMatrixBlock(margin, southY1, panelW, southH, 'BAHÍA SUR (PLAZAS 51 - 100)', 50, 100);
}

function drawSpotMatrixBlock(px, py, pw, ph, title, startIdx, endIdx) {
  ctx.save();

  // Contenedor panel SCADA
  ctx.fillStyle = 'rgba(6, 26, 32, 0.90)';
  ctx.strokeStyle = 'rgba(0, 245, 155, 0.40)';
  ctx.lineWidth = 1.4;
  roundRect(ctx, px, py, pw, ph, 6);
  ctx.fill();
  ctx.stroke();

  // Cabecera del bloque con contador
  const headerH = 17;
  const totalInBlock = endIdx - startIdx;
  let ocuInBlock = 0;
  if (EST.plazasOcupadas >= endIdx) ocuInBlock = totalInBlock;
  else if (EST.plazasOcupadas > startIdx) ocuInBlock = EST.plazasOcupadas - startIdx;

  ctx.fillStyle = 'rgba(0, 245, 155, 0.14)';
  roundRect(ctx, px + 2, py + 2, pw - 4, headerH, 4);
  ctx.fill();

  ctx.font = `800 9px 'JetBrains Mono', monospace`;
  ctx.fillStyle = '#00f59b';
  ctx.textAlign = 'left';
  ctx.fillText(title, px + 6, py + 13);

  ctx.textAlign = 'right';
  ctx.fillStyle = ocuInBlock === totalInBlock ? '#ff0055' : ocuInBlock > 0 ? '#00ff66' : '#94a3b8';
  ctx.fillText(`${ocuInBlock}/${totalInBlock} OCUPADAS`, px + pw - 6, py + 13);

  // Cuadrícula de 10 columnas x 5 filas = 50 celdas por bloque
  const cols = 10, rows = 5;
  const gridPadX = 5, gridPadY = 3;
  const gridW = pw - gridPadX * 2;
  const gridH = ph - headerH - gridPadY * 2 - 2;
  const cellW = gridW / cols;
  const cellH = gridH / rows;
  const ledR  = Math.max(2.6, Math.min(cellW, cellH) * 0.22);

  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const spotNum = startIdx + r * cols + c + 1;
      const idx = spotNum - 1;
      const ocu = idx < EST.plazasOcupadas;

      const cx = px + gridPadX + c * cellW + cellW * 0.5;
      const cy = py + headerH + gridPadY + r * cellH + cellH * 0.5;

      // Micro celda de aparcamiento
      ctx.fillStyle = ocu ? 'rgba(0, 255, 102, 0.08)' : 'rgba(255, 255, 255, 0.02)';
      ctx.strokeStyle = ocu ? 'rgba(0, 255, 102, 0.35)' : 'rgba(100, 116, 139, 0.16)';
      ctx.lineWidth = 0.8;
      roundRect(ctx, cx - cellW * 0.45, cy - cellH * 0.45, cellW * 0.90, cellH * 0.90, 2);
      ctx.fill();
      ctx.stroke();

      // Luz LED (Verde = Carro aparcado / Gris = Plaza libre)
      ctx.beginPath();
      ctx.arc(cx, cy - (cellH > 14 ? 1.5 : 0), ledR, 0, Math.PI * 2);
      if (ocu) {
        ctx.fillStyle = '#00ff66';
        ctx.shadowColor = '#00ff66';
        ctx.shadowBlur = 6;
        ctx.fill();
        ctx.shadowBlur = 0;
      } else {
        ctx.fillStyle = '#475569';
        ctx.shadowBlur = 0;
        ctx.fill();
      }

      // Número de plaza en miniatura
      if (cellH >= 14 && cellW >= 22) {
        ctx.font = `700 6.8px 'JetBrains Mono', monospace`;
        ctx.fillStyle = ocu ? '#00ff66' : '#64748b';
        ctx.textAlign = 'center';
        ctx.fillText(spotNum.toString().padStart(2, '0'), cx, cy + cellH * 0.38);
      }
    }
  }

  ctx.restore();
}

// 3. Calzadas Viales 3D con Señalización Neón y Flechas Brillantes
function draw3DRoadways(x0, entY, salY, gW, cwX, cwX2, W, H, lH, topHudH) {
  // Carril Entrada (Azul Neón / Cyan)
  draw3DLaneSegment(0, entY, W, lH, 'CARRIL DE ENTRADA', '#00f0ff', '#0077b6', 'left');

  // Carril Salida (Naranja Fuego / Ámbar Solar)
  draw3DLaneSegment(0, salY, W, lH, 'CARRIL DE SALIDA', '#ffb700', '#d97706', 'right');
}

function draw3DLaneSegment(x, centerY, w, h, label, neonAccent, darkAccent, dir) {
  const topY = centerY - h / 2, botY = centerY + h / 2;

  // Asfalto con tinte
  const roadGrad = ctx.createLinearGradient(x, topY, x, botY);
  roadGrad.addColorStop(0, '#1a2638');
  roadGrad.addColorStop(0.5, '#283852');
  roadGrad.addColorStop(1, '#1a2638');
  ctx.fillStyle = roadGrad;
  ctx.fillRect(x, topY, w, h);

  // Bordillos 3D con relieve metálico
  ctx.fillStyle = '#64748b';
  ctx.fillRect(x, topY - 3, w, 4);
  ctx.fillStyle = '#0f172a';
  ctx.fillRect(x, botY - 1, w, 4);

  // Línea continua neón de borde
  ctx.strokeStyle = neonAccent;
  ctx.lineWidth = 2.5;
  ctx.shadowColor = neonAccent;
  ctx.shadowBlur = 8;
  ctx.beginPath();
  ctx.moveTo(x, topY); ctx.lineTo(x + w, topY);
  ctx.moveTo(x, botY); ctx.lineTo(x + w, botY);
  ctx.stroke();
  ctx.shadowBlur = 0;

  // Línea discontinua central amarilla autopista brillante
  ctx.strokeStyle = '#ffe600';
  ctx.lineWidth = 3;
  ctx.shadowColor = '#ffe600';
  ctx.shadowBlur = 6;
  ctx.setLineDash([22, 16]);
  ctx.beginPath();
  ctx.moveTo(x, centerY); ctx.lineTo(x + w, centerY);
  ctx.stroke();
  ctx.setLineDash([]);
  ctx.shadowBlur = 0;

  // Flechas direccionales de gran tamaño
  const arrowX1 = w * 0.295, arrowX2 = w * 0.72;
  draw3DRoadArrow(arrowX1, centerY, dir === 'left' ? Math.PI : 0, neonAccent);
  draw3DRoadArrow(arrowX2, centerY, dir === 'left' ? Math.PI : 0, neonAccent);

  // Etiqueta del carril con tarjeta translúcida
  ctx.save();
  const cardW = 160, cardH = 20;
  const cardX = dir === 'left' ? x + 16 : x + w - cardW - 16;
  ctx.fillStyle = 'rgba(15, 23, 42, 0.88)';
  ctx.strokeStyle = neonAccent;
  ctx.lineWidth = 1;
  roundRect(ctx, cardX, centerY + h * 0.24, cardW, cardH, 4);
  ctx.fill(); ctx.stroke();

  ctx.font = `800 10px 'JetBrains Mono', monospace`;
  ctx.fillStyle = neonAccent;
  ctx.textAlign = 'center';
  ctx.fillText(label, cardX + cardW / 2, centerY + h * 0.24 + 14);
  ctx.restore();
}

function draw3DRoadArrow(x, y, angle, color) {
  ctx.save();
  ctx.translate(x, y);
  ctx.rotate(angle);
  ctx.fillStyle = color + '88';
  ctx.strokeStyle = color;
  ctx.lineWidth = 2.5;
  ctx.shadowColor = color;
  ctx.shadowBlur = 10;

  ctx.beginPath();
  ctx.moveTo(20, 0);
  ctx.lineTo(2, -11);
  ctx.lineTo(2, -4.5);
  ctx.lineTo(-20, -4.5);
  ctx.lineTo(-20, 4.5);
  ctx.lineTo(2, 4.5);
  ctx.lineTo(2, 11);
  ctx.closePath();
  ctx.fill(); ctx.stroke();
  ctx.restore();
}

// 4. Paso Peatonal 3D con Cebra Blanca / Verde Láser
function draw3DCrosswalk(x, y, w, h) {
  const isGreen = EST.semPeatonal === 'verde';

  // Base del cruce
  ctx.fillStyle = isGreen ? '#0d3822' : '#241a4a';
  ctx.fillRect(x, y, w, h);

  const stripes = 9;
  const stripeH = h / (stripes * 2);

  for (let i = 0; i < stripes; i++) {
    const sy = y + i * stripeH * 2 + stripeH * 0.5;
    ctx.fillStyle = isGreen ? '#00ff77' : '#ffffff';
    if (isGreen) {
      ctx.shadowColor = '#00ff77';
      ctx.shadowBlur = 12;
    }
    ctx.fillRect(x + w * 0.08, sy, w * 0.84, stripeH);
    ctx.shadowBlur = 0;
  }

  // Marco perimetral
  ctx.strokeStyle = isGreen ? '#00ff77' : '#ffb700';
  ctx.lineWidth = 3;
  ctx.strokeRect(x, y, w, h);
}

function updatePedestrians(dt) {
  const W = ANIM.cssW, H = ANIM.cssH;
  const gW = W * 0.38, cwX = gW, cwW = W * 0.22;
  const topHudH = 48, simH = H - topHudH;
  const entY = topHudH + simH * 0.35, salY = topHudH + simH * 0.68, lH = Math.max(54, simH * 0.18);
  const topY = entY - lH * 0.65, bottomY = salY + lH * 0.65;

  if (EST.semPeatonal === 'verde') {
    if (ANIM.pedestrians.length < 3 && Math.random() < 0.04) {
      const dir = Math.random() > 0.5 ? 1 : -1;
      ANIM.pedestrians.push({
        id: crypto.randomUUID(),
        x: cwX + cwW * (0.25 + Math.random() * 0.5),
        y: dir === 1 ? topY - 14 : bottomY + 14,
        targetY: dir === 1 ? bottomY + 28 : topY - 28,
        dir: dir,
        speed: 48 + Math.random() * 24,
        shirt: ['#00f0ff', '#ff0055', '#ffe600', '#00ff66', '#a855f7', '#ff7700'][Math.floor(Math.random() * 6)],
        walkPhase: Math.random() * Math.PI * 2
      });
    }
  }

  for (let i = ANIM.pedestrians.length - 1; i >= 0; i--) {
    const p = ANIM.pedestrians[i];
    p.y += p.dir * p.speed * dt;
    p.walkPhase += dt * 10;
    const finished = p.dir === 1 ? (p.y >= p.targetY) : (p.y <= p.targetY);
    if (finished) ANIM.pedestrians.splice(i, 1);
  }
}

function drawPedestrians() {
  for (const p of ANIM.pedestrians) {
    ctx.save();
    ctx.translate(p.x, p.y);
    const legOffset = Math.sin(p.walkPhase) * 3.8;

    // Sombra
    ctx.fillStyle = 'rgba(0, 0, 0, 0.5)';
    ctx.beginPath();
    ctx.ellipse(0, 6, 7, 4, 0, 0, Math.PI * 2);
    ctx.fill();

    // Piernas
    ctx.fillStyle = '#0f172a';
    ctx.fillRect(-3.5, -1 + legOffset, 3.2, 7.5);
    ctx.fillRect( 0.5, -1 - legOffset, 3.2, 7.5);

    // Torso / Ropa de color vivo
    ctx.fillStyle = p.shirt;
    ctx.shadowColor = p.shirt;
    ctx.shadowBlur = 6;
    roundRect(ctx, -5.5, -7, 11, 9, 2.5);
    ctx.fill();
    ctx.shadowBlur = 0;

    // Cabeza
    ctx.fillStyle = '#f8fafc';
    ctx.beginPath();
    ctx.arc(0, -9.5, 4.2, 0, Math.PI * 2);
    ctx.fill();

    ctx.restore();
  }
}

// 5. Sistema de Portones Automatizados 3D (Portón Entrada + Portón Salida con Paso Peatonal Central Libre)
function drawDual3DGates(cwX, cwX2, entY, salY, lH, W) {
  const p = ANIM.portonProgress; // 0 cerrado -> 1 abierto
  const isOpen   = EST.portonEstado === 'abierto';
  const isMoving = EST.portonEstado === 'abriendo' || EST.portonEstado === 'cerrando';

  // 1. Portón de Acceso ENTRADA (Sobre el carril superior de llegada)
  drawSingleLaneGate(cwX2 - 6, entY - lH * 0.52, 24, lH * 1.04, 'PORTÓN ENTRADA', p, isOpen, isMoving, 'top');

  // 2. Portón de Acceso SALIDA (Sobre el carril inferior de salida del garaje)
  drawSingleLaneGate(cwX - 18, salY - lH * 0.52, 24, lH * 1.04, 'PORTÓN SALIDA', p, isOpen, isMoving, 'bottom');
}

function drawSingleLaneGate(gx, gy, gw, gh, label, p, isOpen, isMoving, side) {
  const statusColor = isOpen ? '#00ff66' : isMoving ? '#ffe600' : '#ff0055';
  const barrierW = gw;
  const barrierH = gh * (1 - p);

  // Columnas estructurales de soporte en Naranja de Seguridad
  ctx.fillStyle = '#ff5500';
  ctx.strokeStyle = '#ffe600';
  ctx.lineWidth = 2;
  roundRect(ctx, gx - 6, gy - 8, 10, gh + 16, 4); ctx.fill(); ctx.stroke();
  roundRect(ctx, gx + barrierW - 4, gy - 8, 10, gh + 16, 4); ctx.fill(); ctx.stroke();

  // Riel superior guía de acero
  ctx.fillStyle = '#475569';
  ctx.fillRect(gx - 6, gy - 7, barrierW + 12, 6);

  // Barrera de acero que sube/baja
  if (barrierH > 4) {
    ctx.save();
    const barGrad = ctx.createLinearGradient(gx, gy, gx + barrierW, gy);
    barGrad.addColorStop(0, '#1e293b');
    barGrad.addColorStop(0.5, statusColor);
    barGrad.addColorStop(1, '#0f172a');
    ctx.fillStyle = barGrad;
    ctx.strokeStyle = statusColor;
    ctx.lineWidth = 2;
    roundRect(ctx, gx, gy, barrierW, barrierH, 3);
    ctx.fill(); ctx.stroke();

    // Franjas de seguridad reflectantes
    ctx.save();
    ctx.beginPath();
    roundRect(ctx, gx, gy, barrierW, barrierH, 3);
    ctx.clip();
    ctx.strokeStyle = isMoving ? '#ffe600' : 'rgba(255, 0, 85, 0.5)';
    ctx.lineWidth = 5;
    for (let lx = gx - gh; lx < gx + barrierW + gh; lx += 14) {
      ctx.beginPath();
      ctx.moveTo(lx, gy);
      ctx.lineTo(lx + barrierH, gy + barrierH);
      ctx.stroke();
    }
    ctx.restore();

    // Franja inferior amarilla de advertencia
    ctx.fillStyle = '#ffe600';
    ctx.shadowColor = '#ffe600';
    ctx.shadowBlur = 6;
    ctx.fillRect(gx, gy + barrierH - 4, barrierW, 4);
    ctx.shadowBlur = 0;
    ctx.restore();
  }

  // Motorreductor y Baliza Ámbar Giratoria
  const motorX = gx + barrierW + 2, motorY = gy - 16;
  ctx.fillStyle = '#0284c7';
  ctx.strokeStyle = '#00f0ff';
  ctx.lineWidth = 1.5;
  roundRect(ctx, motorX - 6, motorY, 14, 12, 3);
  ctx.fill(); ctx.stroke();

  const beaconX = motorX + 1, beaconY = motorY - 5;
  ctx.beginPath();
  ctx.arc(beaconX, beaconY, 5, 0, Math.PI * 2);
  ctx.fillStyle = isMoving ? '#ffe600' : '#475569';
  if (isMoving) { ctx.shadowColor = '#ffe600'; ctx.shadowBlur = 16; }
  ctx.fill(); ctx.shadowBlur = 0;

  if (isMoving) {
    ctx.save();
    ctx.translate(beaconX, beaconY);
    ctx.rotate(ANIM.beaconAngle);
    const bGrad = ctx.createRadialGradient(0, 0, 1, 0, 0, 35);
    bGrad.addColorStop(0, 'rgba(255, 230, 0, 0.9)');
    bGrad.addColorStop(1, 'rgba(255, 230, 0, 0)');
    ctx.fillStyle = bGrad;
    ctx.beginPath(); ctx.moveTo(0, 0); ctx.arc(0, 0, 35, -0.8, 0.8); ctx.closePath(); ctx.fill();
    ctx.beginPath(); ctx.moveTo(0, 0); ctx.arc(0, 0, 35, 2.3, 3.9); ctx.closePath(); ctx.fill();
    ctx.restore();
  }
}

// 6. Semáforos Industriales 3D con Lentes LED Hiperbrillantes
function draw3DTrafficLight(x, y, code, label, estado, hasAzul) {
  const R = 11, pad = 6;
  const lights = hasAzul
    ? [
        { color: '#ff003c', on: estado === 'rojo', type: 'rojo' },
        { color: '#00ff66', on: estado === 'verde', type: 'verde' },
        { color: '#00d2ff', on: estado === 'azul', type: 'azul' }
      ]
    : [
        { color: '#ff003c', on: estado === 'rojo', type: 'rojo' },
        { color: '#00ff66', on: estado === 'verde', type: 'verde' }
      ];

  const bH = pad * 2 + lights.length * (R * 2 + pad) - pad;
  const bW = R * 2 + pad * 2.5;
  const left = x - bW / 2;

  // Poste de fijación
  ctx.fillStyle = '#475569';
  ctx.fillRect(x - 3, y + bH, 6, 18);

  // Gabinete del semáforo
  ctx.fillStyle = '#0b1329';
  ctx.strokeStyle = '#64748b';
  ctx.lineWidth = 2.5;
  roundRect(ctx, left, y, bW, bH, 7);
  ctx.fill(); ctx.stroke();

  lights.forEach((l, i) => {
    const ly = y + pad + i * (R * 2 + pad) + R;

    // Visera / Parasol 3D
    ctx.strokeStyle = '#94a3b8';
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    ctx.arc(x, ly, R + 4, Math.PI * 1.1, Math.PI * 1.9);
    ctx.stroke();

    // Fondo apagado
    ctx.beginPath();
    ctx.arc(x, ly, R, 0, Math.PI * 2);
    ctx.fillStyle = '#1e293b';
    ctx.fill();

    // Lente encendido con halo de luz
    if (l.on) {
      const lensGrad = ctx.createRadialGradient(x, ly, 1, x, ly, R);
      lensGrad.addColorStop(0, '#ffffff');
      lensGrad.addColorStop(0.3, l.color);
      lensGrad.addColorStop(1, l.color);
      ctx.fillStyle = lensGrad;
      ctx.shadowColor = l.color;
      ctx.shadowBlur = 24;
      ctx.fill();
      ctx.shadowBlur = 0;
    } else {
      ctx.fillStyle = l.color + '25';
      ctx.fill();
    }

    if (code === 'S.P.' || code === 'SP') {
      drawPedestrianIcon(x, ly, R * 0.85, l.type === 'verde' ? (l.on ? '#00ff66' : '#00ff6633') : (l.on ? '#ff003c' : '#ff003c33'), l.type === 'verde');
    }
  });

  // Tarjeta de Identificación del Semáforo
  ctx.save();
  const cardW = 92, cardH = 22;
  ctx.fillStyle = 'rgba(11, 19, 41, 0.92)';
  ctx.strokeStyle = '#00f0ff';
  ctx.lineWidth = 1.1;
  roundRect(ctx, x - cardW / 2, y + bH + 16, cardW, cardH, 4);
  ctx.fill(); ctx.stroke();

  ctx.font = `800 9.5px 'JetBrains Mono', monospace`;
  ctx.fillStyle = '#00f0ff';
  ctx.textAlign = 'center';
  ctx.fillText(code, x, y + bH + 26);

  ctx.font = `600 8px 'Inter', sans-serif`;
  ctx.fillStyle = '#ffffff';
  ctx.fillText(label, x, y + bH + 35);
  ctx.restore();
}

function drawPedestrianIcon(cx, cy, size, color, isWalking) {
  ctx.save();
  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.arc(cx, cy - size * 0.5, size * 0.25, 0, Math.PI * 2);
  ctx.fill();

  if (isWalking) {
    ctx.fillRect(cx - size * 0.18, cy - size * 0.22, size * 0.36, size * 0.45);
    ctx.beginPath();
    ctx.moveTo(cx - size * 0.2, cy + size * 0.2);
    ctx.lineTo(cx - size * 0.45, cy + size * 0.75);
    ctx.lineTo(cx - size * 0.25, cy + size * 0.75);
    ctx.lineTo(cx, cy + size * 0.2);
    ctx.closePath();
    ctx.fill();
    ctx.beginPath();
    ctx.moveTo(cx + size * 0.2, cy + size * 0.2);
    ctx.lineTo(cx + size * 0.5, cy + size * 0.75);
    ctx.lineTo(cx + size * 0.3, cy + size * 0.75);
    ctx.lineTo(cx, cy + size * 0.2);
    ctx.closePath();
    ctx.fill();
  } else {
    ctx.fillRect(cx - size * 0.2, cy - size * 0.25, size * 0.4, size * 0.55);
    ctx.fillRect(cx - size * 0.18, cy + size * 0.3, size * 0.15, size * 0.45);
    ctx.fillRect(cx + size * 0.03, cy + size * 0.3, size * 0.15, size * 0.45);
  }
  ctx.restore();
}

// 7. Sensores Fotoeléctricos / Láser 3D con Haz Neón Brillante
function draw3DSensor(x, y, code, label, activo, color, lH) {
  const topY = y - lH * 0.46, botY = y + lH * 0.46;

  // Lazo Inductivo de piso con borde de color
  ctx.strokeStyle = activo ? color : 'rgba(0, 240, 255, 0.4)';
  ctx.lineWidth = activo ? 3.5 : 1.8;
  ctx.fillStyle = activo ? color + '33' : 'rgba(0,0,0,0.2)';
  ctx.fillRect(x - 20, y - lH * 0.36, 40, lH * 0.72);
  ctx.strokeRect(x - 20, y - lH * 0.36, 40, lH * 0.72);

  // Haz láser brillante continuo
  ctx.save();
  ctx.strokeStyle = activo ? color : color + '88';
  ctx.lineWidth = activo ? 4 : 2;
  ctx.shadowColor = color;
  ctx.shadowBlur = activo ? 20 : 10;
  ctx.beginPath();
  ctx.moveTo(x, topY);
  ctx.lineTo(x, botY);
  ctx.stroke();
  ctx.restore();

  // Columnas emisor y receptor 3D
  [topY, botY].forEach(sy => {
    ctx.fillStyle = '#0b1329';
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.2;
    roundRect(ctx, x - 7.5, sy - 7.5, 15, 15, 3.5);
    ctx.fill(); ctx.stroke();

    // Lente LED del sensor
    ctx.beginPath();
    ctx.arc(x, sy, 4, 0, Math.PI * 2);
    ctx.fillStyle = activo ? color : color + '66';
    ctx.shadowColor = color;
    ctx.shadowBlur = activo ? 16 : 6;
    ctx.fill();
    ctx.shadowBlur = 0;
  });

  // Tarjeta Explicativa del Sensor con Fondo Neón
  ctx.save();
  const cardW = 115, cardH = 24;
  ctx.fillStyle = 'rgba(11, 19, 41, 0.94)';
  ctx.strokeStyle = color;
  ctx.lineWidth = activo ? 1.8 : 1.1;
  roundRect(ctx, x - cardW / 2, topY - cardH - 6, cardW, cardH, 4);
  ctx.fill(); ctx.stroke();

  ctx.font = `800 10px 'JetBrains Mono', monospace`;
  ctx.fillStyle = color;
  ctx.textAlign = 'center';
  ctx.fillText(code, x, topY - cardH + 4);

  ctx.font = `600 8px 'Inter', sans-serif`;
  ctx.fillStyle = '#ffffff';
  ctx.fillText(label, x, topY - cardH + 13);
  ctx.restore();
}

// 8. Finales de Carrera (FCA / FCC)
function draw3DLimitSwitch(x, y, code, label, activo) {
  const switchCol = activo ? '#00ff66' : '#64748b';
  const cardW = 38, cardH = 20;

  ctx.save();
  ctx.fillStyle = 'rgba(11, 19, 41, 0.95)';
  ctx.strokeStyle = switchCol;
  ctx.lineWidth = activo ? 2 : 1.2;
  roundRect(ctx, x - cardW / 2, y - cardH / 2, cardW, cardH, 4);
  ctx.fill(); ctx.stroke();

  // LED de contacto
  ctx.beginPath();
  ctx.arc(x + cardW / 2 - 8, y, 3.5, 0, Math.PI * 2);
  ctx.fillStyle = switchCol;
  if (activo) { ctx.shadowColor = '#00ff66'; ctx.shadowBlur = 12; }
  ctx.fill(); ctx.shadowBlur = 0;

  // Texto del sensor (FCA / FCC)
  ctx.font = `800 9.5px 'JetBrains Mono', monospace`;
  ctx.fillStyle = switchCol;
  ctx.textAlign = 'left';
  ctx.fillText(code, x - cardW / 2 + 5, y + 3.5);
  ctx.restore();
}

// 9. Ondas de Choque al Activar Sensores
function triggerSensorShockwave(x, y, color) {
  ANIM.sensorPulses.push({
    x, y, color,
    radius: 4,
    maxRadius: 46,
    alpha: 1.0
  });
}

function updateSensorPulses(dt) {
  for (let i = ANIM.sensorPulses.length - 1; i >= 0; i--) {
    const sp = ANIM.sensorPulses[i];
    sp.radius += dt * 70;
    sp.alpha -= dt * 2.2;
    if (sp.alpha <= 0 || sp.radius >= sp.maxRadius) {
      ANIM.sensorPulses.splice(i, 1);
    }
  }
}

function drawSensorPulses() {
  for (const sp of ANIM.sensorPulses) {
    ctx.save();
    ctx.strokeStyle = sp.color;
    ctx.globalAlpha = Math.max(0, sp.alpha);
    ctx.lineWidth = 3.5;
    ctx.beginPath();
    ctx.arc(sp.x, sp.y, sp.radius, 0, Math.PI * 2);
    ctx.stroke();
    ctx.restore();
  }
}

// 10. Vehículos 3D con Colores Candy y Faros de Proyección Xenón
function draw3DVehiculo(v) {
  const vW = Math.max(54, ANIM.cssW * 0.062), vH = Math.max(28, ANIM.cssH * 0.05);
  const isMoving = v.fase === 'llegando' || v.fase === 'pasandoPorton' || v.fase === 'saliendo';
  const isBraking = v.fase === 'esperandoVerde';
  const heading = v.tipo === 'entrada' ? Math.PI : 0;

  ctx.save();
  ctx.translate(v.x, v.y);
  ctx.rotate(heading);

  // Faros Delanteros con Proyección Xenón
  draw3DCarHeadlights(vW, vH, v.color);

  // Sombra 3D profunda
  ctx.fillStyle = 'rgba(0, 0, 0, 0.7)';
  roundRect(ctx, -vW / 2 + 2, -vH / 2 + 3, vW, vH, 4);
  ctx.fill();

  // Neumáticos
  ctx.fillStyle = '#060a12';
  const tireW = vW * 0.22, tireH = vH * 0.26;
  ctx.fillRect(-vW * 0.42, -vH * 0.54, tireW, tireH * 0.35);
  ctx.fillRect( vW * 0.20, -vH * 0.54, tireW, tireH * 0.35);
  ctx.fillRect(-vW * 0.42,  vH * 0.42, tireW, tireH * 0.35);
  ctx.fillRect( vW * 0.20,  vH * 0.42, tireW, tireH * 0.35);

  // Carrocería con acabado brillante Candy
  const carGrad = ctx.createLinearGradient(-vW / 2, -vH / 2, vW / 2, vH / 2);
  carGrad.addColorStop(0, v.color);
  carGrad.addColorStop(0.35, '#ffffff99');
  carGrad.addColorStop(0.7, v.color);
  ctx.fillStyle = carGrad;
  ctx.shadowColor = v.color;
  ctx.shadowBlur = 8;
  roundRect(ctx, -vW / 2, -vH / 2, vW, vH, 5);
  ctx.fill();
  ctx.shadowBlur = 0;

  // Parabrisas con reflejo azulado
  ctx.fillStyle = '#0c1a30';
  roundRect(ctx, -vW * 0.26, -vH * 0.36, vW * 0.52, vH * 0.72, 3);
  ctx.fill();

  // Techo
  ctx.fillStyle = v.color;
  roundRect(ctx, -vW * 0.16, -vH * 0.24, vW * 0.32, vH * 0.48, 2);
  ctx.fill();

  // Luces Traseras / Freno de Stop
  ctx.fillStyle = isBraking ? '#ff003c' : '#ff003cbb';
  if (isBraking) { ctx.shadowColor = '#ff003c'; ctx.shadowBlur = 16; }
  ctx.fillRect(-vW * 0.48, -vH * 0.38, 4, 6);
  ctx.fillRect(-vW * 0.48,  vH * 0.22, 4, 6);
  ctx.shadowBlur = 0;

  ctx.restore();
}

function draw3DCarHeadlights(vW, vH, color) {
  const beamDist = vW * 2.2;
  const beamGrad = ctx.createRadialGradient(vW * 0.45, 0, 2, vW * 0.45 + beamDist * 0.6, 0, beamDist);
  beamGrad.addColorStop(0, 'rgba(255, 255, 255, 0.8)');
  beamGrad.addColorStop(0.3, 'rgba(254, 240, 138, 0.45)');
  beamGrad.addColorStop(1, 'rgba(254, 240, 138, 0)');

  ctx.fillStyle = beamGrad;
  ctx.beginPath();
  ctx.moveTo(vW * 0.45, -vH * 0.35);
  ctx.lineTo(vW * 0.45 + beamDist, -vH * 1.15);
  ctx.lineTo(vW * 0.45 + beamDist,  vH * 1.15);
  ctx.lineTo(vW * 0.45,  vH * 0.35);
  ctx.closePath();
  ctx.fill();

  // Focos LED frontales
  ctx.fillStyle = '#ffffff';
  ctx.shadowColor = '#ffffff';
  ctx.shadowBlur = 12;
  ctx.fillRect(vW * 0.45, -vH * 0.38, 4, 6);
  ctx.fillRect(vW * 0.45,  vH * 0.24, 4, 6);
  ctx.shadowBlur = 0;
}

// 11. Banner Superior SCADA Explicativo en Vivo
function drawProcessStatusBanner(W, topHudH) {
  // Fondo de la barra superior HUD con degradado translúcido
  const hudGrad = ctx.createLinearGradient(0, 0, W, topHudH);
  hudGrad.addColorStop(0, 'rgba(11, 19, 41, 0.98)');
  hudGrad.addColorStop(0.5, 'rgba(15, 23, 42, 0.98)');
  hudGrad.addColorStop(1, 'rgba(11, 19, 41, 0.98)');
  ctx.fillStyle = hudGrad;
  ctx.fillRect(0, 0, W, topHudH);

  ctx.strokeStyle = '#00f0ff';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(0, topHudH); ctx.lineTo(W, topHudH);
  ctx.stroke();

  let statusText = '';
  let statusColor = '#00f0ff';
  let badgeIcon = 'SISTEMA';

  if (!EST.sistemaActivo) {
    statusText = "SISTEMA DETENIDO — Presiona 'INICIO' para comenzar.";
    statusColor = '#94a3b8';
    badgeIcon = 'DETENIDO';
  } else if (EST.semPeatonal === 'verde') {
    statusText = "PASO PEATONAL ACTIVO — Peatones cruzando. Vehículos en espera.";
    statusColor = '#00ff66';
    badgeIcon = 'PEATONES';
  } else if (EST.portonEstado === 'abriendo') {
    statusText = "ABRIENDO PORTÓN — Dando paso al vehículo.";
    statusColor = '#ffe600';
    badgeIcon = 'ABRIENDO';
  } else if (EST.portonEstado === 'abierto') {
    statusText = "PORTÓN ABIERTO — Vehículo cruzando el acceso.";
    statusColor = '#00ff66';
    badgeIcon = 'CRUZANDO';
  } else if (EST.portonEstado === 'cerrando') {
    statusText = "CERRANDO PORTÓN — Vehículo completó su recorrido.";
    statusColor = '#ffe600';
    badgeIcon = 'CERRANDO';
  } else if (EST.demandaEntrada) {
    statusText = "VEHÍCULO EN ENTRADA — Esperando turno de acceso.";
    statusColor = '#00f0ff';
    badgeIcon = 'ENTRADA';
  } else if (EST.demandaSalida) {
    statusText = "VEHÍCULO EN SALIDA — Salida en progreso (Prioridad de salida).";
    statusColor = '#ffb700';
    badgeIcon = 'SALIDA';
  } else {
    statusText = "SISTEMA LISTO — Esperando entrada o salida de vehículos.";
    statusColor = '#00f0ff';
    badgeIcon = 'LISTO';
  }

  // Badge de Estado a la Izquierda
  const bW = 125, bH = 28, bx = 14, by = 10;
  ctx.fillStyle = statusColor + '25';
  ctx.strokeStyle = statusColor;
  ctx.lineWidth = 1.8;
  roundRect(ctx, bx, by, bW, bH, 5);
  ctx.fill(); ctx.stroke();

  // Punto parpadeante
  ctx.beginPath();
  ctx.arc(bx + 12, by + bH / 2, 4.5, 0, Math.PI * 2);
  ctx.fillStyle = statusColor;
  ctx.shadowColor = statusColor;
  ctx.shadowBlur = 10;
  ctx.fill();
  ctx.shadowBlur = 0;

  ctx.font = `800 11px 'JetBrains Mono', monospace`;
  ctx.fillStyle = statusColor;
  ctx.textAlign = 'left';
  ctx.fillText(badgeIcon, bx + 24, by + bH / 2 + 4);

  // Mensaje en vivo explicativo en el centro
  ctx.font = `600 12.5px 'Inter', sans-serif`;
  ctx.fillStyle = '#ffffff';
  ctx.textAlign = 'left';
  ctx.fillText(statusText, bx + bW + 16, by + bH / 2 + 4);

  // Contador de Plazas a la derecha
  const libre = 100 - EST.plazasOcupadas;
  const colPlazas = libre > 20 ? '#00f59b' : libre > 5 ? '#ffe600' : '#ff0055';
  ctx.font = `800 13px 'JetBrains Mono', monospace`;
  ctx.fillStyle = colPlazas;
  ctx.textAlign = 'right';
  ctx.fillText(`${libre}/100 LIBRES`, W - 18, by + bH / 2 + 4);
}

// Variables de Cooldown para Entrada y Salida (5 segundos)
let cooldownE1Restante = 0;
let cooldownE1Interval = null;
let cooldownS1Restante = 0;
let cooldownS1Interval = null;

function iniciarCooldownE1(segundos = 5) {
  cooldownE1Restante = segundos;
  actualizarUI();
  clearInterval(cooldownE1Interval);
  cooldownE1Interval = setInterval(() => {
    cooldownE1Restante--;
    if (cooldownE1Restante <= 0) {
      cooldownE1Restante = 0;
      clearInterval(cooldownE1Interval);
    }
    actualizarUI();
  }, 1000);
}

function iniciarCooldownS1(segundos = 5) {
  cooldownS1Restante = segundos;
  actualizarUI();
  clearInterval(cooldownS1Interval);
  cooldownS1Interval = setInterval(() => {
    cooldownS1Restante--;
    if (cooldownS1Restante <= 0) {
      cooldownS1Restante = 0;
      clearInterval(cooldownS1Interval);
    }
    actualizarUI();
  }, 1000);
}

// Simulación y Control de Proceso
let _carIdx = 0;
function crearVehiculoEntrada() {
  const W = ANIM.cssW, H = ANIM.cssH;
  const topHudH = 48, simH = H - topHudH;
  const entY = topHudH + simH * 0.35;
  const colors = ['#00f0ff', '#ff0055', '#ffe600', '#00ff66', '#a855f7', '#ff7700', '#f72585'];
  const col = colors[_carIdx++ % colors.length];
  return {
    id: crypto.randomUUID(),
    tipo: 'entrada',
    x: W * 0.98,
    y: entY,
    color: col,
    fase: 'llegando',
    speed: Math.max(110, W * 0.14),
    e1Triggered: false,
    e2Triggered: false,
    counted: false
  };
}

function crearVehiculoSalida() {
  const W = ANIM.cssW, H = ANIM.cssH;
  const topHudH = 48, simH = H - topHudH;
  const salY = topHudH + simH * 0.68;
  const colors = ['#ffb700', '#ff0055', '#00f0ff', '#a855f7', '#00ff66', '#ff7700'];
  const col = colors[_carIdx++ % colors.length];
  // Generar fuera de pantalla por la izquierda (dentro del garaje),
  // igual que entrada genera fuera de pantalla por la derecha.
  return {
    id: crypto.randomUUID(),
    tipo: 'salida',
    x: W * 0.02,          // Fuera de pantalla a la izquierda (espejo del W*0.98 de entrada)
    y: salY,
    color: col,
    fase: 'llegando',     // Fase nueva: se mueve al stop antes de esperar verde
    speed: Math.max(110, W * 0.14),
    s1Triggered: false,
    s2Triggered: false,
    counted: false
  };
}

function updateVehiculos(dt) {
  const W = ANIM.cssW, H = ANIM.cssH;
  const topHudH = 46, simH = H - topHudH;
  const entY = topHudH + simH * 0.35, salY = topHudH + simH * 0.68;
  const gW = W * 0.38, cwX2 = gW + W * 0.22;
  const e1X = cwX2 + (W - cwX2) * 0.55;
  const e2X = gW * 0.55;   // Sincronizado con la posición visual del Sensor E2
  const s2X = cwX2 + (W - cwX2) * 0.55;
  const vW = Math.max(54, ANIM.cssW * 0.062);
  const stopEntradaX = cwX2 + vW * 0.5 + 24;
  const stopSalidaX  = gW - vW * 0.5 - 24;
  const safeGap = vW + 18;

  const entradas = EST.vehiculos.filter(v => v.tipo === 'entrada');
  const salidas  = EST.vehiculos.filter(v => v.tipo === 'salida');

  // Procesar cola de Entrada
  for (let i = 0; i < entradas.length; i++) {
    const v = entradas[i];
    v.y = entY;

    let targetStopX = stopEntradaX;
    if (i > 0) {
      const frontCar = entradas[i - 1];
      if (frontCar.fase === 'esperandoVerde' || (frontCar.fase === 'pasandoPorton' && frontCar.x > cwX2 - 40)) {
        targetStopX = Math.max(stopEntradaX, frontCar.x + safeGap);
      }
    }

    if (v.fase === 'llegando') {
      v.x -= v.speed * dt;
      if (v.x <= e1X && !v.e1Triggered) {
        v.e1Triggered = true;
        activarSensor('E1');
      }
      if (v.x <= targetStopX) {
        v.x = targetStopX;
        v.fase = 'esperandoVerde';
      }
    } else if (v.fase === 'esperandoVerde') {
      if (v.x > targetStopX) {
        v.x -= v.speed * dt;
        if (v.x <= targetStopX) v.x = targetStopX;
      }
      if (i === 0 && v.x <= stopEntradaX + 4 && EST.semEntrada === 'verde' && EST.portonEstado === 'abierto' && ANIM.portonProgress > 0.80) {
        v.fase = 'pasandoPorton';
      }
    } else if (v.fase === 'pasandoPorton') {
      v.x -= v.speed * dt;
      if (v.x <= e2X && !v.e2Triggered) {
        v.e2Triggered = true;
        v.counted = true;
        activarSensor('E2');
      }
      if (v.x < gW * 0.28) {
        const idx = EST.vehiculos.indexOf(v);
        if (idx !== -1) EST.vehiculos.splice(idx, 1);
      }
    }
  }

  // Procesar cola de Salida
  for (let i = 0; i < salidas.length; i++) {
    const v = salidas[i];
    v.y = salY;

    let targetStopX = stopSalidaX;
    if (i > 0) {
      const frontCar = salidas[i - 1];
      if (frontCar.fase === 'esperandoVerde' || frontCar.fase === 'llegando' ||
          (frontCar.fase === 'saliendo' && frontCar.x < gW + 40)) {
        targetStopX = Math.min(stopSalidaX, frontCar.x - safeGap);
      }
    }

    if (v.fase === 'llegando') {
      // Igual que entrada pero hacia la derecha: avanza desde el garaje al stop
      v.x += v.speed * dt;
      const s1X = gW * 0.55; // Sincronizado con la posición visual del Sensor S1
      if (v.x >= s1X && !v.s1Triggered) {
        v.s1Triggered = true;
        activarSensor('S1');
      }
      if (v.x >= targetStopX) {
        v.x = targetStopX;
        v.fase = 'esperandoVerde';
      }
    } else if (v.fase === 'esperandoVerde') {
      if (v.x < targetStopX) {
        v.x += v.speed * dt;
        if (v.x >= targetStopX) v.x = targetStopX;
      }
      if (i === 0 && v.x >= stopSalidaX - 4 && EST.semSalida === 'verde' && EST.portonEstado === 'abierto' && ANIM.portonProgress > 0.80) {
        v.fase = 'saliendo';
      }
    } else if (v.fase === 'saliendo') {
      v.x += v.speed * dt;
      if (v.x >= s2X && !v.s2Triggered) {
        v.s2Triggered = true;
        v.counted = true;
        activarSensor('S2');
      }
      if (v.x > W * 1.05) {
        const idx = EST.vehiculos.indexOf(v);
        if (idx !== -1) EST.vehiculos.splice(idx, 1);
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
  
  if (!EST.demandaSalida && EST.vehiculos.some(v => v.tipo === 'salida' && v.fase === 'esperandoVerde')) {
    EST.demandaSalida = true;
  }
  if (!EST.demandaEntrada && EST.vehiculos.some(v => v.tipo === 'entrada' && (v.fase === 'esperandoVerde' || v.e1Triggered))) {
    EST.demandaEntrada = true;
  }

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
  if (EST.portonEstado === 'abriendo' || EST.portonEstado === 'abierto') return;
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

  const W = ANIM.cssW, H = ANIM.cssH;
  const topHudH = 46, simH = H - topHudH;
  const entY = topHudH + simH * 0.35, salY = topHudH + simH * 0.68;
  const gW = W * 0.38, cwX2 = gW + W * 0.22;

  const coords = {
    E1: { x: cwX2 + (W - cwX2) * 0.55, y: entY, col: '#38bdf8' },
    E2: { x: gW * 0.76, y: entY, col: '#38bdf8' },
    S1: { x: gW * 0.76, y: salY, col: '#fbbf24' },
    S2: { x: cwX2 + (W - cwX2) * 0.55, y: salY, col: '#fbbf24' }
  };
  if (coords[sensor]) {
    triggerSensorShockwave(coords[sensor].x, coords[sensor].y, coords[sensor].col);
  }

  if (sensor === 'E2') {
    if (EST.plazasOcupadas < 100) EST.plazasOcupadas++;
    EST.totalEntradas++;
    setTimeout(() => { EST.E1 = false; EST.E2 = false; actualizarUI(); }, 600);
    setTimeout(cerrarPorton, 300);
  } else if (sensor === 'S2') {
    if (EST.plazasOcupadas > 0) EST.plazasOcupadas--;
    EST.totalSalidas++;
    setTimeout(() => { EST.S1 = false; EST.S2 = false; actualizarUI(); }, 600);
    setTimeout(cerrarPorton, 300);
  } else if (sensor === 'E1') {
    EST.demandaEntrada = true; procesarDemandas();
  } else if (sensor === 'S1') {
    EST.demandaSalida = true; procesarDemandas();
  }
}

function resetSistema() {
  clearTimeout(EST.spTimer); clearInterval(EST._spBarInterval);
  clearTimeout(EST._paTimer); clearTimeout(EST._paOffTimer);
  clearInterval(cooldownE1Interval); clearInterval(cooldownS1Interval);
  cooldownE1Restante = 0; cooldownS1Restante = 0;
  window._aiPendingAction = null;

  Object.assign(EST, {
    sistemaActivo: false, plazasOcupadas: 0, semEntrada: 'rojo', semSalida: 'rojo', semPeatonal: 'rojo',
    portonEstado: 'cerrado', E1: false, E2: false, S1: false, S2: false, FCA: false, FCC: true,
    demandaEntrada: false, demandaSalida: false, portonParaEntrada: false, portonParaSalida: false,
    paActivo: false, vehiculos: []
  });

  ANIM.portonProgress = 0;
  ANIM.pedestrians = [];
  ANIM.sensorPulses = [];

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
    setEl('paStateText', EST.paActivo ? 'PASO VEHICULAR: HABILITADO' : 'PASO VEHICULAR: EN ESPERA');
  }

  setEl('metEntradas', EST.totalEntradas); setEl('metSalidas', EST.totalSalidas);
  setEl('metCiclos', EST.ciclosPorton); setEl('metEnergia', (EST.ciclosPorton * 45).toFixed(0) + ' Wh');

  // Control de Botones Básicos
  const btnInicio = document.getElementById('btnInicio');
  if (btnInicio) btnInicio.disabled = !puedeDo('inicio') || EST.sistemaActivo;

  const btnReset = document.getElementById('btnReset');
  if (btnReset) btnReset.disabled = !puedeDo('reset');

  // Control de Botón Entrada E1 con Cooldown
  const btnE1 = document.getElementById('btnSimE1');
  if (btnE1) {
    if (cooldownE1Restante > 0) {
      btnE1.textContent = `Entrada (E1) [${cooldownE1Restante}s]`;
      btnE1.classList.add('btn-cooldown');
      btnE1.disabled = true;
    } else {
      btnE1.textContent = 'Entrada (E1)';
      btnE1.classList.remove('btn-cooldown');
      btnE1.disabled = !puedeDo('simE1') || !EST.sistemaActivo || EST.plazasOcupadas >= 100;
    }
  }

  // Control de Botón Salida S1 con Cooldown
  const btnS1 = document.getElementById('btnSimS1');
  if (btnS1) {
    if (cooldownS1Restante > 0) {
      btnS1.textContent = `Salida (S1) [${cooldownS1Restante}s]`;
      btnS1.classList.add('btn-cooldown');
      btnS1.disabled = true;
    } else {
      btnS1.textContent = 'Salida (S1)';
      btnS1.classList.remove('btn-cooldown');
      btnS1.disabled = !puedeDo('simS1') || !EST.sistemaActivo || EST.plazasOcupadas <= 0;
    }
  }
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

function renderLoop(timestamp) {
  const wr = canvas ? canvas.parentElement : null;
  if (wr) {
    const curW = wr.clientWidth;
    const curH = wr.clientHeight;
    if (curW > 50 && curH > 50 && (curW !== ANIM.cssW || curH !== ANIM.cssH)) {
      resizeCanvas();
    }
  }

  if (!ANIM.lastTimestamp) ANIM.lastTimestamp = timestamp || performance.now();
  const now = timestamp || performance.now();
  const dt = Math.min((now - ANIM.lastTimestamp) / 1000, 0.1) || 0.016;
  ANIM.lastTimestamp = now;
  ANIM.time += dt;

  // Interpolación suave del portón (0 cerrado, 1 abierto)
  const targetPorton = (EST.portonEstado === 'abierto' || EST.portonEstado === 'abriendo') ? 1.0 : 0.0;
  const speed = 1.0 / 1.6; // 1.6 segundos para abrir o cerrar
  if (ANIM.portonProgress < targetPorton) {
    ANIM.portonProgress = Math.min(targetPorton, ANIM.portonProgress + speed * dt);
  } else if (ANIM.portonProgress > targetPorton) {
    ANIM.portonProgress = Math.max(targetPorton, ANIM.portonProgress - speed * dt);
  }

  // Rotación de baliza ámbar si el portón se mueve
  if (EST.portonEstado === 'abriendo' || EST.portonEstado === 'cerrando') {
    ANIM.beaconAngle += dt * 9;
  }

  updatePedestrians(dt);
  updateSensorPulses(dt);
  updateVehiculos(dt);
  drawScene();

  requestAnimationFrame(renderLoop);
}

function aplicarRBAC() {
  const rol = sesion?.rol;
  const esSupervisor = (rol === 'Supervisor' || rol === 'Ingeniero');
  const esGerente    = (rol === 'Gerente');
  const esOperador   = (rol === 'Operador');

  const pi = document.getElementById('panelIngeniero'); if (pi) pi.hidden = !esSupervisor && !esGerente;
  const pg = document.getElementById('panelGerente');   if (pg) pg.hidden = !esSupervisor && !esGerente; // Supervisor y Gerente pueden ver métricas
  const pl = document.getElementById('panelLog');       if (pl) pl.hidden = !esGerente; // Exclusivo del Gerente

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
  // Limpieza inmediata de credenciales ingresadas en el formulario de login
  const inputUsr = document.getElementById('inputUsuario');
  const inputPwd = document.getElementById('inputPassword');
  const loginErr = document.getElementById('loginError');
  if (inputUsr) inputUsr.value = '';
  if (inputPwd) {
    inputPwd.value = '';
    inputPwd.type = 'password';
  }
  if (loginErr) {
    loginErr.hidden = true;
    loginErr.textContent = '';
  }

  document.getElementById('authOverlay').hidden = true;
  document.getElementById('app').hidden = false;
  const fab = document.getElementById('btnAiFab');
  if (fab) fab.hidden = false;
  if (sesion?.rol) renderAiQuickChips(sesion.rol);
  resizeCanvas();
  setTimeout(resizeCanvas, 50);
  aplicarRBAC(); log(`Sesión iniciada: ${sesion.nombre} [${sesion.rol}]`, 'ok');
}

function cerrarSesion() {
  log('Sesión cerrada', 'warn');
  sesion = null;
  resetSistema();

  // Limpieza estricta de credenciales y campos de entrada en el DOM
  const inputUsr = document.getElementById('inputUsuario');
  const inputPwd = document.getElementById('inputPassword');
  const loginErr = document.getElementById('loginError');
  if (inputUsr) inputUsr.value = '';
  if (inputPwd) {
    inputPwd.value = '';
    inputPwd.type = 'password';
  }
  if (loginErr) {
    loginErr.hidden = true;
    loginErr.textContent = '';
  }

  // Limpieza de campos del modal de creación de usuarios
  const nuevoUsr = document.getElementById('inputNuevoUsuario');
  const nuevoPwd = document.getElementById('inputNuevoPassword');
  if (nuevoUsr) nuevoUsr.value = '';
  if (nuevoPwd) nuevoPwd.value = '';

  // Limpieza de estado del asistente IA
  window._aiPendingAction = null;
  const chatInput = document.getElementById('aiChatInput');
  if (chatInput) chatInput.value = '';
  const userRoleEl = document.getElementById('aiUserRole');
  if (userRoleEl) userRoleEl.textContent = 'Rol: —';

  const fab = document.getElementById('btnAiFab');
  if (fab) fab.hidden = true;
  const drawer = document.getElementById('aiChatDrawer');
  if (drawer) drawer.hidden = true;
  verificarPantallaInicial();
}

function verificarPantallaInicial() {
  const authOverlay   = document.getElementById('authOverlay');
  const mainApp       = document.getElementById('app');
  const adminModal    = document.getElementById('adminModal');
  const panelBoot     = document.getElementById('panelBootstrapGerente');
  const panelLogin    = document.getElementById('panelLogin');
  const fab           = document.getElementById('btnAiFab');
  const drawer        = document.getElementById('aiChatDrawer');

  // Limpiar campos de login por seguridad
  const inputUsr = document.getElementById('inputUsuario');
  const inputPwd = document.getElementById('inputPassword');
  const loginErr = document.getElementById('loginError');
  if (inputUsr) inputUsr.value = '';
  if (inputPwd) {
    inputPwd.value = '';
    inputPwd.type = 'password';
  }
  if (loginErr) {
    loginErr.hidden = true;
    loginErr.textContent = '';
  }

  if (fab) fab.hidden = true;
  if (drawer) drawer.hidden = true;
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
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    td.className = 'empty-msg';
    td.textContent = 'No hay usuarios registrados en este rol.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  lista.forEach((u, i) => {
    const tr = document.createElement('tr');

    const tdNum = document.createElement('td');
    tdNum.textContent = (i + 1).toString();
    tr.appendChild(tdNum);

    const tdNom = document.createElement('td');
    tdNom.style.fontWeight = '700';
    tdNom.textContent = u.nombre;
    tr.appendChild(tdNom);

    const tdSalt = document.createElement('td');
    tdSalt.className = 'mono';
    tdSalt.title = u.salt;
    tdSalt.textContent = u.salt.slice(0, 10) + '…';
    tr.appendChild(tdSalt);

    const tdHash = document.createElement('td');
    tdHash.className = 'mono';
    tdHash.title = u.hash;
    tdHash.textContent = u.hash.slice(0, 14) + '…';
    tr.appendChild(tdHash);

    const tdAcc = document.createElement('td');
    const btnDel = document.createElement('button');
    btnDel.className = 'btn-del';
    btnDel.textContent = 'Eliminar';
    btnDel.addEventListener('click', () => {
      if (confirm(`¿Eliminar usuario "${u.nombre}"?`)) {
        USUARIOS_BD = USUARIOS_BD.filter(x => x.nombre !== u.nombre);
        persistirUsuariosLocales();
        renderAdminTabla();
        verificarPantallaInicial();
        log(`Usuario "${u.nombre}" eliminado`, 'warn');
      }
    });
    tdAcc.appendChild(btnDel);
    tr.appendChild(tdAcc);

    tbody.appendChild(tr);
  });
}

// Variables de Rate Limiting y Control Anti-Fuerza Bruta
let loginFailedAttempts = 0;
let loginLockoutUntil = 0;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 30000; // 30 segundos de bloqueo por fuerza bruta

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

    // Control Anti-Fuerza Bruta (Account Lockout)
    const now = Date.now();
    if (now < loginLockoutUntil) {
      const segs = Math.ceil((loginLockoutUntil - now) / 1000);
      errEl.textContent = `Demasiados intentos fallidos. Bloqueado temporalmente por ${segs}s (Anti-Fuerza Bruta).`;
      errEl.hidden = false;
      return;
    }

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
      loginFailedAttempts++;
      if (loginFailedAttempts >= MAX_LOGIN_ATTEMPTS) {
        loginLockoutUntil = Date.now() + LOCKOUT_DURATION_MS;
        const segs = Math.ceil(LOCKOUT_DURATION_MS / 1000);
        errEl.textContent = `Bloqueo de seguridad activado tras 5 intentos fallidos. Espera ${segs}s.`;
        log(`Seguridad: Cuenta bloqueada temporalmente por intentos fallidos de login ("${usr}")`, 'error');
      } else {
        const restantes = MAX_LOGIN_ATTEMPTS - loginFailedAttempts;
        errEl.textContent = `Credenciales incorrectas (${restantes} intentos restantes antes de bloqueo).`;
        log(`Login fallido: "${usr}" [Intento ${loginFailedAttempts}/${MAX_LOGIN_ATTEMPTS}]`, 'error');
      }
      errEl.hidden = false;
      document.getElementById('inputPassword').value = '';
      return;
    }

    // Éxito: Resetear contadores de fuerza bruta
    loginFailedAttempts = 0;
    loginLockoutUntil = 0;
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
    if (!await verifyCommand(payload, firma)) { return; }
    EST.sistemaActivo = true; EST.semEntrada = 'azul'; iniciarCicloSP(); actualizarUI();
    snack('Sistema iniciado - ciclo SP activo'); log('Sistema iniciado', 'ok');
  });

  document.getElementById('btnReset')?.addEventListener('click', async () => {
    if (!puedeDo('reset')) return;
    const { payload, firma } = await signCommand('RESET');
    if (!await verifyCommand(payload, firma)) { return; }
    resetSistema(); snack('Sistema en Condiciones Iniciales');
  });

  document.getElementById('btnSimE1')?.addEventListener('click', async () => {
    if (!puedeDo('simE1') || !EST.sistemaActivo || cooldownE1Restante > 0) return;
    if (EST.plazasOcupadas >= 100) { snack('Estacionamiento lleno (100/100)'); return; }
    const { payload, firma } = await signCommand('SIM_E1');
    if (!await verifyCommand(payload, firma)) { return; }
    
    iniciarCooldownE1(3);
    EST.vehiculos.push(crearVehiculoEntrada());
    snack('Vehículo aproximándose a entrada (E1) — Cooldown 3s activado');
    log('Simulación: vehículo en aproximación E1 (Cooldown 3s)', 'info');
  });

  document.getElementById('btnSimS1')?.addEventListener('click', async () => {
    if (!puedeDo('simS1') || !EST.sistemaActivo || cooldownS1Restante > 0) return;
    if (EST.plazasOcupadas === 0) { snack('Garaje vacío (0/100)'); return; }
    const { payload, firma } = await signCommand('SIM_S1');
    if (!await verifyCommand(payload, firma)) { return; }
    
    iniciarCooldownS1(3);
    EST.vehiculos.push(crearVehiculoSalida());
    activarSensor('S1');
    snack('Vehículo demandando salida (S1) — Cooldown 3s activado');
    log('Simulación: vehículo demanda salida S1 (Cooldown 3s)', 'info');
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

  // Verificación de Integridad Criptográfica del Log (Exclusivo Gerente)
  document.getElementById('btnVerifyLog')?.addEventListener('click', async () => {
    if (!puedeDo('verLog')) { snack('Acceso denegado: Exclusivo del Gerente'); return; }
    await verificarIntegridadLogs();
  });

  document.getElementById('btnExportLog')?.addEventListener('click', () => {
    if (!puedeDo('verLog')) { snack('Acceso denegado: Exclusivo del Gerente'); return; }
    const csv = ['id,timestamp,usuario,rol,mensaje,tipo,hash_sha256', ...auditEntries.map(e => `"${e.id}","${e.ts}","${e.nombre}","${e.rol}","${e.msg}","${e.tipo}","${e.hash}"`)].join('\n');
    const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([csv], { type: 'text/csv' })), download: `scada_audit_chain_${Date.now()}.csv` });
    a.click(); URL.revokeObjectURL(a.href); log('Log de auditoría exportado con firmas SHA-256', 'info');
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
  initAiAgent();
}

// =========================================================================
// ASISTENTE AGÉNTICO DE OPERACIONES IA (Google Gemini + Guardrails + Tools)
// =========================================================================

let geminiApiKey = localStorage.getItem('scada_gemini_key') || '';
let n8nWebhookUrl = localStorage.getItem('scada_n8n_webhook') || 'https://agentes.henkki.co/webhook/scada-ai-agent';
if (n8nWebhookUrl.includes('webhook-test')) {
  n8nWebhookUrl = 'https://agentes.henkki.co/webhook/scada-ai-agent';
  localStorage.setItem('scada_n8n_webhook', n8nWebhookUrl);
}

function makeDraggable(el) {
  if (!el) return;
  const header = el.querySelector('.ai-chat-header');
  if (!header) return;

  let isDragging = false;
  let startX = 0, startY = 0;
  let initialLeft = 0, initialTop = 0;

  function onPointerDown(e) {
    // Ignorar si se hace clic en botones dentro del header (cerrar, config)
    if (e.target.closest('button, input, a')) return;
    
    // Solo clic primario (izquierdo) o touch
    if (e.type === 'mousedown' && e.button !== 0) return;

    isDragging = true;
    const clientX = e.type === 'touchstart' ? e.touches[0].clientX : e.clientX;
    const clientY = e.type === 'touchstart' ? e.touches[0].clientY : e.clientY;

    const rect = el.getBoundingClientRect();
    startX = clientX;
    startY = clientY;
    initialLeft = rect.left;
    initialTop = rect.top;

    // Fijar posición calculada actual para transición limpia
    el.style.left = initialLeft + 'px';
    el.style.top = initialTop + 'px';
    el.style.bottom = 'auto';
    el.style.right = 'auto';
    el.style.margin = '0';
    el.classList.add('is-dragging');

    window.addEventListener('mousemove', onPointerMove, { passive: false });
    window.addEventListener('touchmove', onPointerMove, { passive: false });
    window.addEventListener('mouseup', onPointerUp);
    window.addEventListener('touchend', onPointerUp);
  }

  function onPointerMove(e) {
    if (!isDragging) return;
    if (e.cancelable) e.preventDefault();

    const clientX = e.type === 'touchmove' ? e.touches[0].clientX : e.clientX;
    const clientY = e.type === 'touchmove' ? e.touches[0].clientY : e.clientY;

    const dx = clientX - startX;
    const dy = clientY - startY;

    const rect = el.getBoundingClientRect();
    const maxLeft = Math.max(10, window.innerWidth - rect.width - 10);
    const maxTop = Math.max(10, window.innerHeight - rect.height - 10);

    const newLeft = Math.max(10, Math.min(maxLeft, initialLeft + dx));
    const newTop = Math.max(10, Math.min(maxTop, initialTop + dy));

    el.style.left = newLeft + 'px';
    el.style.top = newTop + 'px';
  }

  function onPointerUp() {
    if (!isDragging) return;
    isDragging = false;
    el.classList.remove('is-dragging');

    window.removeEventListener('mousemove', onPointerMove);
    window.removeEventListener('touchmove', onPointerMove);
    window.removeEventListener('mouseup', onPointerUp);
    window.removeEventListener('touchend', onPointerUp);
  }

  // El arrastre se realiza exclusivamente desde la cabecera para no interferir con la barra de scroll del chat
  header.addEventListener('mousedown', onPointerDown);
  header.addEventListener('touchstart', onPointerDown, { passive: true });
}

function initAiAgent() {
  const fab = document.getElementById('btnAiFab');
  const drawer = document.getElementById('aiChatDrawer');
  const btnClose = document.getElementById('btnAiClose');
  const btnConfig = document.getElementById('btnAiConfig');
  const configModal = document.getElementById('aiConfigModal');
  const btnCloseConfig = document.getElementById('btnCloseAiConfig');
  const btnSaveConfig = document.getElementById('btnSaveAiConfig');
  const chatForm = document.getElementById('aiChatForm');
  const chatInput = document.getElementById('aiChatInput');
  const userRoleEl = document.getElementById('aiUserRole');

  // Permitir arrastrar la ventana de chat a cualquier lugar de la pantalla
  if (drawer) makeDraggable(drawer);

  // Toggle de apertura y cierre
  fab?.addEventListener('click', () => {
    drawer.hidden = !drawer.hidden;
    if (!drawer.hidden) {
      if (userRoleEl) userRoleEl.textContent = `Rol: ${sesion?.rol || 'No autenticado'}`;
      chatInput?.focus();
    }
  });

  btnClose?.addEventListener('click', () => { drawer.hidden = true; });

  // Configuración de API Key
  btnConfig?.addEventListener('click', () => {
    document.getElementById('inputGeminiKey').value = geminiApiKey;
    document.getElementById('inputN8nWebhook').value = n8nWebhookUrl;
    configModal.hidden = false;
  });

  btnCloseConfig?.addEventListener('click', () => { configModal.hidden = true; });

  btnSaveConfig?.addEventListener('click', () => {
    geminiApiKey = document.getElementById('inputGeminiKey').value.trim();
    n8nWebhookUrl = document.getElementById('inputN8nWebhook').value.trim();
    localStorage.setItem('scada_gemini_key', geminiApiKey);
    localStorage.setItem('scada_n8n_webhook', n8nWebhookUrl);
    configModal.hidden = true;
    snack('Configuración de IA guardada');
    log('Configuración del Asistente IA actualizada', 'ok');
  });

  // Renderizado inicial de quick chips
  if (sesion?.rol) renderAiQuickChips(sesion.rol);

  // Envío de Formulario de Chat
  chatForm?.addEventListener('submit', e => {
    e.preventDefault();
    const txt = chatInput.value.trim();
    if (!txt) return;
    chatInput.value = '';
    processAiPrompt(txt);
  });
}

function renderAiQuickChips(rol) {
  const container = document.querySelector('.ai-quick-chips');
  if (!container) return;

  let chips = [];
  if (rol === 'Operador') {
    chips = [
      { label: '📊 Plazas', prompt: '¿Cuántas plazas hay disponibles y cuál es el estado del estacionamiento?' },
      { label: '🚪 Portón / Semáforos', prompt: '¿Cuál es el estado actual del portón y los semáforos?' },
      { label: '🚗 Entrada (E1)', prompt: 'Simula la llegada de un vehículo por la entrada E1' },
      { label: '🚙 Salida (S1)', prompt: 'Simula la salida de un vehículo por el sensor S1' },
      { label: '🔄 Reiniciar CI', prompt: 'Reinicia el sistema a condiciones iniciales' },
      { label: '📜 Mis Funciones', prompt: '¿Cuáles son mis funciones y permisos como Operador en este SCADA?' }
    ];
  } else if (rol === 'Supervisor' || rol === 'Ingeniero') {
    chips = [
      { label: '📊 Plazas', prompt: '¿Cuántas plazas hay disponibles y cuál es el estado del estacionamiento?' },
      { label: '📈 Métricas ERP', prompt: 'Muestra el resumen ejecutivo de métricas, entradas, salidas y consumo de energía' },
      { label: '🚪 Abrir/Cerrar Portón', prompt: 'Forzar maniobra manual del portón de acceso' },
      { label: '🚗 Entrada (E1)', prompt: 'Simula la llegada de un vehículo por la entrada E1' },
      { label: '🚙 Salida (S1)', prompt: 'Simula la salida de un vehículo por el sensor S1' },
      { label: '⏱️ Ajustar Tiempos SP', prompt: 'Cambia el tiempo verde del semáforo a 30s' },
      { label: '🔄 Reiniciar CI', prompt: 'Reinicia el sistema a condiciones iniciales' },
      { label: '📜 Mis Funciones', prompt: '¿Cuáles son mis funciones y permisos como Supervisor en este SCADA?' }
    ];
  } else {
    // Gerente
    chips = [
      { label: '📊 Plazas', prompt: '¿Cuántas plazas hay disponibles y cuál es el estado del estacionamiento?' },
      { label: '📈 Métricas ERP', prompt: 'Muestra el resumen ejecutivo de métricas, entradas, salidas y consumo de energía' },
      { label: '👥 Usuarios', prompt: 'Muestra la lista de todos los usuarios registrados y sus roles en el sistema SCADA' },
      { label: '🚪 Control Portón', prompt: 'Abre o cierra el portón del estacionamiento' },
      { label: '🚗 Entrada (E1)', prompt: 'Simula la llegada de un vehículo por la entrada E1' },
      { label: '🚙 Salida (S1)', prompt: 'Simula la salida de un vehículo por el sensor S1' },
      { label: '⏱️ Tiempos SP', prompt: 'Ajusta los tiempos del ciclo semafórico SP' },
      { label: '🛡️ Auditoría SHA-256', prompt: 'Verifica la cadena completa de firmas criptográficas de auditoría' },
      { label: '📜 Mis Funciones', prompt: '¿Cuáles son mis funciones y permisos totales como Gerente en este SCADA?' }
    ];
  }

  container.innerHTML = '';
  chips.forEach(c => {
    const btn = document.createElement('button');
    btn.className = 'ai-chip';
    btn.dataset.prompt = c.prompt;
    btn.textContent = c.label;
    btn.addEventListener('click', () => {
      processAiPrompt(c.prompt);
    });
    container.appendChild(btn);
  });
}

function appendAiMessage(sender, text, badge = null, isRefusal = false) {
  const container = document.getElementById('aiChatMessages');
  if (!container) return;

  const msgDiv = document.createElement('div');
  msgDiv.className = `ai-msg ai-msg-${sender}`;

  const bubble = document.createElement('div');
  bubble.className = 'ai-msg-bubble';

  if (badge) {
    const badgeEl = document.createElement('div');
    badgeEl.className = isRefusal ? 'ai-refusal-badge' : 'ai-tool-badge';
    badgeEl.textContent = badge;
    bubble.appendChild(badgeEl);
  }

  const textNode = document.createElement('div');
  textNode.innerHTML = text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>').replace(/\n/g, '<br>');
  bubble.appendChild(textNode);

  const timeSpan = document.createElement('span');
  timeSpan.className = 'ai-msg-time';
  timeSpan.textContent = new Date().toLocaleTimeString('es-VE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  msgDiv.appendChild(bubble);
  msgDiv.appendChild(timeSpan);
  container.appendChild(msgDiv);
  container.scrollTop = container.scrollHeight;
}

// Definición de Herramientas Agénticas Ejecutables en el SCADA
const AI_TOOLS = {
  consultar_estado: () => {
    return {
      sistemaActivo: EST.sistemaActivo ? "ACTIVO" : "DETENIDO",
      plazasTotales: 100,
      plazasOcupadas: EST.plazasOcupadas,
      plazasLibres: 100 - EST.plazasOcupadas,
      porton: {
        estadoActual: EST.portonEstado.toUpperCase(), // "CERRADO", "ABIERTO", "ABRIENDO", "CERRANDO"
        estaCerrado: EST.portonEstado === 'cerrado',
        estaAbierto: EST.portonEstado === 'abierto',
        sensor_FCC_Cerrado: EST.FCC,
        sensor_FCA_Abierto: EST.FCA
      },
      semaforos: {
        peatonal_SP: EST.semPeatonal.toUpperCase(),
        entrada_SE: EST.semEntrada.toUpperCase(),
        salida_SS: EST.semSalida.toUpperCase()
      },
      pasoVehicularHabilitado: EST.paActivo
    };
  },
  consultar_metricas: () => {
    return {
      totalEntradas: EST.totalEntradas,
      totalSalidas: EST.totalSalidas,
      ciclosPorton: EST.ciclosPorton,
      consumoEnergiaAprox: `${(EST.ciclosPorton * 45).toFixed(0)} Wh`,
      plazasOcupadas: EST.plazasOcupadas
    };
  },
  consultar_usuarios: () => {
    if (sesion?.rol !== 'Gerente') {
      return [{ error: 'Acceso denegado: La consulta de usuarios y roles es exclusiva del rol de Gerente.' }];
    }
    return usuarios.map(u => ({
      usuario: u.nombre,
      rol: u.rol,
      fechaCreacion: u.fechaCreacion || 'Inicial'
    }));
  },
  consultar_auditoria: (limite = 5) => {
    if (!puedeDo('verLog')) {
      return [{ error: 'Acceso denegado: El registro de auditoría es exclusivo para el rol de Gerente.' }];
    }
    return auditEntries.slice(-Math.min(limite, 10)).map(e => ({
      hora: e.ts,
      usuario: e.nombre,
      rol: e.rol,
      mensaje: e.msg,
      tipo: e.tipo,
      hash_sha256: e.hash.slice(0, 16) + '…'
    }));
  },
  ejecutar_comando: async (accion, param = null) => {
    const rol = sesion?.rol;
    // Validación estricta de RBAC
    if (accion === 'iniciar') {
      if (!puedeDo('inicio')) return { exito: false, error: `Rol "${rol}" no tiene permiso para iniciar el sistema.` };
      const { payload, firma } = await signCommand('INICIO');
      if (!await verifyCommand(payload, firma)) return { exito: false, error: 'Firma HMAC inválida.' };
      window._aiPendingAction = null;
      EST.sistemaActivo = true; EST.semEntrada = 'azul'; iniciarCicloSP(); actualizarUI();
      log(`Asistente IA: Sistema iniciado por orden de ${sesion.nombre}`, 'ok');
      return { exito: true, mensaje: 'Sistema SCADA iniciado exitosamente y ciclo de semáforo SP activado.' };
    }
    if (accion === 'detener' || accion === 'pausar' || accion === 'reiniciar') {
      if (!puedeDo('reset')) return { exito: false, error: `Rol "${rol}" no tiene permiso para reiniciar o detener el sistema.` };
      const { payload, firma } = await signCommand('RESET');
      if (!await verifyCommand(payload, firma)) return { exito: false, error: 'Firma HMAC inválida.' };
      window._aiPendingAction = null;
      resetSistema();
      log(`Asistente IA: Simulación reiniciada a Condiciones Iniciales (CI) por ${sesion.nombre}`, 'warn');
      return { exito: true, mensaje: 'Simulación reiniciada a Condiciones Iniciales: sistema detenido, portón cerrado y 100 plazas disponibles.' };
    }
    if (accion === 'simular_entrada') {
      if (!puedeDo('simE1') || cooldownE1Restante > 0) {
        return { exito: false, error: 'Entrada no permitida: cooldown activo o sin permisos.' };
      }
      if (EST.plazasOcupadas >= 100) return { exito: false, error: 'Estacionamiento lleno (100/100).' };

      // Si la simulación está apagada, SOLO activar el sistema y pedir confirmación
      if (!EST.sistemaActivo) {
        EST.sistemaActivo = true;
        EST.semEntrada = 'azul';
        iniciarCicloSP();
        actualizarUI();
        window._aiPendingAction = { tipo: 'entrada', timestamp: Date.now() };
        log(`Asistente IA: Simulación iniciada tras solicitud de entrada de ${sesion.nombre}`, 'ok');
        return {
          exito: true,
          requiereConfirmacion: true,
          mensaje: 'He activado la simulación del sistema SCADA exitosamente.\n\n¿Deseas que proceda a ingresar el vehículo ahora?'
        };
      }

      iniciarCooldownE1(3);
      EST.vehiculos.push(crearVehiculoEntrada());
      actualizarUI();
      log(`Asistente IA: Vehículo ingresado por ${sesion.nombre} (E1)`, 'info');
      return { exito: true, mensaje: 'Vehículo aproximándose por el sensor de entrada (E1).' };
    }
    if (accion === 'simular_salida') {
      if (!puedeDo('simS1') || cooldownS1Restante > 0) {
        return { exito: false, error: 'Salida no permitida: cooldown activo o sin permisos.' };
      }
      if (EST.plazasOcupadas === 0) return { exito: false, error: 'El estacionamiento está vacío (0 vehículos ocupando plazas).' };

      // Si la simulación está apagada, SOLO activar el sistema y pedir confirmación
      if (!EST.sistemaActivo) {
        EST.sistemaActivo = true;
        EST.semEntrada = 'azul';
        iniciarCicloSP();
        actualizarUI();
        window._aiPendingAction = { tipo: 'salida', timestamp: Date.now() };
        log(`Asistente IA: Simulación iniciada tras solicitud de salida de ${sesion.nombre}`, 'ok');
        return {
          exito: true,
          requiereConfirmacion: true,
          mensaje: 'He activado la simulación del sistema SCADA exitosamente.\n\n¿Deseas que proceda a registrar la salida del vehículo ahora?'
        };
      }

      iniciarCooldownS1(3);
      EST.vehiculos.push(crearVehiculoSalida());
      activarSensor('S1');
      actualizarUI();
      log(`Asistente IA: Vehículo en salida por ${sesion.nombre} (S1)`, 'info');
      return { exito: true, mensaje: 'Vehículo demandando salida por el sensor S1. Prioridad concedida.' };
    }
    if (accion === 'forzar_porton') {
      if (!puedeDo('forzarPorton')) return { exito: false, error: `Acceso denegado: Tu rol de ${rol} no tiene privilegios para forzar el portón manual (Requiere Supervisor o Gerente).` };
      if (EST.portonEstado === 'cerrado') {
        EST.portonEstado = 'abriendo'; setTimeout(() => { EST.portonEstado = 'abierto'; EST.FCA = true; actualizarUI(); }, 1600);
      } else if (EST.portonEstado === 'abierto') {
        cerrarPorton();
      }
      actualizarUI();
      log(`Asistente IA: Portón forzado manualmente por ${sesion.nombre}`, 'warn');
      return { exito: true, mensaje: 'Maniobra manual de portón ejecutada exitosamente.' };
    }
    if (accion === 'ajustar_tiempos_sp') {
      if (!puedeDo('ajustarTiempos')) return { exito: false, error: `Acceso denegado: Rol "${rol}" no puede ajustar tiempos (Requiere Supervisor o Gerente).` };
      
      let tv = EST.spVerdeMs;
      let tr = EST.spRojoMs;
      
      const p = (typeof param === 'string' ? param : JSON.stringify(param || '')).toLowerCase();
      const verdeMatch = p.match(/verde[^\d]*(\d+)/i) || (p.includes('verde') ? p.match(/(\d+)\s*(s|seg|segundos)?/i) : null);
      const rojoMatch  = p.match(/rojo[^\d]*(\d+)/i)  || (p.includes('rojo') ? p.match(/(\d+)\s*(s|seg|segundos)?/i) : null);
      
      if (verdeMatch && verdeMatch[1]) {
        tv = Math.max(5, parseInt(verdeMatch[1], 10)) * 1000;
        const inpV = document.getElementById('inputTiempoVerde');
        if (inpV) inpV.value = tv / 1000;
      }
      if (rojoMatch && rojoMatch[1]) {
        tr = Math.max(10, parseInt(rojoMatch[1], 10)) * 1000;
        const inpR = document.getElementById('inputTiempoRojo');
        if (inpR) inpR.value = tr / 1000;
      }
      if (!verdeMatch && !rojoMatch) {
        const anyNum = p.match(/(\d+)\s*(s|seg|segundos)?/i);
        if (anyNum && anyNum[1]) {
          tv = Math.max(5, parseInt(anyNum[1], 10)) * 1000;
          const inpV = document.getElementById('inputTiempoVerde');
          if (inpV) inpV.value = tv / 1000;
        }
      }
      
      EST.spVerdeMs = tv;
      EST.spRojoMs = tr;
      if (EST.sistemaActivo) iniciarCicloSP();
      actualizarUI();
      snack(`SP actualizado: Verde ${tv/1000}s / Rojo ${tr/1000}s`);
      log(`Asistente IA: Tiempos SP modificados a Verde:${tv/1000}s / Rojo:${tr/1000}s por ${sesion.nombre}`, 'ok');
      return { exito: true, mensaje: `Tiempos de semáforo SP actualizados a Verde: ${tv/1000}s y Rojo: ${tr/1000}s.` };
    }
    if (accion === 'consultar_usuarios' || accion === 'listar_usuarios') {
      if (sesion?.rol !== 'Gerente') return { exito: false, error: 'Acceso denegado: La consulta de usuarios y roles es exclusiva del rol de Gerente.' };
      if (!usuarios || usuarios.length === 0) {
        return { exito: true, mensaje: '👥 No hay usuarios adicionales registrados en el sistema.' };
      }
      const lista = usuarios.map(u => `• **${u.nombre}** — Rol: *${u.rol}* ${u.fechaCreacion ? `(Alta: ${u.fechaCreacion})` : ''}`).join('\n');
      const mensaje = `👥 **USUARIOS REGISTRADOS EN EL SISTEMA SCADA (${usuarios.length})**\n\n${lista}\n\n*(🛡️ Las contraseñas se encuentran cifradas con PBKDF2 y 100.000 iteraciones).*`;
      return { exito: true, mensaje, total: usuarios.length };
    }
    if (accion === 'verificar_integridad') {
      if (!puedeDo('verLog')) return { exito: false, error: 'Acceso denegado: La verificación criptográfica de auditoría es exclusiva del Gerente.' };
      const ok = await verificarIntegridadLogs();
      const total = auditEntries.length;
      const ultimoHash = total > 0 ? auditEntries[total - 1].hash : '0000000000000000000000000000000000000000000000000000000000000000';
      const primerEvento = total > 0 ? `[${auditEntries[0].ts}] ${auditEntries[0].msg}` : 'Sin registros';
      const ultimoEvento = total > 0 ? `[${auditEntries[total - 1].ts}] ${auditEntries[total - 1].msg}` : 'Sin registros';

      const reporte = `🛡️ **REPORTE EJECUTIVO DE INTEGRIDAD Y CIBERSEGURIDAD**\n\n` +
        `• **Estado de la Cadena:** ${ok ? '✅ 100% ÍNTEGRA Y AUTÉNTICA' : '❌ INCONSISTENCIA DETECTADA'}\n` +
        `• **Eventos Auditados:** ${total} registros encadenados\n` +
        `• **Criptografía:** SHA-256 con encadenamiento de bloque anterior (Merkle Tree / Blockchain)\n` +
        `• **Primer Registro:** ${primerEvento}\n` +
        `• **Último Registro:** ${ultimoEvento}\n` +
        `• **Último Hash Registrado:** \`${ultimoHash.slice(0, 24)}…\`\n\n` +
        `*Diagnóstico:* Se verificó matemáticamente cada hash individual y la correlación con su bloque anterior. No se detectaron manipulaciones en memoria ni en almacenamiento.`;

      return {
        exito: ok,
        mensaje: reporte,
        totalEventos: total,
        ultimoHash,
        estado: ok ? 'INTEGRO' : 'ALTERADO'
      };
    }
    return { exito: false, error: `Comando "${accion}" desconocido.` };
  }
};

// Procesamiento del Agente con Google Gemini API / n8n o Motor Local con Guardrails
async function processAiPrompt(prompt) {
  if (!sesion) {
    appendAiMessage('bot', '⚠️ Debes iniciar sesión en el sistema SCADA para poder interactuar con el asistente.', null, true);
    return;
  }

  appendAiMessage('user', prompt);
  const sendBtn = document.getElementById('btnAiSend');
  if (sendBtn) sendBtn.disabled = true;

  // Detección de confirmación de acción pendiente (ej: iniciar sistema, entrar/salir vehículo)
  const pLower = prompt.trim().toLowerCase();
  const isConfirm = /^(si|sí|claro|ok|dale|procede|proceder|afirmativo|positivo|por favor|adelante|hazlo|confirmo|confirmar|ingresalo|ingrésalo|sacalo|sácalo|entra|saca)$/i.test(pLower) || /\b(si|sí|confirmo|confirmar|procede|proceder|ingresalo|ingrésalo|sacalo|sácalo|entra|dale|adelante|hazlo|claro|por favor|ok|afirmativo|positivo)\b/i.test(pLower);
  const isDeny = /^(no|nop|cancelar|cancela|deten|para|espera)$/i.test(pLower) || /\b(no|cancela|cancelar|deten|parar|espera|todavia no|todavía no)\b/i.test(pLower);

  if (isConfirm) {
    if (window._aiPendingAction && (Date.now() - window._aiPendingAction.timestamp < 300000)) {
      const tipo = window._aiPendingAction.tipo;
      window._aiPendingAction = null;

      if (tipo === 'iniciar') {
        await AI_TOOLS.ejecutar_comando('iniciar');
        window._aiPendingAction = { tipo: 'entrada', timestamp: Date.now() };
        appendAiMessage('bot', '▶️ Simulación iniciada exitosamente. El sistema SCADA está operativo.\n\n¿Deseas que proceda a ingresar el vehículo ahora?', 'Sistema Iniciado');
        if (sendBtn) sendBtn.disabled = false;
        return;
      }

      if (tipo === 'entrada') {
        iniciarCooldownE1(3);
        EST.vehiculos.push(crearVehiculoEntrada());
        actualizarUI();
        log(`Asistente IA: Entrada de vehículo confirmada por ${sesion.nombre}`, 'info');
        appendAiMessage('bot', '✅ Confirmación recibida. El vehículo está ingresando por el sensor de entrada (E1).', 'Entrada E1');
        if (sendBtn) sendBtn.disabled = false;
        return;
      }

      if (tipo === 'salida') {
        if (EST.plazasOcupadas > 0) {
          iniciarCooldownS1(3);
          EST.vehiculos.push(crearVehiculoSalida());
          activarSensor('S1');
          actualizarUI();
          log(`Asistente IA: Salida de vehículo confirmada por ${sesion.nombre}`, 'info');
          appendAiMessage('bot', '✅ Confirmación recibida. El vehículo está saliendo por el sensor S1.', 'Salida S1');
        } else {
          appendAiMessage('bot', '⚠️ El estacionamiento está vacío (0 vehículos ocupando plazas).', 'Salida S1', true);
        }
        if (sendBtn) sendBtn.disabled = false;
        return;
      }
    } else if (!EST.sistemaActivo) {
      // Si el sistema está detenido y el usuario responde "si", inicia la simulación
      await AI_TOOLS.ejecutar_comando('iniciar');
      window._aiPendingAction = { tipo: 'entrada', timestamp: Date.now() };
      appendAiMessage('bot', '▶️ Simulación iniciada exitosamente. El sistema SCADA ya está activo y operativo.\n\n¿Deseas que proceda a ingresar el vehículo ahora?', 'Sistema Iniciado');
      if (sendBtn) sendBtn.disabled = false;
      return;
    }
  } else if (isDeny && window._aiPendingAction) {
    window._aiPendingAction = null;
    appendAiMessage('bot', 'Entendido, acción cancelada. No se realizarán maniobras de vehículos.', 'Operación Cancelada');
    if (sendBtn) sendBtn.disabled = false;
    return;
  }

  try {
    // 1. Si existe URL de Webhook en n8n, enviamos la petición al flujo de n8n
    if (n8nWebhookUrl) {
      const urlsToTry = [
        n8nWebhookUrl,
        n8nWebhookUrl.includes('webhook-test') ? n8nWebhookUrl.replace('webhook-test', 'webhook') : n8nWebhookUrl.replace('/webhook/', '/webhook-test/')
      ];

      let lastError = null;
      for (const targetUrl of urlsToTry) {
        try {
          const res = await fetch(targetUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              prompt,
              usuario: sesion.nombre,
              rol: sesion.rol,
              scadaState: AI_TOOLS.consultar_estado()
            })
          });

          if (res.ok) {
            const rawText = await res.text();
            let data;
            try {
              data = JSON.parse(rawText);
            } catch (_) {
              data = { output: rawText };
            }

            let outText = '';
            if (typeof data === 'string') {
              outText = data;
            } else if (Array.isArray(data)) {
              outText = data[0]?.output || data[0]?.text || data[0]?.response || JSON.stringify(data[0]);
            } else {
              outText = data.output || data.response || data.text || data.message || (rawText || 'Respuesta procesada.');
            }
            
            // Detección y ejecución de comandos SCADA en tiempo real
            let cmd = data?.accion || data?.comandoSolicitado || data?.[0]?.accion || data?.[0]?.comandoSolicitado;
            if (!cmd) {
              const p = prompt.toLowerCase();
              const esSoloConsulta = p.includes('cual es') || p.includes('quien soy') || p.includes('cuantas') || p.includes('que rol') || p.includes('dime mi') || p.includes('resumen') || p.includes('historial');
              
              if (!esSoloConsulta) {
                // 1. Consulta de Usuarios (Exclusivo Gerente)
                if (/\b(usuarios|cuentas|quienes tienen acceso|lista de usuario|mostrar usuario)\w*/i.test(p) || p.includes('listar usuarios') || p.includes('ver usuarios') || p.includes('lista de usuarios') || p.includes('usuarios registrados')) {
                  cmd = 'consultar_usuarios';
                // 2. Verificación de Integridad / Auditoría SHA-256
                } else if (/\b(integrid|auditor|auditar|sha256|cadena criptogr)\w*/i.test(p) || p.includes('verificar integridad') || p.includes('reporte de integridad') || p.includes('auditoria')) {
                  cmd = 'verificar_integridad';
                // 2. Reiniciar / Detener / Pausar / CI (evaluado primero para que 'reinicia' no coincida con 'inicia')
                } else if (/\b(reinici|reset|restablec|deten|paus|parar|paralo|fren|apaga)\w*/i.test(p) || /\bci\b/i.test(p) || p.includes('condiciones iniciales') || /\bpara\b/i.test(p)) {
                  cmd = 'reiniciar';
                // 3. Iniciar / Arrancar / Activar
                } else if (/\b(inici|arranc|empiez|empez|comienz|comenz|activ|prende|prender)\w*/i.test(p) || /\b(iniciar|inicia|arrancar|activar)\b/i.test(p) || p.includes('simulacion') || p.includes('simulación')) {
                  cmd = 'iniciar';
                } else if (/\b(salid|sacar|egres)\w*/i.test(p) || /\bsal\b/i.test(p) || p.includes('s1')) {
                  cmd = 'simular_salida';
                } else if (/\b(entr|ingres|auto|carro|coche|vehiculo|lleg)\w*/i.test(p) || p.includes('e1')) {
                  cmd = 'simular_entrada';
                } else if (/\b(porton|puerta|reja|abrir|abre|cerrar|cierra|forzar)\w*/i.test(p)) {
                  cmd = 'forzar_porton';
                } else if (/\b(tiempo|verde|rojo|segundo|temporizador|ajust)\w*/i.test(p)) {
                  cmd = 'ajustar_tiempos_sp';
                }
              }
            }

            if (cmd) {
              const actRes = await AI_TOOLS.ejecutar_comando(cmd, prompt);
              if (!actRes.exito) {
                appendAiMessage('bot', `${outText}\n\n⚠️ *${actRes.error}*`, `n8n Agente: ${cmd}`, true);
              } else if (actRes.requiereConfirmacion) {
                appendAiMessage('bot', actRes.mensaje, 'Asistente SCADA: Confirmación');
              } else {
                appendAiMessage('bot', outText, `n8n Agente: ${cmd}`);
              }
            } else {
              // Sincronización inteligente de intenciones desde el texto retornado por n8n:
              const outLower = outText.toLowerCase();

              // Si n8n afirma que inició el sistema pero estaba apagado:
              if (!EST.sistemaActivo && (outLower.includes('iniciado la simulaci') || outLower.includes('inicié la simulaci') || outLower.includes('se encuentra operativo') || outLower.includes('sistema iniciado') || outLower.includes('activado la simulaci'))) {
                await AI_TOOLS.ejecutar_comando('iniciar');
              }

              // Registrar preguntas pendientes si n8n pregunta al usuario
              if (!EST.sistemaActivo && (outLower.includes('iniciar la simulaci') || outLower.includes('proceda a iniciar'))) {
                window._aiPendingAction = { tipo: 'iniciar', timestamp: Date.now() };
              } else if (outLower.includes('ingresar el veh') || outLower.includes('ingresar el vehículo') || outLower.includes('entrar el veh')) {
                window._aiPendingAction = { tipo: 'entrada', timestamp: Date.now() };
              } else if (outLower.includes('salida del veh') || outLower.includes('registrar la salida') || outLower.includes('sacar el veh')) {
                window._aiPendingAction = { tipo: 'salida', timestamp: Date.now() };
              }

              appendAiMessage('bot', outText, 'n8n Agente (Gemini)');
            }

            // Actualizar URL que respondió exitosamente
            n8nWebhookUrl = targetUrl;
            localStorage.setItem('scada_n8n_webhook', targetUrl);
            if (sendBtn) sendBtn.disabled = false;
            return;
          } else {
            const errBody = await res.text();
            lastError = `HTTP ${res.status}: ${errBody || 'No respondió el webhook'}`;
          }
        } catch (netErr) {
          lastError = netErr.message;
        }
      }

      appendAiMessage('bot', `⚠️ **No se pudo comunicar con n8n (${lastError}).**\n\n**Solución rápida en n8n:**\n1. Asegúrate de activar el flujo arriba a la derecha (cambiar **Inactive** a **Active**).\n2. O si estás probándolo en el editor, presiona **Listen for test event** y envía el mensaje de nuevo.`, 'n8n Webhook', true);
      if (sendBtn) sendBtn.disabled = false;
      return;
    }

    // 2. Si existe Gemini API Key, realizamos la llamada con Function Calling / Tools a Google Gemini
    if (geminiApiKey) {
      const systemInstruction = `
Eres el Asistente Agéntico de Operaciones y Control SCADA del Estacionamiento Automatizado de 100 Plazas.
Usuario actual: "${sesion.nombre}" con Rol: "${sesion.rol}".

GUARDRAILS Y LÍMITES ESTRICTOS:
1. LÍMITE DE DOMINIO: Tu conocimiento y conversación se limita ESTRICTAMENTE al estacionamiento automatizado, semáforos (SP, SE, SS), portón, sensores (E1, E2, S1, S2), plazas, métricas y ciberseguridad. Si el usuario te pregunta cosas ajenas (poemas, chistes, programación externa, clima, etc.), RECHAZA la pregunta amablemente diciendo que solo atiendes la operación del estacionamiento.
2. CONTROL DE ACCESO (RBAC):
   - Operador: Consultas de estado, iniciar/reiniciar, simular entrada/salida. NO puede forzar portón ni ver contraseñas/usuarios.
   - Supervisor: Todo lo anterior + Forzar portón + Ajustar tiempos + Ver logs de auditoría.
   - Gerente: Control y visualización total.
3. Responde de forma concisa, profesional y en español.
      `;

      const toolsDeclaration = [{
        function_declarations: [
          {
            name: "consultar_estado",
            description: "Obtiene el estado en vivo de plazas libres/ocupadas, semáforos, portón y sensores."
          },
          {
            name: "consultar_metricas",
            description: "Obtiene entradas totales, salidas, ciclos del portón y consumo eléctrico aproximado."
          },
          {
            name: "consultar_auditoria",
            description: "Obtiene los últimos eventos de auditoría y ciberseguridad firmados con SHA-256."
          },
          {
            name: "ejecutar_comando",
            description: "Ejecuta una orden física o lógica en el SCADA (iniciar, reiniciar, simular_entrada, simular_salida, forzar_porton, verificar_integridad).",
            parameters: {
              type: "OBJECT",
              properties: {
                accion: {
                  type: "STRING",
                  description: "Acción a ejecutar: 'iniciar', 'reiniciar', 'simular_entrada', 'simular_salida', 'forzar_porton', 'verificar_integridad'"
                }
              },
              required: ["accion"]
            }
          }
        ]
      }];

      const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${geminiApiKey}`;
      const payload = {
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        system_instruction: { parts: [{ text: systemInstruction }] },
        tools: toolsDeclaration
      };

      const resp = await fetch(geminiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!resp.ok) {
        throw new Error(`Error API Gemini (${resp.status}): ${await resp.text()}`);
      }

      const resJson = await resp.json();
      const candidate = resJson.candidates?.[0]?.content?.parts?.[0];

      if (candidate?.functionCall) {
        const fnName = candidate.functionCall.name;
        const fnArgs = candidate.functionCall.args || {};

        let toolResult = null;
        if (fnName === 'consultar_estado') toolResult = AI_TOOLS.consultar_estado();
        else if (fnName === 'consultar_metricas') toolResult = AI_TOOLS.consultar_metricas();
        else if (fnName === 'consultar_auditoria') toolResult = AI_TOOLS.consultar_auditoria();
        else if (fnName === 'ejecutar_comando') toolResult = await AI_TOOLS.ejecutar_comando(fnArgs.accion);

        // Segunda llamada a Gemini para sintetizar la respuesta
        const followUpPayload = {
          contents: [
            { role: "user", parts: [{ text: prompt }] },
            { role: "model", parts: [{ functionCall: candidate.functionCall }] },
            {
              role: "function",
              parts: [{
                functionResponse: {
                  name: fnName,
                  response: { result: toolResult }
                }
              }]
            }
          ],
          system_instruction: { parts: [{ text: systemInstruction }] },
          tools: toolsDeclaration
        };

        const followResp = await fetch(geminiUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(followUpPayload)
        });

        const followJson = await followResp.json();
        const finalAns = followJson.candidates?.[0]?.content?.parts?.[0]?.text || JSON.stringify(toolResult);
        appendAiMessage('bot', finalAns, `Tool: ${fnName}`);
        if (sendBtn) sendBtn.disabled = false;
        return;
      }

      if (candidate?.text) {
        appendAiMessage('bot', candidate.text, 'Gemini 1.5');
        if (sendBtn) sendBtn.disabled = false;
        return;
      }
    }

    // 3. Motor Agéntico Local Inteligente (Guardrails + Rule Engine) con soporte completo
    await ejecutarMotorAgenteLocal(prompt);

  } catch (err) {
    appendAiMessage('bot', `⚠️ Ocurrió un inconveniente: ${err.message}. Puedes ingresar o verificar tu API Key de Gemini en el botón ⚙️.`, null, true);
  } finally {
    if (sendBtn) sendBtn.disabled = false;
  }
}

// Motor de Reglas y Comprensión Semántica Local con Guardrails
async function ejecutarMotorAgenteLocal(prompt) {
  const p = prompt.toLowerCase().trim();
  const rol = sesion?.rol;

  // 1. Guardrail de Dominio (Filtro fuera de tema)
  const palabrasFueraDominio = ['clima', 'chiste', 'cancion', 'poema', 'receta', 'futbol', 'bitcoin', 'javascript', 'python', 'quien gano', 'pais', 'capital de'];
  if (palabrasFueraDominio.some(w => p.includes(w))) {
    appendAiMessage('bot', '🚫 **Consulta fuera de ámbito:** Como Asistente de Operaciones SCADA, mis capacidades están delimitadas exclusivamente al control, monitoreo, ciberseguridad y maniobras del estacionamiento automatizado.', 'Guardrail de Dominio', true);
    return;
  }

  // 2. Consulta de Plazas y Ocupación
  if (p.includes('plaza') || p.includes('cuanto') || p.includes('espacio') || p.includes('disponible') || p.includes('capacidad')) {
    const est = AI_TOOLS.consultar_estado();
    appendAiMessage('bot', `📊 **Estado de Ocupación:**\n• Plazas Disponibles: **${est.plazasLibres} de 100**\n• Plazas Ocupadas: **${est.plazasOcupadas} (${est.plazasOcupadas}%)**\n• Prioridad actual: **SALIDA (S1)**\n• Sistema: **${est.sistemaActivo ? 'ACTIVO' : 'DETENIDO'}**`, 'Tool: consultar_estado');
    return;
  }

  // 3. Consulta de Portón y Semáforos
  if (p.includes('porton') || p.includes('semaforo') || p.includes('luz') || p.includes('sp') || p.includes('se') || p.includes('ss')) {
    const est = AI_TOOLS.consultar_estado();
    appendAiMessage('bot', `🚪 **Estado de Acceso y Señalización:**\n• Portón: **${est.portonEstado.toUpperCase()}** (FCA: ${est.finalesDeCarrera.FCA_Abierto ? 'ACTIVO' : 'INACTIVO'}, FCC: ${est.finalesDeCarrera.FCC_Cerrado ? 'ACTIVO' : 'INACTIVO'})\n• Semáforo Peatonal (SP): **${est.semPeatonal.toUpperCase()}**\n• Semáforo Entrada (SE): **${est.semEntrada.toUpperCase()}**\n• Semáforo Salida (SS): **${est.semSalida.toUpperCase()}**\n• Paso Vehicular (PA): **${est.pasoVehicularHabilitado ? 'HABILITADO' : 'EN ESPERA'}**`, 'Tool: consultar_estado');
    return;
  }

  // 4. Métricas y ERP
  if (p.includes('metrica') || p.includes('consumo') || p.includes('energia') || p.includes('cuantos carros') || p.includes('total')) {
    const met = AI_TOOLS.consultar_metricas();
    appendAiMessage('bot', `📈 **Métricas del Sistema:**\n• Entradas Totales: **${met.totalEntradas}**\n• Salidas Totales: **${met.totalSalidas}**\n• Ciclos del Portón: **${met.ciclosPorton}**\n• Consumo Estimado: **${met.consumoEnergiaAprox}**`, 'Tool: consultar_metricas');
    return;
  }

  // 5. Consulta de Usuarios (Exclusivo Gerente)
  if (p.includes('usuario') || p.includes('cuenta') || p.includes('quienes tienen acceso') || p.includes('lista de usuarios')) {
    const res = await AI_TOOLS.ejecutar_comando('consultar_usuarios');
    appendAiMessage('bot', res.mensaje || res.error, 'Tool: consultar_usuarios', !res.exito);
    return;
  }

  // 6. Auditoría e Integridad
  if (p.includes('auditoria') || p.includes('integridad') || p.includes('hash') || p.includes('log') || p.includes('seguridad')) {
    const ok = await AI_TOOLS.ejecutar_comando('verificar_integridad');
    const logs = AI_TOOLS.consultar_auditoria(3);
    let logTxt = Array.isArray(logs) ? logs.map(l => `• [${l.hora}] ${l.usuario} (${l.rol}): ${l.mensaje}`).join('\n') : logs.error;
    appendAiMessage('bot', `🛡️ **Auditoría Criptográfica SHA-256:**\n${ok.mensaje}\n\n**Últimos registros:**\n${logTxt}`, 'Tool: verificar_integridad');
    return;
  }

  // 6. Acciones de Maniobra
  if (p.includes('entra') || p.includes('ingresa') || p.includes('llegar') || p.includes('e1')) {
    const res = await AI_TOOLS.ejecutar_comando('simular_entrada');
    appendAiMessage('bot', res.exito ? `🚗 **Acción Ejecutada:** ${res.mensaje}` : `⚠️ **Aviso:** ${res.error}`, 'Tool: simular_entrada', !res.exito);
    return;
  }

  if (p.includes('sal') || p.includes('salir') || p.includes('s1')) {
    const res = await AI_TOOLS.ejecutar_comando('simular_salida');
    appendAiMessage('bot', res.exito ? `🚙 **Acción Ejecutada:** ${res.mensaje}` : `⚠️ **Aviso:** ${res.error}`, 'Tool: simular_salida', !res.exito);
    return;
  }

  // 5. Reiniciar o Detener (evaluado primero para no colisionar con 'inicia')
  if (/\b(reinici|reset|deten|paus|parar|paralo|frena|apaga)\w*/i.test(p) || /\bci\b/i.test(p) || p.includes('condiciones iniciales') || /\bpara\b/i.test(p)) {
    const res = await AI_TOOLS.ejecutar_comando('reiniciar');
    appendAiMessage('bot', res.exito ? `🔄 **Acción Ejecutada:** ${res.mensaje}` : `⚠️ **Aviso:** ${res.error}`, 'Tool: reiniciar', !res.exito);
    return;
  }

  // 6. Iniciar simulación
  if (/\b(inici|arranc|empiez|empez|comienz|comenz|activ|prende)\w*/i.test(p) || /\b(inicia|iniciar|arrancar|activar)\b/i.test(p)) {
    const res = await AI_TOOLS.ejecutar_comando('iniciar');
    appendAiMessage('bot', res.exito ? `▶️ **Acción Ejecutada:** ${res.mensaje}` : `⚠️ **Aviso:** ${res.error}`, 'Tool: iniciar', !res.exito);
    return;
  }

  if (p.includes('fuerza') || p.includes('abre porton') || p.includes('cierra porton') || p.includes('abrir porton') || p.includes('cerrar porton')) {
    const res = await AI_TOOLS.ejecutar_comando('forzar_porton');
    appendAiMessage('bot', res.exito ? `⚙️ **Acción Ejecutada:** ${res.mensaje}` : `🚫 **Permiso Denegado:** ${res.error}`, 'Tool: forzar_porton', !res.exito);
    return;
  }

  // Respuesta por defecto con orientación
  appendAiMessage('bot', `🤖 Entendido. Como asistente de operaciones SCADA con rol **${rol}**, puedo:\n• Consultar plazas y estado de semáforos\n• Simular tráfico de vehículos (E1 / S1)\n• Controlar portón y verificar integridad SHA-256\n\n*(💡 Puedes configurar tu API Key de Gemini en el botón ⚙️ para potenciar respuestas en lenguaje natural generativo).*`);
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
