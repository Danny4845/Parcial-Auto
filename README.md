# III Parcial de Automatización Industrial — Ejercicio 3
## SCADA Ciberfísico para Control de Acceso de Estacionamiento Automatizado

**Integrantes:**
- Daniel Colmenares
- Hernaldo Pérez Roa

---

## 📌 Resumen del Proyecto

Este sistema consiste en una solución **SCADA / HMI Ciberfísica Web Unificada** para la automatización y control de acceso a un estacionamiento de 100 plazas, desarrollado conforme a los requerimientos técnicos y esquemas de tiempo especificados en el III Parcial.

Toda la aplicación está consolidada en un **único archivo de entrada (`index.html`)**, eliminando la necesidad de gestionar carpetas múltiples o servidores web locales.

---

## 🚀 Características Principales y Funcionalidades

### 1. 🎨 Interfaz HMI & Animación en Canvas 2D
- **Representación fiel al plano del enunciado:**
  - Zona de Garaje de 100 plazas con borde naranja.
  - Paso peatonal (Crosswalk) central con portón de barras verticales.
  - Carriles de entrada y salida en disposición diagonal.
  - Sensores fotoeléctricos (`E1`, `E2`, `S1`, `S2`) y finales de carrera (`FCA` arriba, `FCC` abajo).
  - Semáforos industriales: `S.P.` (Peatonal), `S.E.` (Entrada, incluye LED Azul para plazas disponibles) y `S.S.` (Salida).
- **Animación en tiempo real:** Simulación gráfica interactiva de vehículos ingresando y saliendo con actualización mediante `requestAnimationFrame`.

### 2. ⏱️ Lógica del Proceso Industrial & Tiempos (PA)
- **Semáforo Peatonal (S.P.):** Ciclo continuo con temporizador ajustable (Default: 20s Verde / 40s Rojo).
- **Ventana de Permiso de Acceso (P.A.):**
  - Se activa **4 segundos después** de que S.P. pasa a **ROJO**.
  - Se desactiva **6 segundos antes** de que S.P. regrese a **VERDE** (cerrando el portón preventivamente por seguridad peatonal).
- **Prioridad de Salida:** Las solicitudes de salida (`S1`) tienen prioridad absoluta sobre los vehículos en espera de entrada (`E1`).

### 3. 🛡️ Ciberseguridad Industrial
- **Autenticación Fuerte (PBKDF2):**
  - Algoritmo: `PBKDF2` con `SHA-256`, 100.000 iteraciones y Salt aleatorio de 16 bytes.
  - Implementado con la **Web Crypto API nativa** de JavaScript (`window.crypto.subtle`).
- **Ciclo Completo de Autenticación Academic-Grade:**
  - **Registro (Sign-Up):** Registro de nuevos usuarios con código de activación administrativo (`admin2026`), validación de duplicados y medidor de fuerza de contraseña. Persistencia en `localStorage`.
  - **Login:** Verificación de credenciales con hashing local y fallback a archivo `usuarios.json`.
- **Firma Criptográfica HMAC-SHA256 (Anti-Tampering):**
  - Cada comando enviado desde la interfaz (`INICIO`, `RESET`, `SIM_E1`, `SIM_S1`, etc.) es firmado con una clave HMAC única generada por sesión.
- **Panel de Administración Modal:** Accesible directamente con el botón **🛡️ Admin** en el Header o pantalla de acceso para crear, ver, eliminar y exportar/importar usuarios en `usuarios.json`.

---

## 📂 Estructura Simplificada del Proyecto

```
Automatizacion parcial/
├── index.html       ← Aplicación Unificada (Login, Registro, SCADA Dashboard & Modal Admin)
├── style.css        ← Estilos Industriales Dark Mode Integrados
├── app.js           ← Lógica Completa (Auth PBKDF2, HMAC, Motor Canvas 2D, SCADA & Admin)
└── README.md        ← Documentación técnica académica
```

---

## 💻 Instrucciones de Ejecución

1. Abra la carpeta `Automatizacion parcial`.
2. Haga **doble clic en `index.html`** (se abrirá directamente en Opera GX, Chrome, Edge o Firefox).
3. **Credenciales de demostración pre-configuradas:**
   - **Operador:** `operador1` / `oper2026`
   - **Ingeniero:** `ingeniero1` / `ing2026`
   - **Gerente:** `gerente1` / `ger2026`
4. **Código de Activación para Registro:** `admin2026`
