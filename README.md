# III Parcial de Automatización Industrial — Ejercicio 3
## SCADA Ciberfísico para Control de Acceso de Estacionamiento Automatizado

**Integrantes:**
- Daniel Colmenares
- Hernaldo Pérez Roa

---

## 📌 Resumen del Proyecto

Este sistema consiste en una solución **SCADA / HMI Ciberfísica Web Unificada** para la automatización y control de acceso a un estacionamiento de 100 plazas, desarrollado conforme a los requerimientos técnicos y la **pirámide estricta de seguridad en automatización industrial**.

Toda la aplicación está consolidada en un **único archivo de entrada (`index.html`)**, sin usuarios hardcodeados, ofreciendo un flujo de bootstrapping de seguridad y gestión jerárquica de accesos basada en roles (RBAC).

---

## 🚀 Jerarquía de Seguridad & Roles Industrial (RBAC)

### 1. ⚠️ Configuración Inicial de Arranque (Bootstrapping)
- Si el sistema arranca y **NO existe ningún usuario Gerente** en el almacenamiento:
  - La pantalla inicial muestra un aviso de alerta: *"⚠️ Configuración Inicial Requerida: No existe ningún usuario Gerente registrado. Debes crear el Gerente inicial para activar el sistema SCADA."*
  - Se registra el Gerente inicial con derivación criptográfica **PBKDF2 (100.000 iter, SHA-256, Salt 16B)**.
- Una vez registrado el Gerente inicial, la pantalla inicial cambia **únicamente a Iniciar Sesión** (sin registros públicos abiertos).

### 2. 🔐 Reglas Estrictas de Creación de Usuarios por Rol
- 🟡 **Gerente (Nivel ERP / Máximo):**
  - Acceso total a métricas de consumo de energía, volumen de tráfico y log de auditoría.
  - Puede crear usuarios únicamente con el rol de **Supervisor** (Ingeniero) o **Operador**.
- 🔵 **Supervisor / Ingeniero (Nivel Planta):**
  - Acceso a forzado manual de portón, modificación de tiempos del semáforo peatonal (SP) y log de auditoría.
  - Puede crear usuarios únicamente con el rol de **Operador**.
- 🟢 **Operador (Nivel Control):**
  - Acceso a mandos operativos (Inicio, Reset, Simulación E1/S1).
  - **No puede crear ningún usuario** (no tiene acceso al botón ni modal de creación).

---

## 🛡️ Ciberseguridad Industrial Integrada

- **PBKDF2 con SHA-256 (100.000 iteraciones):** Derivación nativa con Web Crypto API. Sin contraseñas en texto plano.
- **Firma Criptográfica HMAC-SHA256 (Anti-Tampering):** Firma de comandos (`INICIO`, `RESET`, `SIM_E1`, `SIM_S1`, `FORZAR_PORTON`, `AJUSTAR_TIEMPOS`) que previene manipulación desde las DevTools del navegador.
- **Persistencia en LocalStorage:** Almacenamiento seguro y automático de hashes y salts.

---

## 📂 Estructura del Proyecto

```
Automatizacion parcial/
├── index.html                  ← Aplicación Unificada (Setup Gerente, Login, Dashboard SCADA & Modal Crear Usuario)
├── style.css                   ← Estilos Industriales Dark Mode Integrados
├── app.js                      ← Lógica Completa (PBKDF2, HMAC, Jerarquía RBAC, Motor Canvas 2D)
├── README.md                   ← Documentación técnica académica
└── plan_de_verificacion.txt    ← Protocolo de pruebas
```

---

## 💻 Instrucciones de Ejecución

1. Abra la carpeta `Automatizacion parcial`.
2. Haga **doble clic en `index.html`** en Opera GX, Chrome, Edge o Firefox.
3. **Primer Arranque (Sin Gerente):** Complete el formulario inicial para registrar el Gerente de Planta.
4. **Inicio de Sesión:** Ingrese las credenciales del Gerente creado para acceder al Dashboard SCADA.
