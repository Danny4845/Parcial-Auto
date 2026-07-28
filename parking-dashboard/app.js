const reloj = document.getElementById("reloj");
const listaHistorial = document.getElementById("listaHistorial");
const botonInicio = document.getElementById("botonInicio");
const botonDetener = document.getElementById("botonDetener");
const botonEmergencia = document.getElementById("botonEmergencia");
const botonSimularEntrada = document.getElementById("botonSimularEntrada");
const botonSimularSalida = document.getElementById("botonSimularSalida");
const estadoSistema = document.querySelector(".estado-sistema");
const indicadorEspaciosOcupados = document.getElementById("espaciosOcupados");
const indicadorEspaciosDisponibles = document.getElementById("espaciosDisponibles");
const indicadorVehiculosHoy = document.getElementById("vehiculosHoy");
const indicadorEstadoEntrada = document.getElementById("estadoEntrada");
const indicadorEstadoSalida = document.getElementById("estadoSalida");

let sistemaActivo = true;

const capacidadMaxima = 100;
let espaciosOcupados = 0;
let espaciosDisponibles = capacidadMaxima;
let vehiculosHoy = 0;
let barreraEntradaAbierta = false;
let barreraSalidaAbierta = false;

function actualizarPanel() {
    indicadorEspaciosOcupados.textContent = espaciosOcupados;
    indicadorEspaciosDisponibles.textContent = espaciosDisponibles;
    indicadorVehiculosHoy.textContent = vehiculosHoy;
    indicadorEstadoEntrada.textContent =
        barreraEntradaAbierta ? "Abierta" : "Cerrada";
    indicadorEstadoSalida.textContent =
        barreraSalidaAbierta ? "Abierta" : "Cerrada";
}

function actualizarReloj() {
    const fecha = new Date();
    const hora = fecha.toLocaleTimeString();
    reloj.textContent = hora;
}

setInterval(actualizarReloj, 1000);
actualizarReloj();

function agregarEvento(mensaje) {
    const fecha = new Date();
    const hora = fecha.toLocaleTimeString();
    const nuevoEvento = document.createElement("li");
    nuevoEvento.textContent = `${hora} - ${mensaje}`;
    listaHistorial.prepend(nuevoEvento);
}

botonInicio.addEventListener("click", () => {
    sistemaActivo = true;
    estadoSistema.textContent = "🟢 Sistema Activo";
    agregarEvento("Sistema iniciado.");
});

botonDetener.addEventListener("click", () => {
    sistemaActivo = false;
    estadoSistema.textContent = "🔴 Sistema detenido";
    agregarEvento("Sistema detenido.");
});

botonEmergencia.addEventListener("click", () => {
    sistemaActivo = false;
    estadoSistema.textContent = "🟠 Emergencia";
    agregarEvento("¡¡EMERGENCIA ACTIVADA!!");
});

botonSimularEntrada.addEventListener("click", () => {
    agregarEvento("Solicitud de entrada de vehículo.");
});

botonSimularSalida.addEventListener("click", () => {
    agregarEvento("Solicitud de salida de vehículo.");
});