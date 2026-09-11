# Automatización de Endpoint Hardening & Telemetría para SIEM (CIS Benchmarks)

## Descripción del Proyecto

Este proyecto simula las responsabilidades clave de un **Ingeniero de Endpoint Security**. Consiste en un desarrollo en PowerShell diseñado para auditar, mitigar y generar telemetría automatizada sobre endpoints Windows, alineado con las mejores prácticas internacionales del **Center for Internet Security (CIS) Benchmarks**.

El script valida de manera segura configuraciones críticas del sistema operativo, aplica remediaciones orientadas a reducir la superficie de ataque y centraliza los eventos en un formato estructurado optimizado para entornos **SIEM (Splunk, Elastic, Microsoft Sentinel)**.

---

## Controles CIS Implementados

### 1. Deshabilitación de SMBv1 (CIS Control 4.8)

- **Riesgo:** El protocolo Server Message Block v1 (SMBv1) carece de cifrado nativo y es altamente vulnerable a exploits heredados (ej. EternalBlue). Es un vector crítico para el despliegue de Ransomware (_WannaCry_, _Petya_) y movimientos laterales en redes corporativas.
- **Solución Automatizada:** El script detecta el estado de la característica opcional y la remedia de forma silenciosa si se encuentra activa.

### 2. Deshabilitación de LLMNR (CIS Control 9.2)

- **Riesgo:** Link-Local Multicast Name Resolution (LLMNR) permite la resolución de nombres local cuando DNS falla. Atacantes internos usan herramientas como _Responder_ para envenenar estas peticiones (LLMNR Poisoning) y capturar hashes de contraseñas NTLMv2.
- **Solución Automatizada:** Modificación forzada y segura en la colmena del registro (`HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient`) inyectando el valor `EnableMulticast = 0`.

---

## Diseño de Telemetría (SIEM-Ready)

El script no solo actúa sobre el sistema; genera logs en formato **JSON Lines (NDJSON)** guardados en la ruta corporativa determinada. Cada evento cuenta con:

- `Timestamp`: Registro temporal en formato ISO 8601 UTC.
- `Hostname`: Identificador único del dispositivo afectado.
- `ControlID`: Mapeo directo con el control formal de CIS Benchmarks.
- `Estado`: Clasificación estricta (`Seguro`, `Inseguro`, `Corregido`, `Error`).

### Ejemplo de Log Capturado durante la Auditoría:

```json
{
  "Timestamp": "2026-09-10T20:56:02Z",
  "Hostname": "DESKTOP-LJK1VF5",
  "ControlID": "CIS-9.2",
  "Componente": "LLMNR",
  "Accion": "Auditoria",
  "Estado": "Inseguro",
  "Detalle": "Resolución LLMNR activa o no configurada en el registro."
}
```

---

## Guía de Ejecución Segura

1. Clonar el repositorio en el directorio de trabajo local.
2. Abrir una consola de PowerShell con **Privilegios de Administrador**.
3. Ejecutar el Script de Hardening:
   ```powershell
   .\Scripts\EndpointHardening-CIS.ps1
   ```
4. Consultar y validar la telemetría generada en la carpeta local:
   ```powershell
   Get-Content -Path "Logs\HardeningTelemetry.json" | ConvertFrom-Json
   ```

---

## Enfoque de Entrevista (Defensa Técnica)

- **¿Cómo mitiga el malware?** Al apagar SMBv1 impedimos la propagación automatizada de gusanos de ransomware en la red. Al desactivar LLMNR, neutralizamos la fase de reconocimiento local y robo de credenciales en un Directorio Activo.
- **¿Cómo defenderlo ante el equipo de Infraestructura/TI?** Se destaca que el script cuenta con bloques `try/catch` para evitar caídas del sistema, se ejecuta de forma silenciosa sin interrumpir las tareas del usuario final y permite un modo puramente consultivo/auditoría para mapear riesgos en una fase de pruebas (Staging) antes de forzar políticas restrictivas en producción.
