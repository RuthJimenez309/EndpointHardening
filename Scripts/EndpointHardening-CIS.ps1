<#
.SYNOPSIS
    EndpointHardening-CIS - Script de Automatización de Seguridad
    Basado en las recomendaciones de los CIS Benchmarks para Windows.
#>

# 1. Configuración de Rutas de Telemetría
$LogDir = "C:\Users\Ruth\Documents\EndpointHardening\Logs"
$LogFile = "$LogDir\HardeningTelemetry.json"

# 2. Función para generar entradas de Log formateadas para SIEM
function Write-SIEMLog {
    param (
        [string]$ControlID,
        [string]$Componente,
        [string]$Accion,
        [string]$Estado, # Ejemplo: Auditado, Corregido, Error
        [string]$Detalle
    )
    
    # Estructura de objeto plano optimizado para SIEM
    $LogEntry = [PSCustomObject]@{
        Timestamp  = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        Hostname   = $env:COMPUTERNAME
        ControlID  = $ControlID
        Componente = $Componente
        Accion     = $Accion
        Estado     = $Estado
        Detalle    = $Detalle
    }
    
    # Convertir a JSON en una sola línea (formato JSON Lines / NDJSON, ideal para SIEM)
    $JsonEntry = $LogEntry | ConvertTo-Json -Compress
    Add-Content -Path $LogFile -Value $JsonEntry
}

# Inicializar Telemetría del Script
Write-SIEMLog -ControlID "CIS-0.0" -Componente "ScriptEngine" -Accion "Inicio" -Estado "Ejecutando" -Detalle "Iniciando proceso de auditoría y hardening CIS."

# =============================================================================
# CONTROL 1: Deshabilitar protocolo obsoleto SMBv1 (CIS Control 4.8)
# Reducción de superficie frente a ransomware y movimiento lateral.
# =============================================================================
Write-Host "`n[*] Evaluando Control 1: Estado de SMBv1..." -ForegroundColor Cyan

# Comprobar el estado actual de la característica SMBv1
$SMBv1Status = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol"

if ($SMBv1Status.State -eq "Enabled") {
    Write-SIEMLog -ControlID "CIS-4.8" -Componente "SMBv1" -Accion "Auditoria" -Estado "Inseguro" -Detalle "El protocolo obsoleto SMBv1 se encuentra HABILITADO."
    Write-Host "[!] ALERTA: SMBv1 está habilitado. Procediendo a deshabilitar de forma segura..." -ForegroundColor Yellow
    
    try {
        # Comando de Hardening: Deshabilitar el protocolo de forma silenciosa
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop
        
        Write-SIEMLog -ControlID "CIS-4.8" -Componente "SMBv1" -Accion "Remediacion" -Estado "Corregido" -Detalle "SMBv1 ha sido deshabilitado exitosamente. Requiere reinicio programado."
        Write-Host "[+] ÉXITO: SMBv1 deshabilitado correctamente." -ForegroundColor Green
    }
    catch {
        Write-SIEMLog -ControlID "CIS-4.8" -Componente "SMBv1" -Accion "Remediacion" -Estado "Error" -Detalle "Fallo al intentar deshabilitar SMBv1: $_"
        Write-Host "[-] ERROR: No se pudo modificar SMBv1. Verifique privilegios de Administrador." -ForegroundColor Red
    }
} else {
    Write-SIEMLog -ControlID "CIS-4.8" -Componente "SMBv1" -Accion "Auditoria" -Estado "Seguro" -Detalle "SMBv1 ya se encuentra deshabilitado."
    Write-Host "[+] SEGURO: SMBv1 ya está deshabilitado." -ForegroundColor Green
}


# =============================================================================
# CONTROL 2: Deshabilitar resolución LLMNR (CIS Control 9.2)
# Mitigación contra envenenamiento de red local (Ataques MitM / Responder).
# =============================================================================
Write-Host "`n[*] Evaluando Control 2: Estado de LLMNR..." -ForegroundColor Cyan

$RegistryPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
$ValueName = "EnableMulticast"

# Asegurar que la ruta de la política en el registro exista
if (-not (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
}

$LLMNRStatus = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue

# En Windows, poner EnableMulticast en 0 deshabilita LLMNR de manera segura
if ($null -eq $LLMNRStatus -or $LLMNRStatus.$ValueName -ne 0) {
    Write-SIEMLog -ControlID "CIS-9.2" -Componente "LLMNR" -Accion "Auditoria" -Estado "Inseguro" -Detalle "Resolución LLMNR activa o no configurada en el registro."
    Write-Host "[!] ALERTA: LLMNR está activo. Aplicando política de Hardening en Registro..." -ForegroundColor Yellow
    
    try {
        # Modificación segura del registro para aplicar hardening corporativo
        New-ItemProperty -Path $RegistryPath -Name $ValueName -Value 0 -PropertyType DWord -Force | Out-Null
        
        Write-SIEMLog -ControlID "CIS-9.2" -Componente "LLMNR" -Accion "Remediacion" -Estado "Corregido" -Detalle "Se añadio EnableMulticast=0 en el registro para mitigar ataques LLMNR Poisoning."
        Write-Host "[+] ÉXITO: LLMNR deshabilitado a través de política de registro." -ForegroundColor Green
    }
    catch {
        Write-SIEMLog -ControlID "CIS-9.2" -Componente "LLMNR" -Accion "Remediacion" -Estado "Error" -Detalle "Error al modificar registro de DNSClient: $_"
        Write-Host "[-] ERROR: No se pudo aplicar el hardening de LLMNR." -ForegroundColor Red
    }
} else {
    Write-SIEMLog -ControlID "CIS-9.2" -Componente "LLMNR" -Accion "Auditoria" -Estado "Seguro" -Detalle "LLMNR ya se encuentra deshabilitado corporativamente."
    Write-Host "[+] SEGURO: LLMNR ya está desactivado mediante directiva." -ForegroundColor Green
}

# Finalizar ejecución del Script
Write-SIEMLog -ControlID "CIS-0.0" -Componente "ScriptEngine" -Accion "Fin" -Estado "Completado" -Detalle "Proceso de hardening finalizado correctamente."
Write-Host "`n[+] Hardening completado. Telemetría generada en la carpeta Logs." -ForegroundColor Green

