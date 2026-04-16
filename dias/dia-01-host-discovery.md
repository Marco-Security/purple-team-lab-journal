# Día 1 — Host Discovery

**MITRE ATT&CK:** T1018 — Remote System Discovery  
**Táctica:** Discovery (TA0007)

## Red Team

### Comandos ejecutados
| Comando | Output |
|---|---|
| `ping -c 4 <target>` | TTL=64 → Linux confirmado |
| `nmap -sn <target>` | Host activo — MAC 08:00:27:FE:EB:70 (VirtualBox) |
| `nmap -sn <network>/24` | Network sweep — hosts activos identificados |
| `sudo arp-scan -l` | IPs + MACs + vendors en subred |

### Hallazgos
- TTL=64 confirma sistema operativo Linux en el target
- MAC prefix `08:00:27` identifica VirtualBox como vendor
- Network sweep `/24` completado en ~1 segundo — 256 ARP requests automatizados

## Blue Team

### Detección
| Comando | Qué detectó |
|---|---|
| `sudo tcpdump -i enp0s3 -n src host <attacker> and not port 22` | ICMP echo requests + ARP flood visibles |
| `sudo tcpdump -r dia01_capture.pcap -n` | ~512 ARP requests en menos de 1 segundo |

### Evidencia
- 4 paquetes ICMP Type 8 desde el atacante con timestamps exactos
- ARP flood de `.0` a `.255` completado en ~1 segundo — imposible para un humano
- Detección 100% manual — sin alertas automáticas

## Purple Team Analysis

**Effectiveness Score: 50/100**

| Red Team | Blue Team |
|---|---|
| ICMP ping identificó host activo | tcpdump capturó ICMP requests |
| ARP sweep mapeó toda la subred | ARP flood visible — patrón de automatización claro |
| TTL reveló SO Linux | Sin alerta automática |

### Security Gaps
- Sin IDS/IPS — Suricata no configurado
- Sin alertas automáticas en Wazuh para ICMP flood
- Sin baseline de tráfico normal
- Sin respuesta automática ante sweep

### Lección
El ataque más básico — ping sweep — ya expone la diferencia entre visibilidad manual y detección automatizada. Un SOC real necesita SIEM + IDS, no solo tcpdump.

## DVWA — Brute Force (Low)

### Hallazgos
- Formulario de login sin rate limiting, sin lockout, sin CAPTCHA
- Credencial válida encontrada: `admin / password`
- Hydra falló por problemas de ruta — resuelto con script bash + curl
- Script bash con `rockyou.txt` encontró la contraseña en segundos

### Mitigación
- Rate limiting: máximo 5 intentos por IP en 15 minutos
- Account lockout después de X intentos fallidos
- CAPTCHA en formulario de login
- MFA obligatorio

## 🟡 Wazuh
- Agent Windows-Marco activo y reportando
- 112 alertas totales (3 Medium + 109 Low)
- Wazuh no detectó el ICMP/ARP scan — agent monitorea eventos del OS, no tráfico LAN
