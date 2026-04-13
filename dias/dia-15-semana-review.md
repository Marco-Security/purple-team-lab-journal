# Día 15 — Semana 1-2 Review

**Fecha:** Abril 2026  
**Tipo:** Review & Consolidación

---

## Días completados

| Día | Tema | DVWA | Estado |
|-----|------|------|--------|
| 01 | Host Discovery | Brute Force | ✅ |
| 02 | Port Scanning TCP | Command Injection | ✅ |
| 03 | Port Scanning Avanzado — UDP & NSE | SQL Injection | ✅ |
| 04 | HTTP Enumeration | XSS Reflected | ✅ |
| 05 | SMB Enumeration | XSS Stored | ✅ |
| 06 | FTP & Database Enumeration | — | ✅ |
| 07 | SQL Injection Blind + sqlmap | SQLi Blind | ✅ |
| 08 | SNMP & DNS Enumeration | — | ✅ |
| 09 | File Inclusion — LFI & RFI | File Inclusion | ✅ |
| 10 | WAF Detection & Evasion | CSRF | ✅ |
| 11 | Nikto & OpenVAS | File Upload | ✅ |
| 12 | Metasploit Introducción | Insecure CAPTCHA | ✅ |
| 13 | Metasploit Exploitation | SQLi Medium | ✅ |
| 14 | Reverse Shells | XSS Medium | ✅ |

---

## Aprendizajes clave

### Reconocimiento y Scanning
Durante las primeras dos semanas se estableció la metodología base de reconocimiento. El flujo aprendido fue escanear dispositivos dentro de la red mediante protocolos TCP y UDP, identificar servicios ejecutados en cada dispositivo con nmap, y descubrir directorios y rutas ocultas usando scripts NSE de nmap, gobuster y Nikto. Metasploit complementó el proceso buscando CVEs asociados a las versiones de servicios identificadas.

La diferencia entre TCP y UDP es fundamental — TCP deja rastro del handshake y es más fácil de detectar, mientras que UDP es silencioso y frecuentemente ignorado en escaneos defensivos, dejando servicios como DNS y SNMP expuestos sin que el defensor lo sepa.

### Hallazgo más impactante — Reverse Shell
La reverse shell fue el hallazgo más impactante de las dos semanas. A través de una aplicación web vulnerable (DVWA File Upload) fue posible subir código PHP malicioso al servidor y establecer una conexión interactiva completa desde Ubuntu hacia Kali, evadiendo restricciones de firewall. El servidor víctima inicia la conexión saliente — que los firewalls generalmente permiten — en lugar de recibir una conexión entrante que sería bloqueada.

```
Aplicación vulnerable → File Upload → rshell.php en servidor →
Apache ejecuta PHP → fsockopen() conecta a Kali:4444 →
Shell interactiva como www-data
```

### Lección más importante — tcpdump
tcpdump cambió la perspectiva sobre seguridad defensiva. Al capturar tráfico entre Kali y Ubuntu fue posible ver en texto plano las peticiones HTTP con parámetros maliciosos — incluyendo payloads CSRF con `password_new=pwned` completamente visibles. Esto demostró que un IDS/IPS configurado para detectar patrones en el tráfico puede identificar ataques automatizados en tiempo real, y que HTTPS es necesario para proteger la confidencialidad de los datos en tránsito.

---

## Conceptos consolidados

**Scanning:** nmap TCP/UDP, NSE scripts, identificación de versiones con `-sV`

**Web Enumeration:** gobuster para directorios, Nikto para vulnerabilidades, Metasploit dir_scanner

**Vulnerabilidades web explotadas:**
- Brute Force, Command Injection, SQLi, XSS Reflected/Stored
- SQLi Blind, File Inclusion, CSRF, File Upload
- WAF Evasion, Insecure CAPTCHA, SQLi Medium, XSS Medium

**Conceptos defensivos:**
- tcpdump para análisis de tráfico
- Detección de patrones en requests HTTP
- Headers de seguridad — X-Frame-Options, httponly, Content-Type
- Validación server-side vs client-side

---

## Pendientes identificados

- OpenVAS — instalación incompleta, requiere sesión dedicada
- tcpdump en File Upload y Reverse Shell — Blue Team pendiente
- Escalada de privilegios — sin vectores en contenedor Docker, se retoma Día 16

---

## Conclusión

Las primeras dos semanas establecieron la base del Purple Team Lab — metodología de reconocimiento, explotación de vulnerabilidades web en niveles Low y Medium, y análisis defensivo con tcpdump. El hallazgo más relevante fue la cadena completa desde File Upload hasta Reverse Shell, demostrando cómo una aplicación vulnerable es suficiente para comprometer un servidor independientemente del estado del sistema operativo. tcpdump reveló que los ataques dejan rastros claros en el tráfico de red — la detección es posible si se sabe qué buscar.
