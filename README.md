# Purple Team Lab Journal — 52 días

Documentación de mi journey de 52 días hacia un rol de SOC Analyst / Security Analyst.

## Objetivo

Convertirme en SOC Analyst.

## Certificaciones

- SC-900 — Microsoft Security Fundamentals ✓
- SC-200 — Microsoft Security Operations Analyst (examen: 18 Junio 2026)

## Estructura del journal

Cada día cubre 3 secciones:

- **Purple Team** — Red Team + Blue Team + Análisis
- **DVWA / Juice Shop** — Vulnerabilidades web prácticas (Días 1–31)
- **App MS Security** — Dashboard de seguridad en desarrollo (Días 1–27)

## Índice de días

### MES 1 — Red Team + Blue Team Basics

#### Semana 1-2 — Reconnaissance & Scanning

| Día | Tema | MITRE | DVWA | Link |
|-----|------|-------|------|------|
| 01 | Host Discovery | T1018 | Brute Force | [→](dias/dia-01-host-discovery.md) |
| 02 | Port Scanning TCP | T1046 | Command Injection | [→](dias/dia-02-port-scanning-tcp.md) |
| 03 | Port Scanning Avanzado — UDP & NSE | T1046 | SQL Injection | [→](dias/dia-03-port-scanning-avanzado.md) |
| 04 | HTTP Enumeration | T1190 | XSS Reflected | [→](dias/dia-04-http-enumeration.md) |
| 05 | SMB Enumeration | T1021.002 | XSS Stored | [→](dias/dia-05-smb-enumeration.md) |
| 06 | FTP & Database Enumeration | T1210 | — | [→](dias/dia-06-ftp-database.md) |
| 07 | SQL Injection Blind | T1190 | SQLi Blind | [→](dias/dia-07-dvwa-sqli-blind.md) |
| 08 | SNMP & DNS Enumeration | T1046 | File Inclusion | [→](dias/dia-08-snmp-dns-enumeration.md) |
| 09 | File Inclusion — LFI & RFI | T1190 | File Inclusion | [→](dias/dia-09-file-inclusion.md) |
| 10 | WAF Detection & Evasion | T1190 | CSRF | [→](dias/dia-10-waf-detection-evasion.md) |
| 11 | Vulnerability Scanning — Nikto & OpenVAS | T1595 | File Upload | [→](dias/dia-11-vulnerability-scanning.md) |
| 12 | Metasploit — Introducción | T1203 | Insecure CAPTCHA | [→](dias/dia-12-metasploit-intro.md) |
| 13 | Metasploit — Exploitation | T1203 | SQL Injection (Medium) | [→](dias/dia-13-metasploit-exploitation.md) |
| 14 | Reverse Shells | T1059 | XSS (Medium) | [→](dias/dia-14-reverse-shells.md) |
| 15 | Semana 1-2 Review | — | — | [→](dias/dia-15-semana-review.md) |

#### Semana 3 — Vulnerability Assessment

| Día | Tema | MITRE | DVWA | Link |
|-----|------|-------|------|------|
| 16 | Privilege Escalation Linux — SUID | T1548.001 | SQLi (High) | [→](dias/dia-16-privesc-suid.md) |
| 17 | Privilege Escalation Linux — Sudo | T1548.003 | XSS (High) | [→](dias/dia-17-privesc-sudo.md) |
| 18 | Privilege Escalation Linux — Cron | T1053.003 | Brute Force (Medium) | [→](dias/dia-18-privesc-cron.md) |
| 19 | Password Cracking — Hashcat | T1110.002 | Command Injection (Medium) | [→](dias/dia-19-password-cracking.md) |
| 20 | Network Sniffing — Wireshark | T1040 | File Inclusion (Medium) | [→](dias/dia-20-network-sniffing.md) |
| 21 | ARP Spoofing & MITM | T1557.002 | CSRF (Medium) | [→](dias/dia-21-arp-spoofing.md) |
| 22 | Semana 3 Review | — | — | [→](dias/dia-22-semana-review.md) |

#### Semana 4 — Initial Access & Exploitation

| Día | Tema | MITRE | DVWA / Juice Shop | Link |
|-----|------|-------|-------------------|------|
| 23 | Web Shells | T1505.003 | File Upload (Medium) | [→](dias/dia-23-web-shells.md) |
| 24 | SQL Injection — SQLmap avanzado | T1190 | SQLi Blind (Medium) | [→](dias/dia-24-sqlmap-avanzado.md) |
| 25 | XSS avanzado — BeEF Framework | T1185 | XSS (High) | [→](dias/dia-25-beef-framework.md) |
| 26 | SSRF — Server Side Request Forgery | T1190 | — | [→](dias/dia-26-ssrf.md) |
| 27 | XXE — XML External Entity | T1190 | — | [→](dias/dia-27-xxe.md) |
| 28 | IDOR — Insecure Direct Object Reference | T1078 | — | [→](dias/dia-28-idor.md) |
| 29 | Broken Authentication | T1078.001 | Brute Force (High) | [→](dias/dia-29-broken-auth.md) |
| 30 | Directory Traversal | T1083 | File Inclusion (High) | [→](dias/dia-30-directory-traversal.md) |
| 31 | Mes 1 Review | — | — | [→](dias/dia-31-mes1-review.md) |

### MES 2 — Advanced Offensive & Detection

#### Semana 5-6 — Post Exploitation & Lateral Movement

| Día | Tema | MITRE | Link |
|-----|------|-------|------|
| 32 | Post Exploitation — Meterpreter | T1059.002 | [→](dias/dia-32-meterpreter.md) |
| 33 | Persistence — Cron & Startup | T1053 | [→](dias/dia-33-persistence.md) |
| 34 | Credential Dumping | T1003 | [→](dias/dia-34-credential-dumping.md) |
| 35 | Pass the Hash | T1550.002 | [→](dias/dia-35-pass-the-hash.md) |
| 36 | Lateral Movement — SSH | T1021.004 | — |
| 37 | Lateral Movement — SMB | T1021.002 | — |
| 38 | Pivoting | T1090 | — |
| 39 | C2 — Command & Control básico | T1071 | — |
| 40 | Data Exfiltration | T1041 | — |
| 41 | Semana 5-6 Review | — | — |

### MES 3 — Microsoft Ecosystem

#### Semana 7-8 — Azure AD & Entra ID

| Día | Tema | MITRE | Link |
|-----|------|-------|------|
| 42 | Azure AD — Fundamentos | T1078.004 | — |
| 43 | Azure AD — Enumeration | T1087.004 | — |
| 44 | Entra ID — Conditional Access | — | — |
| 45 | Microsoft Defender — Configuración | — | — |
| 46 | Microsoft Defender — Alertas & Respuesta | — | — |

#### Semana 9 — Active Directory

| Día | Tema | MITRE | Link |
|-----|------|-------|------|
| 47 | Active Directory — Fundamentos | T1018 | — |
| 48 | AD Enumeration — BloodHound | T1087.002 | — |
| 49 | Kerberoasting | T1558.003 | — |
| 50 | Pass the Ticket | T1550.003 | — |
| 51 | AD Defense — Hardening | — | — |

### FINAL — Full Chain Attack

| Día | Tema | MITRE | Link |
|-----|------|-------|------|
| 52 | Full Chain Attack — Compromiso completo de Ubuntu | T1018 → T1059 → T1548 → T1041 | — |

**Full Chain Attack** es un ejercicio integrador sin guía previa. Partiendo de cero — solo con la IP de la víctima — se ejecuta un ataque completo que encadena todas las fases aprendidas en el journal:

```
Reconnaissance → Scanning → Enumeration → Exploitation
→ Privilege Escalation → Persistence → Data Exfiltration
```

El objetivo es comprometer completamente la máquina Ubuntu (192.168.1.96) documentando cada decisión táctica, los comandos ejecutados y las técnicas de detección desde el Blue Team.

## Entorno técnico

- **Atacante:** Kali Linux (192.168.1.132)
- **Target:** Ubuntu con DVWA + OWASP Juice Shop (192.168.1.96)
- **Microsoft E5:** Cuenta compartida — Microsoft Defender XDR + Sentinel
- **Azure:** Cuenta estudiante ($100 crédito) — VMs, Log Analytics, Sentinel
- **App MS:** Flask + React — [repo](https://github.com/Marco-Security/ms-security-app)
- **Mobile Lab:** MobilePwn Lab — [repo](https://github.com/Marco-Security/mobilepwn-lab)
