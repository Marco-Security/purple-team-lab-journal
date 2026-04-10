# 🟣 Purple Team Lab Journal — 120 días

Documentación de mi journey de 120 días hacia un rol de SOC Analyst / Security Analyst.

## Objetivo
Convertirme en SOC Analyst.

## Certificaciones en progreso
- 🔄 SC-900 — Microsoft Security Fundamentals
- 🔄 SC-200 — Microsoft Security Operations Analyst

## Estructura del journal
Cada día cubre 4 secciones:
- 🟣 **Purple Team** — Red Team + Blue Team + Análisis
- 🔓 **DVWA** — Vulnerabilidades web prácticas
- 🔵 **App MS Security** — Dashboard de seguridad en desarrollo
- 🟡 **Wazuh SIEM** — Hardening real de Windows

## 📅 Índice de días

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
| 16 | Privilege Escalation Linux — SUID | T1548.001 | SQLi (High) | — |
| 17 | Privilege Escalation Linux — Sudo | T1548.003 | XSS (High) | — |
| 18 | Privilege Escalation Linux — Cron | T1053.003 | Brute Force (Medium) | — |
| 19 | Password Cracking — Hashcat | T1110.002 | Command Injection (Medium) | — |
| 20 | Network Sniffing — Wireshark | T1040 | File Inclusion (Medium) | — |
| 21 | ARP Spoofing & MITM | T1557.002 | CSRF (Medium) | — |
| 22 | Semana 3 Review | — | — | — |

#### Semana 4 — Initial Access & Exploitation
| Día | Tema | MITRE | DVWA | Link |
|-----|------|-------|------|------|
| 23 | Web Shells | T1505.003 | File Upload (Medium) | — |
| 24 | SQL Injection — SQLmap avanzado | T1190 | SQLi Blind (Medium) | — |
| 25 | XSS avanzado — BeEF Framework | T1185 | XSS (High) | — |
| 26 | SSRF — Server Side Request Forgery | T1190 | — | — |
| 27 | XXE — XML External Entity | T1190 | — | — |
| 28 | IDOR — Insecure Direct Object Reference | T1078 | — | — |
| 29 | Broken Authentication | T1078.001 | Brute Force (High) | — |
| 20 | Directory Traversal | T1083 | File Inclusion (High) | — |
| 31 | Mes 1 Review | — | — | — |

### MES 2 — Advanced Offensive & Detection
#### Semana 5-6 — Post Exploitation & Lateral Movement
| Día | Tema | MITRE | Link |
|-----|------|-------|------|
| 32 | Post Exploitation — Meterpreter | T1059.002 | — |
| 33 | Persistence — Cron & Startup | T1053 | — |
| 34 | Credential Dumping | T1003 | — |
| 35 | Pass the Hash | T1550.002 | — |
| 36 | Lateral Movement — SSH | T1021.004 | — |
| 37 | Lateral Movement — SMB | T1021.002 | — |
| 38 | Pivoting | T1090 | — |
| 39 | C2 — Command & Control básico | T1071 | — |
| 40 | Data Exfiltration | T1041 | — |
| 41 | Semana 5-6 Review | — | — |

#### Semana 7 — Mobile Pentesting
| Día | Tema | MITRE | Link |
|-----|------|-------|------|
| 42 | Android Security — ADB | T1437 | — |
| 43 | APK Analysis — jadx-gui | T1430 | — |
| 44 | Insecure Data Storage | T1533 | — |
| 45 | Mobile Traffic Interception | T1040 | — |
| 46 | Mobile Authentication Bypass | T1078 | — |

#### Semana 8 — Purple Team Integration
| Día | Tema | MITRE | Link |
|-----|------|-------|------|
| 47 | Purple Team Exercise 1 | T1018-T1190 | — |
| 48 | Purple Team Exercise 2 | T1021-T1059 | — |
| 49 | Detection Engineering — Sigma Rules | — | — |
| 50 | Incident Response — Playbooks | — | — |
| 51 | Mes 2 Review | — | — |

### MES 3 — Microsoft Ecosystem
#### Semana 9-10 — Azure AD & Entra ID
| Día | Tema | MITRE | Link |
|-----|------|-------|------|
| 52 | Azure AD — Fundamentos | T1078.004 | — |
| 53 | Azure AD — Enumeration | T1087.004 | — |
| 54 | Entra ID — Conditional Access | — | — |
| 55 | Microsoft Defender — Configuración | — | — |
| 56 | Microsoft Defender — Alertas & Respuesta | — | — |

#### Semana 11 — Microsoft Sentinel & KQL
| Día | Tema | MITRE | Link |
|-----|------|-------|------|
| 61 | Sentinel — Introducción & Setup | — | — |
| 62 | KQL — Fundamentos | — | — |
| 63 | KQL — Hunting Queries | — | — |
| 64 | Sentinel — Custom Analytics Rules | — | — |
| 65 | Sentinel — Incident Management | — | — |

#### Semana 12 — Active Directory
| Día | Tema | MITRE | Link |
|-----|------|-------|------|
| 71 | Active Directory — Fundamentos | T1018 | — |
| 72 | AD Enumeration — BloodHound | T1087.002 | — |
| 73 | Kerberoasting | T1558.003 | — |
| 74 | Pass the Ticket | T1550.003 | — |
| 75 | AD Defense — Hardening | — | — |

### MES 4 — Automation & Certification
#### Semana 13-14 — Purple Team Platform
| Día | Tema | Link |
|-----|------|------|
| 91 | App MS — Azure Sentinel Integration | — |
| 92 | App MS — Defender API | — |
| 93 | App MS — Graph API | — |
| 94 | Wazuh — Thermodynamic Dashboard | — |
| 95 | Purple Team Platform — Final | — |

## Entorno técnico
- **Atacante:** Kali Linux
- **Target:** Ubuntu con DVWA + OWASP Juice Shop
- **SIEM:** Wazuh 4.14.3 — Agent: Windows-Marco
- **App MS:** Flask + React — [repo](https://github.com/Marco-Security/ms-security-app)
