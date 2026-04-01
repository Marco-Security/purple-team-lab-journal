# Día 6 — FTP & Database Enumeration

**MITRE ATT&CK:** T1210 — Exploitation of Remote Services  
**Táctica:** Lateral Movement (TA0008)

## 🔴 Red Team

### Comandos ejecutados
| Comando | Output |
|---|---|
| `nmap -p 21 --script ftp-anon,ftp-syst <target>` | Anonymous FTP login allowed — vsFTPd 3.0.5 |
| `ftp <target>` → usuario: `anonymous` | Acceso sin contraseña — directorio raíz accesible |
| `get secret.txt` | Archivo con credenciales descargado en texto plano |
| `nmap -p 3306 --script mysql-info <target>` | MySQL 8.4.8 expuesto — puerto 3306 abierto |
| `mysql -h <target> -u root --skip-ssl` | Acceso a MySQL sin contraseña desde Kali |
| `SHOW DATABASES;` | 4 bases de datos del sistema + `empresa` |
| `SELECT * FROM empresa.empleados;` | 3 credenciales en texto plano expuestas |

### Hallazgos críticos
- FTP con anonymous login habilitado — acceso sin credenciales
- Archivo `secret.txt` con credenciales en texto plano accesible via FTP
- MySQL accesible desde cualquier IP sin contraseña
- 3 usuarios con passwords en texto plano extraídos: admin, marco, juan
- FTP sin cifrado — credenciales viajan en texto plano por la red

## 🔵 Blue Team

### Detección
| Comando | Qué detectó |
|---|---|
| `sudo tcpdump -i enp0s3 -n src host <attacker> and not port 22 -w dia06_capture.pcap` | Conexiones a puertos 21 y 3306 capturadas |
| `sudo tcpdump -r dia06_capture.pcap -n \| head -20` | `USER anonymous` y `PASS IEUser@` visibles en texto plano |

### Evidencia
- `FTP: USER anonymous` visible en captura — credencial sin cifrado
- `FTP: PASS IEUser@` capturada en texto plano — ataque MITM trivial
- Conexiones simultáneas a puerto 21 y 3306 identificadas
- En un ataque MITM real, estas credenciales serían interceptadas automáticamente

## 🟣 Purple Team Analysis

**Effectiveness Score: 70/100**

| 🔴 Red Team | 🔵 Blue Team |
|---|---|
| FTP anonymous login — acceso sin credenciales | Credenciales FTP capturadas en texto plano |
| MySQL sin contraseña — DB completa expuesta | Conexiones a 21 y 3306 visibles en tcpdump |
| Credenciales en texto plano extraídas | Sin alerta automática |

### Security Gaps
- FTP sin autenticación — anonymous login habilitado
- FTP sin cifrado — reemplazar con SFTP o FTPS
- MySQL accesible desde cualquier IP sin contraseña
- Passwords almacenados en texto plano — usar bcrypt
- Sin IDS para detectar accesos anónimos automáticamente

### Lección
FTP es un protocolo de los años 70 — sin cifrado por diseño. Todo lo que viaja por FTP es legible por cualquier persona en la misma red. En entornos reales FTP nunca debería usarse — SFTP (puerto 22) o FTPS son las alternativas seguras. MySQL expuesto sin contraseña es igualmente crítico — una DB accesible desde la red sin autenticación es compromiso total de datos.

## 🔓 DVWA
- Pendiente — sesión enfocada en FTP y MySQL

## 🔵 App MS Security
- Pendiente — continuación Día 7

## 🟡 Wazuh
- Pendiente — análisis en próxima sesión
