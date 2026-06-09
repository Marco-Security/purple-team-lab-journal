# Día 34 — Credential Dumping + Defender Advanced Hunting

**Fecha:** Junio 2026  
**MITRE:** T1003  
**Target:** Ubuntu 192.168.1.96

---

## Teoría

### ¿Qué es Credential Dumping?

Credential Dumping es la técnica donde el atacante extrae credenciales almacenadas en el sistema — hashes de passwords, tokens de sesión o passwords en texto plano — para usarlas en ataques posteriores.

```
Sin credential dumping:
Atacante tiene acceso a 1 máquina → limitado a ese sistema

Con credential dumping:
Atacante extrae hashes → los crackea o reutiliza → accede a más sistemas
```

**Fuentes de credenciales en Linux:**

| Archivo | Qué contiene | Requiere |
|---------|-------------|----------|
| `/etc/shadow` | Hashes de passwords | Root |
| `/etc/passwd` | Info de usuarios (sin hashes) | Cualquier usuario |
| `~/.bash_history` | Comandos — puede tener passwords | Usuario propietario |
| Configs de apps | Credenciales DB, APIs | Varía |

**Equivalentes en Windows (referencia SC-200):**

| Fuente | Herramienta | MITRE |
|--------|------------|-------|
| SAM database | mimikatz, hashdump | T1003.002 |
| LSASS memory | mimikatz lsadump | T1003.001 |
| NTDS.dit (AD) | secretsdump | T1003.003 |

---

## Red Team

### Sección 1 — Extracción de hashes de /etc/shadow

```bash
ssh vboxuser@192.168.1.96
sudo su

grep -v ':!:' /etc/shadow | grep -v ':\*:' | grep -v '^$'
```

El filtro excluye cuentas bloqueadas (`!`) y sin password (`*`), dejando solo cuentas con hash real.

**Resultado — 2 hashes reales:**
```
vboxuser:$y$j9T$t23wcW0kpA82bAFLmAeHe1$yzOtb71hLRSzCDpQ779nILRdZmUWImvPEFw4XP/7B/2
lowpriv:$y$j9T$M63lj3LfX.AXcwtx8uwOQ1$Ol0kACdMbWT1qc662.c2FNCIa.c6hl1xf3bqdZKvRn7
```

### Sección 2 — Identificación del algoritmo

El prefijo del hash indica el algoritmo usado:

| Prefijo | Algoritmo | Resistencia |
|---------|-----------|-------------|
| `$1$` | MD5 | Muy débil — millones/seg |
| `$5$` | SHA-256 | Débil — miles/seg |
| `$6$` | SHA-512 | Media — cientos/seg |
| `$y$` | yescrypt | Alta — diseñado anti-GPU |

Ambos hashes usan **`$y$` = yescrypt**, el algoritmo por defecto en Ubuntu moderno, diseñado específicamente para resistir cracking por GPU y CPU.

### Sección 3 — Intentos de cracking

**John the Ripper — formato no reconocido:**
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hashes.txt
# → No password hashes loaded
# John estándar no soporta yescrypt nativamente
```

**Hashcat modo 7400 (sha512crypt) — token length exception:**
```bash
hashcat -m 7400 /tmp/hashes.txt /usr/share/wordlists/rockyou.txt
# → Token length exception — formato incorrecto
```

**Hashcat modo 70200 (Scrypt-Yescrypt) — separator unmatched:**
```bash
hashcat -m 70200 /tmp/hashes_only.txt /usr/share/wordlists/rockyou.txt
# → Separator unmatched
# El modo 70200 espera formato SCRYPT:N:r:p:salt:hash, no el formato crypt $y$
```

El modo 70200 es para scrypt genérico, no para el yescrypt de `/etc/shadow`.

**John con --format=crypt — funciona pero impráctico:**
```bash
john --format=crypt --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hashes.txt
# → Loaded 2 password hashes (crypt, generic crypt(3))
# → 16 hashes/segundo
# → ETA: 25+ días
```

`--format=crypt` usa la librería del sistema que sí soporta yescrypt, pero la velocidad fue de apenas **16 hashes/segundo**.

### Sección 4 — Resultado: yescrypt resistió

**Velocidad comparada por algoritmo (CPU estándar):**
```
MD5 ($1$)      → millones/segundo → crackeable en minutos
SHA-512 ($6$)  → cientos/segundo  → crackeable en horas/días
yescrypt ($y$) → ~16/segundo      → impráctico sin GPU dedicada
```

**Estimación con rockyou.txt:**
```
rockyou.txt = ~14 millones de passwords
yescrypt en CPU ≈ 16 hashes/segundo
14,000,000 / 16 = 875,000 segundos ≈ 10 días por hash
```

El ataque se detuvo tras confirmar la velocidad. **El credential dumping fue exitoso** (los hashes se extrajeron correctamente de `/etc/shadow`), pero **el cracking offline resultó impráctico** con hardware estándar contra yescrypt.

### Conclusión del ataque

```
✅ Credential dumping → hashes extraídos de /etc/shadow
❌ Offline cracking   → yescrypt resistió con CPU + rockyou
```

Este resultado demuestra por qué Linux moderno migró a yescrypt: aunque un atacante comprometa root y obtenga `/etc/shadow`, los passwords permanecen protegidos si son razonablemente robustos. El cuello de botella del atacante pasa de "obtener los hashes" a "crackearlos" — y yescrypt hace lo segundo prohibitivamente costoso.

**Vectores alternativos cuando el cracking falla:**
- **Pass the Hash** — reutilizar el hash directamente sin crackearlo (Día 35)
- **GPU cracking** — yescrypt sigue siendo lento incluso con GPU, pero más viable
- **Diccionarios dirigidos** — wordlists personalizadas basadas en OSINT del objetivo
- **Buscar passwords en otros lugares** — `.bash_history`, configs, memoria

---

## SC-200 — Advanced Hunting para Credential Access

### Detección de credential dumping en Defender XDR

En Windows, el credential dumping deja rastros detectables. La query KQL para cazar accesos a LSASS:

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("mimikatz.exe", "procdump.exe")
   or ProcessCommandLine contains "lsass"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| sort by Timestamp desc
```

### Categoría CredentialAccess en el tenant

```kql
AlertInfo
| where Timestamp > ago(30d)
| where Category == "CredentialAccess"
| project Timestamp, Title, Severity, ServiceSource
| sort by Timestamp desc
```

El tenant tiene 2 alertas de CredentialAccess (vistas en días anteriores) — ambas relacionadas con "Unusual number of failed sign-in attempts", que es un indicador de brute force contra credenciales.

### Conceptos clave para el examen

**MITRE T1003 — OS Credential Dumping** tiene subtécnicas:
- T1003.001 — LSASS Memory (Windows)
- T1003.002 — Security Account Manager / SAM (Windows)
- T1003.003 — NTDS (Active Directory)
- T1003.008 — /etc/passwd y /etc/shadow (Linux) ← lo que hicimos hoy

**Defender for Endpoint** detecta credential dumping mediante:
- Monitoreo de acceso a LSASS
- Detección de herramientas conocidas (mimikatz, procdump)
- Análisis de comportamiento — procesos que leen memoria de otros procesos

---

## Blue Team

### Detección de Credential Dumping

**Linux:**
```bash
# Auditar accesos a /etc/shadow
auditctl -w /etc/shadow -p r -k shadow_access

# Revisar quién leyó shadow recientemente
ausearch -k shadow_access
```

**KQL en Defender (Windows):**
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("sekurlsa", "lsadump", "procdump lsass")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### Mitigación

- **Algoritmos modernos de hashing** — yescrypt en lugar de MD5/SHA. Ubuntu ya lo hace por defecto
- **Passwords robustos** — yescrypt protege solo si el password no está en wordlists comunes
- **Credential Guard (Windows)** — aísla LSASS para prevenir dumping
- **Least privilege** — limitar quién tiene root/admin que puede leer shadow/SAM
- **MFA** — aunque el password se comprometa, el segundo factor protege
- **Monitoreo de acceso a archivos sensibles** — alertar en lecturas de `/etc/shadow`

---

## Conclusión

El Día 34 demostró el ciclo completo de credential dumping en Linux y, más importante, sus límites. La extracción de hashes de `/etc/shadow` fue trivial con acceso root, pero el cracking offline reveló por qué yescrypt es el estándar moderno: a 16 hashes/segundo en CPU, crackear un password robusto tomaría semanas. Esto cambia la estrategia del atacante — en lugar de crackear, conviene reutilizar el hash directamente (Pass the Hash, Día 35) o buscar credenciales en texto plano en otros lugares del sistema. Para el SC-200, el credential dumping mapea a T1003 con subtécnicas específicas por fuente, y Defender for Endpoint lo detecta monitoreando accesos a LSASS y herramientas conocidas como mimikatz.
