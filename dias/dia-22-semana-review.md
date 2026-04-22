# Día 22 — Semana 3 Review

**Fecha:** Abril 2026  
**Formato:** Mock entrevista técnica SOC Analyst  
**Semana cubierta:** Días 16-21

---

## Resumen de la Semana 3

| Día | Tema | Técnica clave |
|-----|------|---------------|
| 16 | Privilege Escalation SUID | `find -exec /bin/bash -p` |
| 17 | Privilege Escalation Sudo | `sudo python3 -c 'os.system("/bin/bash")'` |
| 18 | Privilege Escalation Cron | Modificar script con chmod 777 |
| 19 | Password Cracking Hashcat | MD5 crackeado en 1 segundo |
| 20 | Network Sniffing Wireshark | tshark captura payloads HTTP |
| 21 | ARP Spoofing & MITM | Credenciales HTTP en texto plano |

---

## Mock Entrevista — Q&A

### Q1: Un atacante obtiene acceso como usuario sin privilegios en Linux y encuentra un binario con SUID. ¿Qué puede hacer y cómo lo detectarías?

**Respuesta:**
Cualquier binario con SUID y capacidad de ejecutar subprocesos puede ser explotado para escalar privilegios. El bit SUID hace que el binario corra con los permisos del dueño (root) sin importar quién lo ejecute. Si el binario acepta parámetros como `-exec`, puede lanzar una shell que hereda esos permisos.

**Exploit concreto:**
```bash
find . -exec /bin/bash -p \; -quit
# → euid=0(root)
```

**Detección Blue Team:**
```bash
find / -perm -4000 -type f
```
Lista todos los binarios con SUID. En un sistema bien configurado esa lista debe ser corta y conocida. Cualquier binario inesperado es una alerta. GTFOBins es la referencia para identificar cuáles son explotables.

**Mitigación:** nunca asignar SUID a binarios que no lo necesiten estrictamente.

---

### Q2: Encuentras en `/etc/sudoers`: `deploy ALL=(ALL) NOPASSWD: /usr/bin/python3`. ¿Es un problema de seguridad?

**Respuesta:**
Sí — permite al usuario deploy ejecutar python3 con sudo sin contraseña. Python puede ejecutar subprocesos como una shell, permitiendo escalada completa de privilegios.

**Exploit concreto:**
```bash
sudo python3 -c 'import os; os.system("/bin/bash")'
# → uid=0(root)
```

**Detección Blue Team:**
Revisar `/etc/sudoers` y `/etc/sudoers.d/` periódicamente buscando entradas con `NOPASSWD` combinadas con binarios en GTFOBins. Si el binario aparece en GTFOBins con entrada de sudo, es explotable.

**Mitigación:** nunca permitir sudo sobre binarios que puedan ejecutar comandos arbitrarios. Usar wrappers específicos en lugar del binario completo.

---

### Q3: Un cron job de root ejecuta `/opt/backup.sh` cada minuto con permisos `chmod 777`. ¿Cuál es el riesgo?

**Respuesta:**
chmod 777 da permisos de escritura a cualquier usuario sobre el archivo. Un usuario sin privilegios puede modificar el script para que ejecute código malicioso — cuando cron lo ejecute como root, el código del atacante corre con privilegios de root.

**Cadena de ataque:**
```bash
echo 'echo "lowpriv ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers' > /opt/backup.sh
# Esperar 1 minuto → cron ejecuta como root
sudo bash → uid=0(root)
```

**Diferenciador vs SUID y Sudo:** el ataque es silencioso y automático — no requiere interacción del administrador.

**Detección Blue Team:** File Integrity Monitoring sobre scripts ejecutados por root. Wazuh FIM hubiera detectado el cambio en `/opt/backup.sh` inmediatamente.

**Mitigación:** scripts de cron deben tener permisos `700` y ser propiedad de root.

---

### Q4: Tienes hashes MD5 de contraseñas. ¿Por qué MD5 es inseguro y qué alternativa recomendarías?

**Respuesta:**
MD5 es vulnerable a ataques de fuerza bruta por su velocidad — herramientas como Hashcat pueden probar 31,665 hashes/segundo usando solo CPU. Además no incluye salt, lo que permite ataques con rainbow tables.

**Demostrado en el lab:**
```bash
hashcat -m 0 dvwa_hashes.txt rockyou.txt --force
# 4/4 hashes crackeados en 1 segundo
```

**Alternativa — bcrypt:**
- Key stretching: 4,096 iteraciones por intento → ~10 hashes/segundo
- Salt aleatorio por usuario → elimina rainbow tables
- Con rockyou.txt: MD5 en minutos, bcrypt en semanas

**Otras alternativas más seguras:** argon2 y scrypt — además del tiempo consumen memoria, haciendo ataques con GPU menos eficientes.

**Corrección técnica importante:** bcrypt no "aumenta la entropía" — aumenta el costo computacional y agrega salt. La entropía es un concepto diferente relacionado con la aleatoriedad del input.

---

### Q5: ¿Cómo interceptarías credenciales HTTP con ARP Spoofing? ¿Por qué no funciona con HTTPS?

**Respuesta:**
ARP Spoofing consiste en enviar ARP replies falsos para posicionarse como Man in the Middle entre la víctima y el router.

**Proceso técnico:**
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward  # habilitar reenvío
sudo arpspoof -i eth0 -t víctima gateway # engañar a la víctima
sudo arpspoof -i eth0 -t gateway víctima # engañar al router
sudo tshark -i eth0 -Y "http" ...        # capturar tráfico
```

**¿Por qué no funciona con HTTPS?**
TLS establece un canal cifrado end-to-end. El atacante intercepta los paquetes pero solo ve datos cifrados — nunca el contenido. En el lab confirmamos esto: Google fue ilegible, DVWA en HTTP fue texto plano con credenciales visibles.

**Matiz importante para SOC:** ARP Spoofing puede combinarse con SSL Stripping para degradar HTTPS a HTTP si el sitio no implementa HSTS. Por eso HSTS existe como capa adicional de protección.

**Detección:** arpwatch monitorea cambios en la tabla ARP y alerta sobre MACs que cambian frecuentemente.

---

## Lecciones Clave de la Semana 3

**Privilege Escalation:**
- SUID + capacidad de ejecutar subprocesos = escalada garantizada
- Sudo mal configurado con binarios en GTFOBins = escalada garantizada
- Scripts de cron con permisos de escritura = escalada garantizada
- Los tres vectores son detectables con auditoría básica del sistema

**Password Security:**
- MD5 sin salt es equivalente a guardar contraseñas en texto plano para un atacante con GPU
- bcrypt es el mínimo aceptable — argon2 es la recomendación actual
- El factor de costo de bcrypt debe ajustarse con el tiempo conforme las GPUs mejoran

**Network Security:**
- HTTP expone todo en texto plano — credenciales, cookies, tokens
- HTTPS es la defensa fundamental contra MITM
- ARP Spoofing es pasivo desde la perspectiva de la víctima — difícil de detectar sin herramientas específicas
- Cualquier control de seguridad que dependa de valores modificables por el cliente es inseguro (Referer, headers HTTP)
