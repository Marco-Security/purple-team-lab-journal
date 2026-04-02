# Día 8 — SNMP & DNS Enumeration

**MITRE ATT&CK:** T1046 — Network Service Discovery  
**Táctica:** Discovery (TA0007)

## 🔴 Red Team

### SNMP Enumeration
| Comando | Output |
|---|---|
| `snmpwalk -v2c -c public <target>` | Kernel, hostname, interfaces de red, IPs internas, tabla ARP |
| `nmap -sU -p 161 --script snmp-info,snmp-interfaces <target>` | Mapa completo de interfaces — enp0s3, docker0, bridges |

### Información expuesta via SNMP
- OS: `Linux Ubuntu-Victim 6.17.0-19-generic`
- Interfaces: `enp0s3 (192.168.1.96)`, `docker0 (172.17.0.1)`, `br-ae8856dc7adc (172.18.0.1)`
- MACs de todos los adaptadores de red
- IPs de otros hosts en la red: Kali (192.168.1.132), Gateway (192.168.1.254)
- Contenedores Docker internos visibles desde fuera

### DNS Zone Transfer
| Comando | Output |
|---|---|
| `dig axfr empresa.local @<target>` | 9 registros DNS — infraestructura completa expuesta |

### Infraestructura expuesta via Zone Transfer
| Subdominio | IP | Función |
|---|---|---|
| www.empresa.local | 192.168.1.96 | Servidor web |
| mail.empresa.local | 192.168.1.97 | Servidor de correo |
| vpn.empresa.local | 192.168.1.98 | Servidor VPN |
| db.empresa.local | 192.168.1.99 | Base de datos |
| admin.empresa.local | 192.168.1.100 | Panel de administración |

## 🔵 Blue Team

### Detección
| Comando | Qué detectó |
|---|---|
| `sudo tcpdump -i enp0s3 -n src host <attacker> and not port 22 -w dia08_capture.pcap` | SNMP GetRequest + DNS AXFR capturados |
| `sudo tcpdump -r dia08_capture.pcap -n \| head -20` | Puerto 161 UDP + `AXFR? empresa.local` visible en texto plano |

### Evidencia
- `GetRequest` de Kali al puerto 161 UDP — SNMP enumeration visible
- `AXFR? empresa.local` literal en la captura — Zone Transfer sin cifrado
- Ambos ataques completados en menos de 5 segundos

## 🟣 Purple Team Analysis

**Effectiveness Score: 75/100**

| 🔴 Red Team | 🔵 Blue Team |
|---|---|
| SNMP expuso arquitectura completa de red | SNMP GetRequest visible en tcpdump |
| Zone Transfer entregó mapa de infraestructura | `AXFR? empresa.local` visible en texto plano |
| Sin credenciales necesarias para ninguno | Sin alerta automática |

### Security Gaps
- SNMP con community string `public` por defecto — sin autenticación
- Zone Transfer permitido para cualquier IP — `allow-transfer { any; }`
- Ambos protocolos sin cifrado — tráfico legible en red local
- Sin IDS para detectar SNMP enumeration o Zone Transfer automáticamente

### Mitigación SNMP
- Cambiar community string `public` por uno complejo
- Migrar a SNMPv3 — autenticación + cifrado
- Restringir acceso SNMP solo a IPs de gestión

### Mitigación DNS
- Restringir Zone Transfer solo a servidores DNS secundarios autorizados
- En bind9: `allow-transfer { <ip_secundario>; };`

### Lección
SNMP mal configurado es el equivalente a darle a un atacante el plano completo de la red — interfaces, IPs, subredes y dispositivos conectados sin necesidad de escanear nada. El Zone Transfer es igual de peligroso — en segundos expone toda la infraestructura interna de una organización. Ambos son protocolos diseñados para administración interna que nunca deberían ser accesibles desde redes no confiables.

## 🟡 Wazuh
- Pendiente — análisis en próxima sesión
