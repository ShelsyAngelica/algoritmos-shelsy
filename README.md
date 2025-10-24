# Algoritmos - JavaScript

Implementaciones de algoritmos en JavaScript para estructuras de datos y análisis de seguridad.

## Contenido

1. LRU Cache
2. Detector de Actividad Sospechosa

---

## LRU Cache (algoritmo1.js)

Sistema de caché que elimina automáticamente los elementos menos usados cuando alcanza su capacidad máxima.

### Uso

```javascript
const cache = new LRUCache(3);

cache.put("a", 1);
cache.put("b", 2);
cache.put("c", 3);

cache.get("a"); // Marca "a" como reciente

cache.put("d", 4); // Elimina "b" (menos usado)
```

### Métodos

- `constructor(capacity)` - Inicializa el caché con capacidad máxima
- `get(key)` - Obtiene un valor y lo marca como reciente
- `put(key, value)` - Almacena un valor, elimina el menos usado si excede capacidad

---

## Detector de Actividad Sospechosa (algoritmo2.js)

Analiza logs de APIs para detectar ataques de fuerza bruta y comportamientos anómalos.

### Configuración

```javascript
{
    max_requests_per_minute: 60,
    max_failed_logins: 5,
    suspicious_endpoints: ["/api/login", "/api/admin"],
    time_window: 300000
}
```

### Estructura de Log

```javascript
{
    ip: "192.168.1.1",
    endpoint: "/api/login",
    timestamp: 1697123456789,
    status: 401,
    user_agent: "Mozilla/5.0...",
    response_time: 150
}
```

### Uso

```javascript
const resultado = detectarActividadSospechosa(logsdata, configs);
```

### Detecciones

- **Fuerza bruta**: Múltiples intentos fallidos de login
- **User-Agents sospechosos**: python-requests, curl, Go-http-client, Unknown

### Reporte

```javascript
{
    ips_sospechosas: [],
    ataques_fuerza_bruta: [{ ip: "203.0.113.10", tries: 6 }],
    endpoints_bajo_ataque: [],
    anomalias_detectadas: [...],
    total_eventos_sospechosos: 14
}
```

Shelsy - Octubre 2025
