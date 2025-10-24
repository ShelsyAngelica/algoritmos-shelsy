/**
* Analiza logs de acceso a una API para detectar patrones sospechosos
* y posibles ataques de fuerza bruta o spam
*
* @param {Array<Object>} logs - Array de logs de acceso
* @param {Object} config - Configuración de detección
* @returns {Object} Reporte de actividad sospechosa
*
* Estructura de log:

    * {
*        ip: "192.168.1.1",
*        endpoint: "/api/login",
*        timestamp: 1697123456789,
*        status: 401,
*        user_agent: "Mozilla/5.0...",
*        response_time: 150
    * }
*
*/

// Config ejemplo:
    let configs = {

        max_requests_per_minute: 60,
        max_failed_logins: 5,
        suspicious_endpoints: ["/api/login", "/api/admin"],
        time_window: 300000 // 5 minutos en ms
    }

    let logsdata = [
        {
          "ip": "203.0.113.10",
          "endpoint": "/api/login",
          "timestamp": 1740112800000,
          "status": 401,
          "user_agent": "python-requests/2.31.0",
          "response_time": 85
        },
        {
            "ip": "203.0.113.10",
            "endpoint": "/api/login",
            "timestamp": 1740112802000,
            "status": 401,
            "user_agent": "python-requests/2.31.0",
            "response_time": 85
        },
        {
            "ip": "203.0.113.10",
            "endpoint": "/api/login",
            "timestamp": 1740112803000,
            "status": 401,
            "user_agent": "python-requests/2.31.0",
            "response_time": 85
        },
        {
            "ip": "203.0.113.10",
            "endpoint": "/api/login",
            "timestamp": 1740112804000,
            "status": 401,
            "user_agent": "python-requests/2.31.0",
            "response_time": 85
        },
        {
          "ip": "203.0.113.10",
          "endpoint": "/api/login",
          "timestamp": 1740112805000,
          "status": 401,
          "user_agent": "python-requests/2.31.0",
          "response_time": 78
        },
        {
          "ip": "203.0.113.10",
          "endpoint": "/api/login",
          "timestamp": 1740112802000,
          "status": 401,
          "user_agent": "python-requests/2.31.0",
          "response_time": 82
        },
        {
          "ip": "198.51.100.42",
          "endpoint": "/api/login",
          "timestamp": 1740112815000,
          "status": 200,
          "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
          "response_time": 140
        },
        {
          "ip": "198.51.100.42",
          "endpoint": "/api/users",
          "timestamp": 1740112817000,
          "status": 200,
          "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
          "response_time": 110
        },
        {
          "ip": "192.0.2.77",
          "endpoint": "/api/login",
          "timestamp": 1740112820000,
          "status": 401,
          "user_agent": "curl/7.88.1",
          "response_time": 40
        },
        {
          "ip": "192.0.2.77",
          "endpoint": "/api/login",
          "timestamp": 1740112820500,
          "status": 401,
          "user_agent": "curl/7.88.1",
          "response_time": 35
        },
        {
          "ip": "192.0.2.77",
          "endpoint": "/api/login",
          "timestamp": 1740112821000,
          "status": 401,
          "user_agent": "curl/7.88.1",
          "response_time": 37
        },
        {
          "ip": "192.0.2.77",
          "endpoint": "/api/login",
          "timestamp": 1740112821500,
          "status": 401,
          "user_agent": "curl/7.88.1",
          "response_time": 36
        },
        {
          "ip": "150.172.4.9",
          "endpoint": "/api/password_reset",
          "timestamp": 1740112830000,
          "status": 429,
          "user_agent": "Go-http-client/1.1",
          "response_time": 20
        },
        {
          "ip": "150.172.4.9",
          "endpoint": "/api/password_reset",
          "timestamp": 1740112830500,
          "status": 429,
          "user_agent": "Go-http-client/1.1",
          "response_time": 18
        },
        {
          "ip": "66.102.8.35",
          "endpoint": "/api/register",
          "timestamp": 1740112845000,
          "status": 201,
          "user_agent": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/118.0.0.0 Mobile Safari/537.36",
          "response_time": 220
        },
        {
          "ip": "66.102.8.35",
          "endpoint": "/api/login",
          "timestamp": 1740112850000,
          "status": 401,
          "user_agent": "Unknown",
          "response_time": 300
        },
        {
          "ip": "45.55.200.200",
          "endpoint": "/api/products",
          "timestamp": 1740112860000,
          "status": 200,
          "user_agent": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
          "response_time": 95
        },
        {
          "ip": "45.55.200.200",
          "endpoint": "/api/login",
          "timestamp": 1740112861000,
          "status": 401,
          "user_agent": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
          "response_time": 90
        }
    ]
    
    let dangerousUA = ['python-requests', 'curl', 'Go-http-client', 'Unknown'];
    let total_eventos_sospechosos = 0;


    function detectarActividadSospechosa(logs, config) {
    // Tu implementación debe detectar:
    // 1. IPs con exceso de requests por minuto
    
    // 3. Acceso masivo a endpoints sensibles
    
        return {
            ips_sospechosas: [],
            ataques_fuerza_bruta: setLoginFail(logs, config),
            endpoints_bajo_ataque: [],
            anomalias_detectadas: setAnomalies(logs, config),
            total_eventos_sospechosos,
        };
    }

    function setLoginFail(logs, config){
        // 2. Patrones de fuerza bruta (múltiples fallos de login)
        let loginFail = [];

        logs.forEach((element) => {
                
            if ( element.endpoint == '/api/login'  && element.status == 401) {
                let ipFind = loginFail.find(e => e.ip == element.ip)

                if(ipFind){
                    ipFind.tries ++
                }else{
                    loginFail.push({ip:element.ip, tries: 1})
                }
            }                
        });

        let ataques_fuerza_bruta = loginFail.filter(el => el.tries >= config.max_failed_logins)
        total_eventos_sospechosos += ataques_fuerza_bruta.length
        return ataques_fuerza_bruta 

    }

    function setAnomalies(logs, config){

        // 4. Comportamiento anómalo por User-Agent
        let anomalias_detectadas = [];

        logs.forEach((element) => {

            dangerousUA.forEach(elementUA => {
                
                if ( element.user_agent.toLowerCase().includes(elementUA.toLowerCase())) {
                    total_eventos_sospechosos ++; 
                    anomalias_detectadas.push(element);
                }                
            });
        });

        return anomalias_detectadas
    }


    console.log(detectarActividadSospechosa(logsdata,configs));
    