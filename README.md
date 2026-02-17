# Suricata Dashboard

Dashboard en tiempo real para monitoreo de Suricata IDS/IPS.

## Características

- Métricas en tiempo real (WebSocket)
- Gráficos de alertas por severity y protocolo
- Timeline de actividad (24h)
- Top firmas detectadas
- Top IPs fuente y destino
- Tabla de alertas recientes con búsqueda
- Notificaciones toast para nuevas alertas

## Requisitos

- Node.js 18+
- npm

## Instalación

```bash
cd suricata-dashboard
npm install
```

## Configuración

### Variables de entorno (opcional)

```bash
export SURICATA_LOG=/ruta/a/eve.json  # Default: logs/eve.json
export PORT=3000                       # Default: 3000
```

## Ejecución

```bash
npm start
```

El dashboard estará disponible en: http://localhost:3000

## Modo desarrollo

```bash
npm run dev
```

## Formato de logs

El dashboard procesa logs en formato JSON de Suricata (eve.json):

```json
{
  "timestamp": "2024-01-15T10:30:45.123456",
  "event_type": "alert",
  "src_ip": "192.168.1.100",
  "src_port": 45678,
  "dest_ip": "10.0.0.50",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "signature_id": 2002919,
    "signature": "ET SCAN Potential SSH Scan OUTBOUND",
    "severity": 2
  }
}
```

### Campos soportados

| Campo | Descripción |
|-------|-------------|
| timestamp | Fecha y hora del evento |
| event_type | Tipo de evento (alert, etc.) |
| src_ip | IP fuente |
| src_port | Puerto fuente |
| dest_ip | IP destino |
| dest_port | Puerto destino |
| proto | Protocolo (TCP, UDP, ICMP) |
| alert.severity | 1=Critical, 2=High, 3=Medium, 4=Low |
| alert.signature | Firma de la regla |

## API REST

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| /api/metrics | GET | Obtener métricas actuales |
| /api/alerts | GET | Obtener alertas recientes (?limit=50) |
| /api/reset | POST | Reiniciar métricas |

## Configuración con Suricata real

Para conectar con Suricata real, configura en suricata.yaml:

```yaml
- interface: eth0
  # ... otras opciones

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - stats
```

Y establece la variable de entorno:

```bash
export SURICATA_LOG=/var/log/suricata/eve.json
```

## Screenshots

![Dashboard](docs/screenshot.png)

## Licencia

MIT
