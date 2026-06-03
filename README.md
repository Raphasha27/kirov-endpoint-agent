# Kirov Endpoint Agent

A lightweight Go agent that runs on endpoints (servers, workstations) to monitor for suspicious activity, collect system health, and report to the Kirov Security Core.

## Architecture

```
┌─────────────────────────────────────────────┐
│              Kirov Endpoint Agent            │
│                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ Process  │  │  Login   │  │   File   │  │
│  │ Monitor  │  │ Monitor  │  │ Integrity│  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       │             │             │         │
│  ┌────▼─────────────▼─────────────▼─────┐  │
│  │            Alerter Queue             │  │
│  └────────────────┬────────────────────┘  │
│                   │                       │
│  ┌────────────────▼────────────────────┐  │
│  │         HTTP Reporter              │  │
│  │  (retry, backoff, auth, buffer)    │  │
│  └────────────────┬────────────────────┘  │
│                   │                       │
│  ┌────────────────▼────────────────────┐  │
│  │       Kirov Security Core           │  │
│  │   POST /api/v1/agents/*             │  │
│  └─────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

## Quick Start

```bash
go build -o agent ./cmd/agent
./agent --config config.yaml
```

### Docker

```bash
docker build -t kirov-endpoint-agent .
docker run -d --name kirov-agent \
  -v /etc/kirov/agent/config.yaml:/etc/kirov/agent/config.yaml \
  -v /var/log:/var/log:ro \
  kirov-endpoint-agent
```

## Configuration

| Environment Variable    | Config Key          | Default                 | Description                  |
|------------------------|---------------------|-------------------------|------------------------------|
| KIROV_AGENT_ID         | agent_id            | auto-generated UUID     | Unique agent identifier      |
| KIROV_CORE_URL         | core_url            | http://localhost:8000   | Kirov Core API base URL      |
| KIROV_HEARTBEAT_INTERVAL | heartbeat_interval | 60                      | Heartbeat interval in seconds |
| KIROV_LOG_LEVEL        | log_level           | info                    | Log level (debug/info/warn/error) |
| KIROV_WATCH_DIRS       | watch_dirs          | /etc,/usr/local/bin,/opt | Comma-separated directories for file integrity |
| KIROV_ALLOWED_PROCESSES | allowed_processes | systemd,sshd,nginx,...  | Comma-separated process whitelist |
| KIROV_BLACKLIST_PROCESSES | blacklist_processes | mimikatz,nc,...     | Comma-separated process blacklist |

## Monitoring Capabilities

| Collector       | Capability                        | Interval | Platform Support        |
|-----------------|-----------------------------------|----------|-------------------------|
| Process Monitor | New/unknown process detection     | 30s      | Linux, macOS, Windows   |
| Process Monitor | Suspicious process (whitelist)    | 30s      | Linux, macOS, Windows   |
| Process Monitor | Unsigned binary detection         | 30s      | Windows                 |
| Login Monitor   | Failed/successful login events    | 15s      | Linux (auth.log), macOS (system.log), Windows (EventLog) |
| Login Monitor   | Brute force detection (>5 fails) | 1min     | All                     |
| File Integrity  | SHA-256 hash comparison           | 5min     | All (directory walk)    |
| File Integrity  | Add/modify/delete detection       | 5min     | All                     |
| System Health   | CPU, memory, disk, network        | 60s      | All (gopsutil)          |
| System Health   | Load averages                     | 60s      | Linux, macOS            |

## Security Considerations

- Agent runs as non-root user (`kirov`, UID 1000)
- Read-only root filesystem in Docker
- All outbound communication uses JWT bearer tokens
- Alert buffer limits prevent memory exhaustion (max 1000)
- Exponential backoff retry prevents thundering herd
- Config file should be mounted read-only in production
- On Windows, unsigned binaries from non-standard paths are flagged
- Logging uses structured JSON for SIEM integration

## Integration with Kirov Core

The agent communicates with the Kirov Security Core via REST API:

| Endpoint                              | Method | Purpose            |
|---------------------------------------|--------|--------------------|
| `/api/v1/agents/register`            | POST   | Agent registration |
| `/api/v1/agents/{id}/heartbeat`      | POST   | Heartbeat signal   |
| `/api/v1/agents/{id}/health`         | POST   | System metrics     |
| `/api/v1/agents/{id}/alerts`         | POST   | Event alerts       |
| `/api/v1/agents/{id}/batch`          | POST   | Batched events     |

On startup the agent registers itself, receives a JWT token, and begins sending heartbeats every 60 seconds. Alerts are queued locally and sent asynchronously; if the core is unreachable, up to 1000 alerts are buffered in memory.

## License

Proprietary. Kirov Security.
