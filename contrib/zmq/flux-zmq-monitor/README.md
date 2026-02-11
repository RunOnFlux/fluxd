# Flux ZMQ Monitor

Real-time monitoring tool for FluxD ZMQ events.

## Installation

```bash
# Install to /opt
sudo mkdir -p /opt/flux-zmq-monitor
sudo cp -r . /opt/flux-zmq-monitor/
cd /opt/flux-zmq-monitor

# Install dependencies
sudo uv sync

# Install systemd service
sudo cp ../flux-zmq-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable flux-zmq-monitor
sudo systemctl start flux-zmq-monitor
```

## Usage

```bash
# Run directly
flux-zmq-monitor --help

# Run with custom endpoint
flux-zmq-monitor --endpoint tcp://127.0.0.1:16123

# Run with log file
flux-zmq-monitor --log-file /var/log/flux-zmq-monitor/events.log
```

## Events Monitored

- `hashblockheight` - New block notifications
- `chainreorg` - Chain reorganization events
- `fluxnodelistdelta` - FluxNode state changes

## See Also

- Main documentation: `../README.md`
- Systemd service: `flux-zmq-monitor.service`
- Validator tool: `../flux-state-validator/`
