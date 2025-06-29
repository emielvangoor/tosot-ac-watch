# Tosot AC Watch

Control and monitor Tosot/Gree air conditioners via WiFi with automatic error recovery.

## Features

- 🔍 **Device Discovery** - Automatically find AC units on your network
- 📊 **Status Monitoring** - Check power state, temperature, modes, and more
- 🎮 **Full Control** - Turn on/off, set temperature, view all parameters
- 🔧 **Auto Recovery** - Automatically detect and recover from AC errors
- 📝 **Error Logging** - Track all errors and recovery attempts
- 🐳 **Docker Support** - Run easily in containers

## Quick Start

### Using Docker

```bash
docker run -d \
  --name ac-watch \
  --network host \
  -v ac-data:/app/data \
  tesseractpro/ac-watch:latest
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/emielvangoor/tosot-ac-watch.git
cd tosot-ac-watch

# Build the control tool
go build -o tosot-ac-control main.go

# Build the watch daemon
cd watch && go build -o ../ac-watch main.go
```

## Usage

### Control Tool

```bash
# Scan for devices
./tosot-ac-control scan

# Control specific device
./tosot-ac-control status gang
./tosot-ac-control start gang
./tosot-ac-control stop gang
./tosot-ac-control temp gang 22
```

### Watch Daemon

The watch daemon monitors the AC for errors and automatically recovers:

```bash
# Run the watch daemon
./ac-watch

# Run in background
nohup ./ac-watch > ac-watch.log 2>&1 &
```

## Configuration

Edit `main.go` to configure your devices:

```go
devices := map[string]struct {
    MAC string
    IP  string
}{
    "gang":      {"f4911ef6d9bf", "192.168.1.223"},
    "woonkamer": {"f4911ef82651", "192.168.1.222"},
}
```

## Error Recovery

The watch daemon:
- Monitors AC status every minute
- Detects error codes automatically
- Stops and restarts the AC on errors
- Restores previous temperature settings
- Implements rate limiting (max 2 restarts per 5 minutes)

## Docker Hub

Pre-built images available at: [tesseractpro/ac-watch](https://hub.docker.com/r/tesseractpro/ac-watch)

```bash
# Latest version
docker pull tesseractpro/ac-watch:latest

# Specific version
docker pull tesseractpro/ac-watch:1
```

## Protocol

This project uses the Gree protocol which is supported by:
- Tosot
- Gree
- Sinclair
- Many other brands using EWPE Smart app

## License

MIT License - See LICENSE file for details