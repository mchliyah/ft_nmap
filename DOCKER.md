# ft_nmap Docker Setup

This document explains how to use Docker with the ft_nmap project for cross-platform development.

## Prerequisites

- Docker Desktop (for macOS/Windows) or Docker Engine (for Linux)
- Docker Compose

## Quick Start

### 1. Build the Docker Image

```bash
./docker.sh build
```

### 2. Run Interactive Shell

```bash
./docker.sh run
```

### 3. Build and Run ft_nmap

```bash
# Inside the container, compile the project
make

# Run ft_nmap
./ft_nmap
```

## Available Commands

| Command             | Description                          |
| ------------------- | ------------------------------------ |
| `./docker.sh build` | Build the Docker image               |
| `./docker.sh run`   | Start interactive shell in container |
| `./docker.sh clean` | Clean up containers and images       |
| `./docker.sh help`  | Show help message                    |

## Development Workflow

### For Active Development

```bash
# Build and run interactive shell
./docker.sh build
./docker.sh run

# Inside the container:
make
./ft_nmap --help
```

### For Testing

```bash
# Build and test
./docker.sh build
./docker.sh run

# Inside the container:
make
./ft_nmap
```

## Docker Compose Services

### ft_nmap

- Main service for running the application
- Privileged mode for raw socket access
- Host network mode for better network access

## Troubleshooting

### Permission Issues

If you encounter permission issues, the container runs as a non-root user by default. For network scanning that requires raw sockets, the container uses privileged mode.

### Network Access

The container uses host network mode to ensure proper network access for scanning. This is necessary for raw socket operations.

### Rebuilding

If you make changes to the source code:

```bash
# Rebuild the image
./docker.sh build
```

## File Structure

```
ft_nmap/
├── Dockerfile              # Main Docker image definition
├── docker-compose.yml      # Docker Compose configuration
├── .dockerignore           # Files to ignore during build
├── docker.sh               # Helper script for Docker operations
└── DOCKER.md              # This documentation
```

## Cross-Platform Benefits

- **Consistent Environment**: Same Ubuntu 22.04 base across all platforms
- **Dependency Management**: All required libraries (libpcap, pthread) pre-installed
- **Build Reproducibility**: Same compiler and build tools everywhere
- **Easy Collaboration**: Share exact same development environment

## Security Notes

- Container runs with a non-root user (`scanner`) by default
- Privileged mode is used only when necessary for raw socket access
- Network scanning capabilities are contained within Docker's security model
