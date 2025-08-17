# Use Ubuntu as base image for better compatibility
FROM ubuntu:22.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install required dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    libpcap-dev \
    libpthread-stubs0-dev \
    net-tools \
    iputils-ping \
    nmap \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Create a working directory
WORKDIR /app

# Copy the project files
COPY . .

# Build the project
RUN make clean && make

# Create a non-root user for security
RUN useradd -m -s /bin/bash scanner

# Set appropriate permissions
RUN chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Default command
CMD ["./ft_nmap", "--help"]
