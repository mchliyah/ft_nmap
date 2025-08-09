#!/bin/bash

# ft_nmap Docker Setup Script
# This script helps you build and run the ft_nmap project in Docker

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
}

# Build the Docker image
build_image() {
    print_status "Building ft_nmap Docker image..."
    docker-compose build
    print_success "Docker image built successfully!"
}

# Run the container interactively
run_interactive() {
    print_status "Starting ft_nmap container in interactive mode..."
    docker-compose up -d ft_nmap
    docker-compose exec ft_nmap /bin/bash
}

# Run ft_nmap with arguments
run_scan() {
    if [ $# -eq 0 ]; then
        print_error "No arguments provided for scan"
        echo "Usage: $0 scan <ft_nmap_arguments>"
        exit 1
    fi
    
    print_status "Running ft_nmap with arguments: $*"
    docker-compose run --rm ft_nmap ./ft_nmap "$@"
}

# Clean up containers and images
cleanup() {
    print_status "Cleaning up Docker containers and images..."
    docker-compose down
    docker system prune -f
    print_success "Cleanup completed!"
}

# Development mode with auto-rebuild
dev_mode() {
    print_status "Starting development mode with auto-rebuild..."
    docker-compose up ft_nmap-dev
}

# Show help
show_help() {
    echo "ft_nmap Docker Helper Script"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  build          Build the Docker image"
    echo "  run            Start interactive shell in container"
    echo "  scan [args]    Run ft_nmap with specified arguments"
    echo "  dev            Start development mode with auto-rebuild"
    echo "  clean          Clean up containers and images"
    echo "  help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 build                          # Build the image"
    echo "  $0 run                            # Interactive shell"
    echo "  $0 scan --help                    # Show ft_nmap help"
    echo "  $0 scan -p 80,443 192.168.1.1    # Scan specific ports"
    echo "  $0 dev                            # Development mode"
    echo ""
}

# Main script logic
main() {
    check_docker
    
    case "${1:-help}" in
        build)
            build_image
            ;;
        run)
            run_interactive
            ;;
        scan)
            shift
            run_scan "$@"
            ;;
        dev)
            dev_mode
            ;;
        clean)
            cleanup
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
