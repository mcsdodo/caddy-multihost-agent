#!/bin/bash
#
# deploy-hosts.sh
# Deploys Caddy multi-host agent system to test hosts
#
# Usage: ./deploy-hosts.sh [host1|host2|host3|all] [--build] [--no-start]
#

set -e

# Host configurations
HOSTS=(
    "host1:root@192.168.0.96"
    "host2:root@192.168.0.98"
    "host3:root@192.168.0.99"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Options
BUILD_IMAGES=false
START_CONTAINERS=true

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

build_images() {
    echo -e "${BLUE}=== Building Docker images ===${NC}\n"

    # Build caddy-docker-proxy
    echo -e "${YELLOW}Building caddy-docker-proxy...${NC}"
    docker build -f "${SCRIPT_DIR}/Dockerfile.Caddy" -t caddy-docker-proxy:latest "${SCRIPT_DIR}"
    docker save caddy-docker-proxy:latest | gzip > "${SCRIPT_DIR}/caddy-docker-proxy.tar.gz"
    echo -e "${GREEN}✓ caddy-docker-proxy built${NC}\n"

    # Build caddy-agent
    echo -e "${YELLOW}Building caddy-agent...${NC}"
    docker build -t caddy-agent:latest "${SCRIPT_DIR}"
    docker save caddy-agent:latest | gzip > "${SCRIPT_DIR}/caddy-agent.tar.gz"
    echo -e "${GREEN}✓ caddy-agent built${NC}\n"
}

deploy_host1() {
    local host_ssh="root@192.168.0.96"
    echo -e "${YELLOW}Deploying to host1 (${host_ssh}) - Server...${NC}"

    # Check connectivity
    if ! ssh -o ConnectTimeout=5 "${host_ssh}" "echo 'Connected'" > /dev/null 2>&1; then
        echo -e "${RED}✗ Cannot connect to host1${NC}"
        return 1
    fi

    # Check if image exists
    if [ ! -f "${SCRIPT_DIR}/caddy-docker-proxy.tar.gz" ]; then
        echo -e "${RED}✗ caddy-docker-proxy.tar.gz not found. Run with --build first.${NC}"
        return 1
    fi

    # Create directory
    ssh "${host_ssh}" "mkdir -p /root/caddy-multihost"

    # Copy files
    echo "  Copying files..."
    scp -q "${SCRIPT_DIR}/caddy-docker-proxy.tar.gz" "${host_ssh}:/root/caddy-multihost/"
    scp -q "${SCRIPT_DIR}/docker-compose-prod-server.yml" "${host_ssh}:/root/caddy-multihost/"
    scp -q "${SCRIPT_DIR}/Dockerfile.Caddy" "${host_ssh}:/root/caddy-multihost/"
    echo -e "${GREEN}  ✓ Files copied${NC}"

    # Load image
    echo "  Loading Docker image..."
    ssh "${host_ssh}" "cd /root/caddy-multihost && gunzip -c caddy-docker-proxy.tar.gz | docker load" > /dev/null
    echo -e "${GREEN}  ✓ Image loaded${NC}"

    # Start containers
    if [ "$START_CONTAINERS" = true ]; then
        echo "  Starting containers..."
        ssh "${host_ssh}" "cd /root/caddy-multihost && docker compose -f docker-compose-prod-server.yml up -d" 2>&1 | grep -v "^time=" || true
        echo -e "${GREEN}  ✓ Containers started${NC}"
    else
        echo -e "${YELLOW}  Skipping container start (--no-start)${NC}"
    fi

    echo -e "${GREEN}✓ host1 deployed${NC}\n"
}

deploy_host2() {
    local host_ssh="root@192.168.0.98"
    echo -e "${YELLOW}Deploying to host2 (${host_ssh}) - Agent...${NC}"

    # Check connectivity
    if ! ssh -o ConnectTimeout=5 "${host_ssh}" "echo 'Connected'" > /dev/null 2>&1; then
        echo -e "${RED}✗ Cannot connect to host2${NC}"
        return 1
    fi

    # Check if image exists
    if [ ! -f "${SCRIPT_DIR}/caddy-agent.tar.gz" ]; then
        echo -e "${RED}✗ caddy-agent.tar.gz not found. Run with --build first.${NC}"
        return 1
    fi

    # Create directory
    ssh "${host_ssh}" "mkdir -p /root/caddy-multihost"

    # Copy files
    echo "  Copying files..."
    scp -q "${SCRIPT_DIR}/caddy-agent.tar.gz" "${host_ssh}:/root/caddy-multihost/"
    scp -q "${SCRIPT_DIR}/docker-compose-prod-agent2.yml" "${host_ssh}:/root/caddy-multihost/"
    echo -e "${GREEN}  ✓ Files copied${NC}"

    # Load image
    echo "  Loading Docker image..."
    ssh "${host_ssh}" "cd /root/caddy-multihost && gunzip -c caddy-agent.tar.gz | docker load" > /dev/null
    echo -e "${GREEN}  ✓ Image loaded${NC}"

    # Start containers
    if [ "$START_CONTAINERS" = true ]; then
        echo "  Starting containers..."
        ssh "${host_ssh}" "cd /root/caddy-multihost && docker compose -f docker-compose-prod-agent2.yml up -d" 2>&1 | grep -v "^time=" || true
        echo -e "${GREEN}  ✓ Containers started${NC}"
    else
        echo -e "${YELLOW}  Skipping container start (--no-start)${NC}"
    fi

    echo -e "${GREEN}✓ host2 deployed${NC}\n"
}

deploy_host3() {
    local host_ssh="root@192.168.0.99"
    echo -e "${YELLOW}Deploying to host3 (${host_ssh}) - Agent...${NC}"

    # Check connectivity
    if ! ssh -o ConnectTimeout=5 "${host_ssh}" "echo 'Connected'" > /dev/null 2>&1; then
        echo -e "${RED}✗ Cannot connect to host3${NC}"
        return 1
    fi

    # Check if image exists
    if [ ! -f "${SCRIPT_DIR}/caddy-agent.tar.gz" ]; then
        echo -e "${RED}✗ caddy-agent.tar.gz not found. Run with --build first.${NC}"
        return 1
    fi

    # Create directory
    ssh "${host_ssh}" "mkdir -p /root/caddy-multihost"

    # Copy files
    echo "  Copying files..."
    scp -q "${SCRIPT_DIR}/caddy-agent.tar.gz" "${host_ssh}:/root/caddy-multihost/"
    scp -q "${SCRIPT_DIR}/docker-compose-prod-agent3.yml" "${host_ssh}:/root/caddy-multihost/"
    echo -e "${GREEN}  ✓ Files copied${NC}"

    # Load image
    echo "  Loading Docker image..."
    ssh "${host_ssh}" "cd /root/caddy-multihost && gunzip -c caddy-agent.tar.gz | docker load" > /dev/null
    echo -e "${GREEN}  ✓ Image loaded${NC}"

    # Start containers
    if [ "$START_CONTAINERS" = true ]; then
        echo "  Starting containers..."
        ssh "${host_ssh}" "cd /root/caddy-multihost && docker compose -f docker-compose-prod-agent3.yml up -d" 2>&1 | grep -v "^time=" || true
        echo -e "${GREEN}  ✓ Containers started${NC}"
    else
        echo -e "${YELLOW}  Skipping container start (--no-start)${NC}"
    fi

    echo -e "${GREEN}✓ host3 deployed${NC}\n"
}

# Parse arguments
TARGET="all"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --build|-b)
            BUILD_IMAGES=true
            shift
            ;;
        --no-start)
            START_CONTAINERS=false
            shift
            ;;
        host1|host2|host3|all)
            TARGET="$1"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [host1|host2|host3|all] [--build] [--no-start]"
            echo ""
            echo "Targets:"
            echo "  host1      - Deploy only host1/server (192.168.0.96)"
            echo "  host2      - Deploy only host2/agent (192.168.0.98)"
            echo "  host3      - Deploy only host3/agent (192.168.0.99)"
            echo "  all        - Deploy all hosts (default)"
            echo ""
            echo "Options:"
            echo "  --build    - Build Docker images before deploying"
            echo "  --no-start - Copy files but don't start containers"
            echo ""
            echo "Examples:"
            echo "  $0 --build           # Build and deploy all"
            echo "  $0 host1 --build     # Build and deploy host1 only"
            echo "  $0 all --no-start    # Deploy without starting"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}=== Caddy Multi-Host Deployment ===${NC}\n"

# Build if requested
if [ "$BUILD_IMAGES" = true ]; then
    build_images
fi

# Deploy based on target
case "$TARGET" in
    host1)
        deploy_host1
        ;;
    host2)
        deploy_host2
        ;;
    host3)
        deploy_host3
        ;;
    all)
        failed=0
        deploy_host1 || ((failed++))
        deploy_host2 || ((failed++))
        deploy_host3 || ((failed++))

        if [ $failed -eq 0 ]; then
            echo -e "${GREEN}=== All hosts deployed successfully ===${NC}"
        else
            echo -e "${RED}=== ${failed} host(s) failed to deploy ===${NC}"
            exit 1
        fi
        ;;
esac

# Show status
if [ "$START_CONTAINERS" = true ]; then
    echo ""
    echo -e "${BLUE}Run tests with:${NC}"
    echo "  python test_all.py --integration"
fi
