#!/bin/bash
#
# cleanup-hosts.sh
# Cleans up all Docker resources on remote test hosts
#
# Usage: ./cleanup-hosts.sh [host1|host2|host3|all]
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
NC='\033[0m' # No Color

cleanup_host() {
    local host_name=$1
    local host_ssh=$2

    echo -e "${YELLOW}Cleaning up ${host_name} (${host_ssh})...${NC}"

    # Check if host is reachable
    if ! ssh -o ConnectTimeout=5 "${host_ssh}" "echo 'Connected'" > /dev/null 2>&1; then
        echo -e "${RED}✗ Cannot connect to ${host_name}${NC}"
        return 1
    fi

    # Get container count
    local container_count=$(ssh "${host_ssh}" "docker ps -aq | wc -l" 2>/dev/null || echo "0")

    if [ "$container_count" -eq 0 ]; then
        echo -e "${GREEN}  No containers to clean${NC}"
    else
        echo "  Stopping and removing ${container_count} containers..."
        ssh "${host_ssh}" "docker stop \$(docker ps -aq) 2>&1 && docker rm \$(docker ps -aq) 2>&1" > /dev/null
        echo -e "${GREEN}  ✓ Containers removed${NC}"
    fi

    # Clean up networks
    echo "  Pruning networks..."
    local network_output=$(ssh "${host_ssh}" "docker network prune -f 2>&1")
    if echo "$network_output" | grep -q "Deleted Networks:"; then
        echo -e "${GREEN}  ✓ Networks pruned${NC}"
    else
        echo -e "${GREEN}  No networks to prune${NC}"
    fi

    # Clean up volumes
    echo "  Pruning volumes..."
    local volume_output=$(ssh "${host_ssh}" "docker volume prune -f 2>&1")
    if echo "$volume_output" | grep -q "Total reclaimed space:"; then
        local reclaimed=$(echo "$volume_output" | grep "Total reclaimed space:" | awk '{print $4, $5}')
        echo -e "${GREEN}  ✓ Volumes pruned (reclaimed: ${reclaimed})${NC}"
    else
        echo -e "${GREEN}  No volumes to prune${NC}"
    fi

    # Verify cleanup
    echo "  Verifying cleanup..."
    local remaining=$(ssh "${host_ssh}" "docker ps -aq | wc -l")
    if [ "$remaining" -eq 0 ]; then
        echo -e "${GREEN}✓ ${host_name} cleanup complete${NC}\n"
        return 0
    else
        echo -e "${RED}✗ ${host_name} still has ${remaining} containers${NC}\n"
        return 1
    fi
}

# Parse arguments
TARGET="${1:-all}"

case "$TARGET" in
    host1)
        cleanup_host "host1" "root@192.168.0.96"
        ;;
    host2)
        cleanup_host "host2" "root@192.168.0.98"
        ;;
    host3)
        cleanup_host "host3" "root@192.168.0.99"
        ;;
    all)
        echo -e "${YELLOW}=== Cleaning up all hosts ===${NC}\n"
        failed=0
        for host_config in "${HOSTS[@]}"; do
            IFS=':' read -r host_name host_ssh <<< "$host_config"
            cleanup_host "$host_name" "$host_ssh" || ((failed++))
        done

        if [ $failed -eq 0 ]; then
            echo -e "${GREEN}=== All hosts cleaned successfully ===${NC}"
            exit 0
        else
            echo -e "${RED}=== ${failed} host(s) failed to clean ===${NC}"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 [host1|host2|host3|all]"
        echo ""
        echo "Options:"
        echo "  host1  - Clean only host1 (192.168.0.96)"
        echo "  host2  - Clean only host2 (192.168.0.98)"
        echo "  host3  - Clean only host3 (192.168.0.99)"
        echo "  all    - Clean all hosts (default)"
        exit 1
        ;;
esac
