# Contributing Guide

Thank you for your interest in contributing to Caddy Agent! Here's how to help.

## Getting Started

### Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/caddy-agent.git
cd caddy-agent

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install docker requests

# Run locally
export AGENT_MODE=standalone
export AGENT_ID=dev-machine
python caddy-agent-watch.py
```

### Project Structure

```
caddy-agent/
├── caddy-agent-watch.py      # Main agent logic
├── Dockerfile                 # Docker image
├── Caddyfile                 # Minimal Caddy config
├── docker-compose-prod-*.yml # Production configs
├── README.md                 # Main documentation
├── DEPLOYMENT.md             # Deployment guide
├── CONFIGURATION.md          # Config reference
├── TROUBLESHOOTING.md        # Troubleshooting
├── QUICK-START.md            # Quick start
├── CONTRIBUTING.md           # This file
├── 05-TESTING-PLAN.md        # Test suite
└── 06-TEST-RUN-*.md          # Test results
```

## Ways to Contribute

### 1. Bug Reports

Found a bug? Create an issue with:

- **Title**: Clear, concise description
- **Reproduction**: Steps to reproduce
- **Environment**: OS, Docker version, Python version
- **Error**: Full error message/logs
- **Expected**: What should happen

Example:
```
Title: Routes from host2 disappear when host3 syncs

Reproduction:
1. Deploy 3 hosts (server + 2 agents)
2. Add container on host2
3. Wait 5 seconds
4. Add container on host3
5. Check routes on host1 - host2 route is gone!

Environment: Ubuntu 20.04, Docker 20.10, Python 3.9
Error: Routes only show host3, host2 missing

Expected: All 2 routes should be present
```

### 2. Feature Requests

Have an idea? Open an issue with:

- **Title**: Feature name
- **Problem**: What problem does it solve?
- **Solution**: Your proposed solution
- **Alternatives**: Other approaches considered
- **Use Case**: Real-world example

Example:
```
Title: Support persistent configuration storage

Problem:
Routes are lost when Caddy restarts because config isn't persisted

Solution:
Implement optional config backup to disk/database after each update.
On Caddy startup, agents check for persisted config and restore if needed.

Use Case:
Production deployments where service restart shouldn't cause downtime
```

### 3. Code Contributions

#### Pull Request Process

1. **Fork** the repository
2. **Create branch** for your feature/fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Implement** with tests
4. **Run tests** to verify:
   ```bash
   ./test-all.sh
   ```

5. **Commit** with meaningful messages:
   ```bash
   git commit -m "feat: add heartbeat mechanism for stale route cleanup"
   git commit -m "fix: preserve routes during concurrent agent updates"
   ```

6. **Push** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create Pull Request** with description
8. **Address feedback** from maintainers

#### Commit Message Format

Use conventional commits:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `refactor`: Code refactoring
- `docs`: Documentation
- `test`: Test additions/changes
- `chore`: Build/dependency changes

**Scopes** (optional):
- `agent`: Core agent logic
- `config`: Configuration handling
- `routes`: Route generation/merging
- `docker`: Docker integration
- `caddy`: Caddy Admin API
- `tests`: Test suite
- `docs`: Documentation

**Examples**:
```
feat(routes): add TTL mechanism for stale route cleanup

fix(agent): prevent route overwriting in concurrent updates

refactor(config): simplify label parsing logic

test(routes): add unit tests for merge_routes function

docs: add troubleshooting section to README
```

### 4. Documentation

Help improve documentation:

- **Fix typos** in README, guides, or comments
- **Add examples** for common use cases
- **Clarify sections** that are confusing
- **Add translations** for other languages
- **Create tutorials** for specific scenarios

### 5. Testing

Improve the test suite:

- **Add test cases** for edge cases
- **Create scripts** for automated testing
- **Document test procedures**
- **Report test failures** with reproduction steps

## Code Style

### Python Style Guide

Follow [PEP 8](https://pep8.org/):

```python
# Good
def get_caddy_routes():
    """Get routes from Docker containers based on labels."""
    routes = []
    for container in client.containers.list():
        labels = container.attrs['Config']['Labels']
        if not labels:
            continue
    return routes

# Bad
def GetCaddyRoutes( ):
    routes=[]
    for c in client.containers.list():
        l=c.attrs['Config']['Labels']
        if not l:continue
    return routes
```

### Naming Conventions

```python
# Classes: PascalCase
class DockerClient:
    pass

# Functions: snake_case
def get_caddy_routes():
    pass

# Constants: SCREAMING_SNAKE_CASE
DOCKER_SOCKET = '/var/run/docker.sock'

# Private: leading underscore
def _helper_function():
    pass
```

### Comments

```python
# Good: explain WHY, not WHAT
def merge_routes(local_routes, new_routes):
    """Merge local and new routes, using AGENT_ID for conflict prevention."""
    # Agent ID prefixing prevents routes from different agents from
    # overwriting each other during concurrent updates
    merged = {}
    for route_id, route in local_dict.items():
        agent_id = get_agent_id_from_route(route)
        # Keep routes from other agents
        if agent_id != AGENT_ID:
            merged[route_id] = route

# Bad: explains WHAT (code is already clear)
def merge_routes(local_routes, new_routes):
    merged = {}  # Loop through routes
    for route_id, route in local_dict.items():  # Get route ID
        agent_id = get_agent_id_from_route(route)  # Extract agent ID
        if agent_id != AGENT_ID:  # Check if from other agent
            merged[route_id] = route  # Add to merged dict
```

## Testing

### Run Tests

```bash
# All tests
bash ./test-all.sh

# Specific category
bash ./test-all.sh routing
bash ./test-all.sh agents
```

### Write Tests

Add test cases to `05-TESTING-PLAN.md` or create new test files:

```bash
# Test script structure
#!/bin/bash
set -e

TEST_NAME="My Feature Test"
echo "Testing: $TEST_NAME"

# Setup
docker run -d --name test-container ...

# Test
result=$(curl http://localhost/test)
if [ "$result" = "expected" ]; then
  echo "✅ PASS"
else
  echo "❌ FAIL: got $result"
  exit 1
fi

# Cleanup
docker rm -f test-container
```

### Test Coverage

Aim for:
- **Happy path**: Normal operation
- **Edge cases**: Empty containers, invalid labels, etc.
- **Error cases**: Network failures, permission issues
- **Performance**: Multiple containers, rapid updates
- **Integration**: Multi-host coordination

## Release Process

### Version Format

Use [Semantic Versioning](https://semver.org/):

```
MAJOR.MINOR.PATCH
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes
```

Examples:
- `1.0.0` - Initial release
- `1.1.0` - Added heartbeat feature
- `1.1.1` - Fixed route merging bug
- `2.0.0` - Removed standalone mode

### Release Checklist

1. Update version in:
   - `Dockerfile` (Docker image tag)
   - `docker-compose-*.yml` files
   - `README.md` (badge, if any)

2. Update `CHANGELOG.md`:
   ```markdown
   ## [1.1.0] - 2025-11-20

   ### Added
   - Heartbeat mechanism for stale route cleanup
   - Prometheus metrics export

   ### Fixed
   - Route overwriting during concurrent updates
   - Memory leak in event listener

   ### Changed
   - Admin API requires token authentication
   ```

3. Run full test suite:
   ```bash
   bash ./test-all.sh
   ```

4. Create GitHub release:
   - Tag: `v1.1.0`
   - Release notes: Copy from CHANGELOG.md
   - Attach: Compressed Docker image tar

5. Push to registries:
   ```bash
   docker tag caddy-agent:1.1.0 yourusername/caddy-agent:1.1.0
   docker tag caddy-agent:1.1.0 yourusername/caddy-agent:latest
   docker push yourusername/caddy-agent:1.1.0
   docker push yourusername/caddy-agent:latest
   ```

## Communication

### Issue Discussion

- **Be respectful** - Everyone is volunteering their time
- **Stay on topic** - Keep discussions relevant to the issue
- **Provide context** - Reference related issues/PRs
- **Use reactions** - 👍 for agreement instead of "me too" comments

### Pull Request Review

When reviewing:

- **Test locally** - Does it work?
- **Check code quality** - Does it follow style guide?
- **Verify tests** - Are there tests? Do they pass?
- **Review design** - Is the approach sound?
- **Be constructive** - Suggest improvements, not criticism

When submitting:

- **Respond to feedback** - Address comments promptly
- **Keep it focused** - One feature per PR
- **Add tests** - New features need test coverage
- **Update docs** - Document new behavior

## Resources

### Documentation

- [Python docker library](https://docker-py.readthedocs.io/)
- [Caddy Admin API](https://caddyserver.com/docs/json/)
- [Docker Event API](https://docs.docker.com/engine/api/v1.41/#operation/SystemEventsStream)

### Architecture

- [ARCHITECTURE.md](ARCHITECTURE.md) - System design
- [03-README-MULTIHOST.md](03-README-MULTIHOST.md) - Implementation details

### Development

- Branch: `main` - Stable releases
- Branch: `develop` - Development (if using git-flow)

## Community

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - General questions and discussions
- **Pull Requests** - Code contributions

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all.

### Our Standards

Examples of behavior that contributes:
- Using welcoming and inclusive language
- Being respectful of differing opinions
- Accepting constructive criticism gracefully
- Focusing on what is best for the community

Unacceptable behavior:
- Harassment or discrimination
- Insulting/derogatory comments
- Personal attacks
- Publishing private information

### Enforcement

Violations may be reported to maintainers and will be addressed promptly.

---

## Getting Help

- **Questions?** Open a GitHub Discussion
- **Found a bug?** Create an Issue with `bug` label
- **Have an idea?** Create an Issue with `enhancement` label
- **Need guidance?** Comment on an issue and ask

## Acknowledgments

Thanks to all contributors! You make this project better.

---

**Happy Contributing!** 🚀

