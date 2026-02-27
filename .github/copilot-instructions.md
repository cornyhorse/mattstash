# MattStash - Copilot Agent Instructions

## Project Overview

**MattStash** is a KeePass-backed secrets accessor with a CLI and Python API. It provides credential management with versioning support, database URL construction, and S3 client creation capabilities.

## Mission Statement

Provide a simple, secure, and developer-friendly secrets management solution using KeePass databases as the backend storage, suitable for local development and small-team environments.

---

## Agent Constraints & File Management

### Allowed File Operations

Agents are **strictly limited** to creating or modifying only these files:

| File Type | Location | Purpose |
|-----------|----------|---------|
| `README.md` | `/README.md` | Main project documentation |
| `plan.md` | `/.github/architecture/plan.md` | Master project plan |
| `plan_n.md` | `/.github/architecture/plan_n.md` | Phase-level plans (e.g., `plan_1.md`, `plan_2.md`) |
| `plan_phase_n_task_y.md` | `/.github/architecture/plan_phase_n_task_y.md` | Detailed task breakdowns (e.g., `plan_phase_1_task_3.md`) |
| `clarifications_n.md` | `/.github/architecture/clarifications/clarifications_n.md` | Q&A and decision records |

### Prohibited Actions

- ❌ **Proliferation of `.md` files is expressly forbidden** - Do not create documentation files outside the allowed patterns above
- ❌ Do not create summary documents, changelog files, or ad-hoc markdown notes
- ❌ Do not create TODO.md, NOTES.md, or similar files

### Encouraged Behaviors

- ✅ **Frequent writes and updates to plan files** - This enables other agents to resume work if interrupted
- ✅ Keep plans current with completed work, blockers, and next steps
- ✅ Document decisions and clarifications in the clarifications folder

---

## Technology Stack

### Backend
- **Language**: Python 3.9+
- **KeePass Library**: pykeepass
- **Optional Dependencies**: boto3/botocore for S3 support
- **Testing**: pytest with coverage

### Project Structure
```
src/mattstash/
├── __init__.py           # Package exports
├── core.py               # Re-exports for backward compatibility
├── credential_store.py   # KeePass database operations
├── module_functions.py   # Module-level convenience functions
├── version_manager.py    # Versioned credentials support
├── builders/             # URL and client builders
│   ├── db_url.py         # SQLAlchemy URL construction
│   └── s3_client.py      # S3 client creation
├── cli/                  # Command-line interface
│   ├── main.py           # CLI entry point
│   └── handlers/         # Command handlers
├── core/                 # Core business logic
│   ├── bootstrap.py      # Database initialization
│   ├── entry_manager.py  # CRUD operations
│   ├── mattstash.py      # Main orchestration class
│   └── password_resolver.py  # Password resolution
├── models/               # Data models
│   ├── config.py         # Configuration settings
│   └── credential.py     # Credential dataclass
└── utils/                # Utilities
    └── exceptions.py     # Custom exceptions
```

---

## Development Environment

### Python Virtual Environment

This project uses a centralized virtual environment located at:
```
/Users/matt/.venvs/mattstash
```

**Important**: Always activate this venv before running Python commands:
```bash
source /Users/matt/.venvs/mattstash/bin/activate
```

The server component has its own venv at:
```
/Users/matt/Documents/GitHub/mattstash/server/venv
```

Activate for server work:
```bash
cd server && source venv/bin/activate
```

### Development Scripts

#### `scripts/run-tests.sh` - Test Suite
Runs the full test suite with pytest.

#### `scripts/update-pypi.sh` - Package Publishing
Publishes the package to PyPI.

---

## Quality Standards

### Code Quality
- Type hints required on all public functions
- Docstrings for all modules, classes, and public methods
- Follow PEP 8 style guidelines
- No high/critical security vulnerabilities

### Testing
- Minimum test coverage: **90%**
- Unit tests with pytest
- Mock external dependencies (KeePass, S3)

---

## Plan File Structure

### Master Plan (`.github/architecture/plan.md`)
```markdown
# MattStash Master Plan

## Current Phase: [N]
## Current Status: [In Progress / Blocked / Complete]

## Phases Overview
- Phase 1: [Name] - [Status]
- Phase 2: [Name] - [Status]
...

## Quick Links
- [Phase 1 Details](plan_1.md)
- [Phase 2 Details](plan_2.md)
```

### Phase Plan (`.github/architecture/plan_n.md`)
```markdown
# Phase N: [Phase Name]

## Objective
[What this phase accomplishes]

## Tasks
- [ ] Task 1 - [Status]
- [ ] Task 2 - [Status]

## Detailed Task Plans
- [Task 3 Details](plan_phase_n_task_3.md) (if complex)

## Completion Criteria
[How we know this phase is done]
```

### Clarifications (`.github/architecture/clarifications/clarifications_n.md`)
```markdown
# Clarifications - Session N

## Date: [YYYY-MM-DD]

### Q1: [Question]
**A**: [Answer/Decision]
**Rationale**: [Why this decision was made]
```

---

## Resumption Protocol

When an agent picks up work:

1. Read `.github/architecture/plan.md` for current status
2. Read the current phase plan (`plan_n.md`)
3. Check for any blocking clarifications needed
4. Update plan with "Work resumed by agent at [timestamp]"
5. Continue from last documented checkpoint
6. Update plan frequently during work
7. On interruption, document exact stopping point

---

## Key Principles

1. **Security First**: Credentials must be handled securely; never log passwords in plaintext
2. **Continuity**: Plans must always reflect current state for seamless handoffs
3. **Traceability**: All decisions documented in clarifications
4. **Simplicity**: No file proliferation - use the defined structure only
5. **Backward Compatibility**: Maintain API compatibility across versions
6. **Minimal Dependencies**: Keep runtime dependencies minimal (only pykeepass required)
