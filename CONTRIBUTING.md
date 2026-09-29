# Contributing to CanaryFabric

Thank you for your interest in contributing to CanaryFabric! This document provides guidelines for contributing to the project.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/sagarv48/canary-fabric.git
cd canary-fabric

# Create a virtual environment and install dependencies
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest -v
```

## Code Quality

We use `ruff` for linting. Run it before submitting:

```bash
ruff check .
ruff format .
```

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Add or update tests for any new functionality.
3. Ensure all tests pass and ruff reports no errors.
4. Update documentation (README, docstrings) if applicable.
5. Submit a pull request with a clear description of the changes.

## Reporting Security Vulnerabilities

**Do not open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Code of Conduct

Be respectful, constructive, and collaborative. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.