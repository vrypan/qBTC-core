# Contributing to qBTC Core

Thank you for your interest in contributing to qBTC Core! We welcome contributions from the community.

## How to Contribute

### 1. Fork the Repository

Fork the repository on GitHub and clone your fork locally:

```bash
git clone https://github.com/your-username/qBTC-core.git
cd qBTC-core
git remote add upstream https://github.com/q-btc/qBTC-core.git
```

### 2. Create a Branch

Create a feature branch for your changes:

```bash
git checkout -b feature/your-feature-name
```

### 3. Make Your Changes

- Write clean, maintainable code
- Follow the existing code style
- Add tests for new functionality
- Update documentation as needed

### 4. Test Your Changes

```bash
# Run unit tests
cd tests && pytest -v

# Run integration tests
python full_100_cycle_test.py --cycles 10

# Run security tests
pytest test_security.py test_rate_limiting.py -v
```

### 5. Commit Your Changes

Write clear commit messages:

```bash
git add .
git commit -m "Add feature: brief description

- Detailed explanation
- Another detail"
```

### 6. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## Development Setup

See the [README](README.md#development-setup) for detailed setup instructions.

## Code Style

- Use Python 3.10+ features
- Follow PEP 8 guidelines
- Use type hints where appropriate
- Keep functions focused and small
- Add docstrings to all public functions

## Testing

- Write tests for all new features
- Maintain or improve code coverage
- Tests should be fast and reliable

## Security

- Never commit secrets or private keys
- Follow secure coding practices
- Report security issues privately

## Pull Request Process

1. Update the README.md with details of changes if needed
2. Ensure all tests pass
3. Get approval from at least one maintainer
4. Squash commits if requested

## Questions?

Open an issue for discussion before making major changes.

Thank you for contributing!