# Contributing to NexusTrace

Thank you for your interest in contributing to NexusTrace! This document provides guidelines and instructions for contributing to the project.

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Git
- uv (Python package manager) - Install with: `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Docker (optional, for containerized development)

### Setting Up Development Environment

1. **Clone the repository**
   ```bash
   git clone https://github.com/zswizzle00/NexusTrace.git
   cd NexusTrace
   ```

2. **Install dependencies**
   ```bash
   uv sync
   ```

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

4. **Run the development server**
   ```bash
   ./start.sh
   ```

5. **Run tests**
   ```bash
   uv run python app/tests/test_ipv6_otx.py
   uv run python app/tests/test_endpoints.py
   ```

## Development Workflow

### Branching Strategy

- `main` - Stable production code
- `latest-version` - Latest development version
- Feature branches - `feature/your-feature-name`
- Bugfix branches - `bugfix/your-bugfix-name`

### Making Changes

1. **Create a new branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write clean, readable code
   - Follow existing code style
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes**
   ```bash
   # Run all tests
   uv run python app/tests/test_ipv6_otx.py
   uv run python app/tests/test_endpoints.py
   
   # Run development server
   ./start.sh
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "Clear, descriptive commit message"
   ```

5. **Push to your branch**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a pull request**
   - Go to https://github.com/zswizzle00/NexusTrace/pulls
   - Click "New Pull Request"
   - Provide a clear description of your changes

## Code Style Guidelines

### Python Code

- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions focused and concise
- Use type hints where appropriate

### JavaScript Code

- Use modern JavaScript (ES6+)
- Follow existing code patterns
- Add comments for complex logic
- Keep functions small and focused

### HTML/Templates

- Use semantic HTML
- Follow existing template structure
- Use Tailwind CSS classes consistently
- Keep templates clean and readable

## Testing Guidelines

### Writing Tests

- Write tests for new functionality
- Test both success and error cases
- Use descriptive test names
- Keep tests independent and fast

### Running Tests

```bash
# Run all tests
uv run python app/tests/test_ipv6_otx.py
uv run python app/tests/test_endpoints.py

# Run specific test file
uv run python app/tests/test_ipv6_otx.py
```

## Documentation Guidelines

### Updating Documentation

- Keep README.md up to date
- Update relevant documentation files
- Add comments for complex code
- Document new features and APIs

### Documentation Style

- Use clear, concise language
- Provide code examples
- Include screenshots where helpful
- Keep documentation organized

## Security Guidelines

### Reporting Security Issues

- Do not report security issues publicly
- Send security issues to: zackmckone@icloud.com
- Include detailed reproduction steps
- Allow time for the issue to be addressed

### Security Best Practices

- Never commit API keys or secrets
- Use environment variables for sensitive data
- Follow OWASP security guidelines
- Test for common vulnerabilities

## Pull Request Guidelines

### Before Submitting

- Ensure all tests pass
- Update documentation
- Follow code style guidelines
- Add tests for new functionality
- Update CHANGELOG if applicable

### Pull Request Description

- Provide a clear title
- Describe the changes made
- Explain the motivation for the changes
- List any breaking changes
- Reference related issues

### Review Process

- Maintainers will review your pull request
- Address feedback in a timely manner
- Be open to suggestions and improvements
- Keep discussions constructive

## Issue Guidelines

### Reporting Issues

- Search existing issues first
- Use clear, descriptive titles
- Provide detailed information
- Include reproduction steps
- Add relevant logs and screenshots

### Issue Labels

- `bug` - Bug reports
- `enhancement` - Feature requests
- `documentation` - Documentation issues
- `security` - Security issues
- `performance` - Performance issues

## Getting Help

### Resources

- README.md - Project overview and setup
- docs/ directory - Detailed documentation
- GitHub Issues - Known issues and discussions
- TODO.md - Current development priorities

### Communication

- GitHub Issues - For bugs and feature requests
- GitHub Discussions - For questions and ideas
- Email: zackmckone@icloud.com - For security issues

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for contributing to NexusTrace!