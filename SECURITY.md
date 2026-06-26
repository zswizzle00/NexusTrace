# Security Policy

## Supported Versions

Currently supported versions of NexusTrace:

| Version | Supported |
|---------|-----------|
| Latest version on `latest-version` branch | Yes |
| Older versions | No |

## Reporting a Vulnerability

### How to Report

**Do not report security vulnerabilities publicly.** Instead, send them directly to the maintainer:

- **Email:** zackmckone@icloud.com
- **Subject:** Security Vulnerability in NexusTrace

### What to Include

Please include the following information in your report:

- Description of the vulnerability
- Steps to reproduce the vulnerability
- Potential impact of the vulnerability
- Any suggested fixes or mitigations
- Your contact information for follow-up

### Response Timeline

- **Initial Response:** Within 48 hours
- **Detailed Assessment:** Within 1 week
- **Fix Timeline:** Depends on severity and complexity

### Coordinated Disclosure

We follow responsible disclosure practices:

1. Acknowledge receipt of your report
2. Work with you to understand and validate the issue
3. Develop and test a fix
4. Coordinate release of fix and disclosure
5. Credit you in the release notes (if desired)

## Security Best Practices

### For Users

- Keep NexusTrace updated to the latest version
- Use strong, unique API keys
- Enable HTTPS in production
- Review and restrict API key permissions
- Monitor usage logs for suspicious activity
- Keep dependencies updated

### For Developers

- Never commit API keys or secrets
- Use environment variables for sensitive data
- Follow OWASP security guidelines
- Implement proper input validation
- Use parameterized queries to prevent SQL injection
- Enable security headers (CSP, HSTS, etc.)
- Implement rate limiting
- Log security events appropriately

### For Deployment

- Use HTTPS/TLS for all connections
- Implement proper authentication and authorization
- Use Cloudflare WAF or similar protection
- Keep systems and dependencies updated
- Implement proper logging and monitoring
- Use secrets management (Vault, Docker Secrets, etc.)
- Regular security audits and penetration testing

## Known Security Considerations

### Current Security Features

- CSRF protection via Flask-WTF
- Security headers via Flask-Talisman
- Rate limiting for API endpoints
- Input validation and sanitization
- Secure session management
- API key authentication for enrichment endpoints

### Areas for Improvement

- Enhanced input validation for SSRF prevention
- Comprehensive security testing suite
- Advanced rate limiting per user
- Security audit and penetration testing
- Dependency vulnerability scanning

## Security Updates

### How Updates Are Handled

- Security updates are released as soon as possible
- Critical vulnerabilities are addressed immediately
- Updates are announced via GitHub releases
- Security advisories are published for critical issues

### Staying Informed

- Watch the GitHub repository for releases
- Subscribe to security advisories
- Review CHANGELOG for security updates
- Follow security best practices

## Dependency Security

### Managing Dependencies

- Dependencies are managed with `uv`
- Regular updates for security patches
- Vulnerability scanning recommended
- Review dependencies before adding

### Recommended Tools

- `pip-audit` - Check for known vulnerabilities
- `safety` - Security linting for Python
- `bandit` - Security linter for Python code

## Security Testing

### Automated Testing

- Unit tests for security-critical functions
- Integration tests for API security
- Automated security scanning in CI/CD

### Manual Testing

- Regular security reviews
- Penetration testing
- Code reviews with security focus

## Incident Response

### Security Incident Process

1. **Detection** - Identify potential security incident
2. **Assessment** - Evaluate severity and impact
3. **Containment** - Limit damage if possible
4. **Eradication** - Remove threat or vulnerability
5. **Recovery** - Restore normal operations
6. **Lessons Learned** - Document and improve processes

### Contact for Incidents

- **Email:** zackmckone@icloud.com
- **Subject:** Security Incident - NexusTrace

## Compliance

NexusTrace is designed to help with security research and threat intelligence. Users should:

- Use only for legitimate security purposes
- Respect terms of service of integrated APIs
- Follow applicable laws and regulations
- Obtain proper authorization before testing
- Report vulnerabilities responsibly

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Security Guidelines](https://github.com/zswizzle00/NexusTrace/blob/main/docs/security.md)

## Questions

If you have questions about security that don't involve reporting a vulnerability:

- Open a GitHub Discussion
- Email: zackmckone@icloud.com
- Subject: Security Question - NexusTrace

Thank you for helping keep NexusTrace secure!