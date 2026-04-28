# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.5.x   | :white_check_mark: |
| < 0.5   | :x:                |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Instead:

1. Email security issues to the maintainer — contact links are available on the [GitHub profile](https://github.com/Swixixle).

2. Include:

   - Description of vulnerability  
   - Steps to reproduce  
   - Potential impact  
   - Suggested fix (if known)

3. Allow 90 days for fix before public disclosure  
4. A CVE may be filed if applicable  

## Security Assumptions

See [Threat model](./THREAT_MODEL.md) for full security assumptions and limitations.

**TL;DR:**

- KeySmith is a working prototype for development workflows  
- Not recommended for production secrets at scale  
- No formal security audit has been performed  
- Assumes trusted team members  
- Enforcement is advisory (can be bypassed)  

## Known Limitations

1. **No formal audit** — use at your own risk  
2. **Enforcement is advisory** — can be bypassed  
3. **Basic test coverage** — the test suite is not comprehensive  
4. **Assumes non-adversarial context** — not for malicious insider threats  
5. **No kernel-level protection** — a compromised machine can expose secrets  

## Recommended Usage

**Good for:**

- Personal development workflows  
- Small trusted teams (2–5 people)  
- Non-critical API credentials  

**Not for:**

- Production secrets at scale  
- Regulated environments (HIPAA, PCI-DSS)  
- High-security contexts  
- Adversarial team environments  
