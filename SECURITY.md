# Security policy

Please report vulnerabilities in odoo-doctor privately, through [GitHub's private vulnerability reporting](https://github.com/MarcRodriguezz/odoo-doctor/security/advisories/new), and do not open a public issue.

These are the issues that matter most, since they break the tool's promises:

- Anything that writes to an audited system.
- A secret, such as a password or API key, appearing in a report or in process arguments.
- A malicious module, file or server response that can run code or corrupt a report.

## Reports contain sensitive data

An HTML or JSON report can contain logins, database names, and details of a system's weaknesses. Treat reports as confidential, and use `--redact` before sharing them.

## Authorized use

Only audit systems you own or have permission to test. The external checks connect to the target's ports and request its database manager pages, which some monitoring tools may flag.
