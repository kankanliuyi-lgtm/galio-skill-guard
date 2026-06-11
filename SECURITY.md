# Security Policy

## Supported version

The current supported release line is `v0.2.x-alpha`.

## Reporting a vulnerability

Please do not publish an exploit, credential, or sensitive sample in a public issue.

Report the problem through GitHub Security Advisories after the repository is published:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Include the affected version, input type, minimal reproduction, expected behavior, and actual behavior.

If private reporting is unavailable, open a public issue containing only a non-sensitive summary and ask the maintainer for a private channel.

## Security expectations

- The scanner must never execute code from the target Skill.
- A low-risk result is not a security certification.
- Findings may contain false positives and false negatives.
- Do not include real tokens, private keys, cookies, or personal files in reports.
