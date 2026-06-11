# Threat Model

## Security goals

- Scan before installation.
- Never execute, import, install, or source files from the target Skill.
- Report evidence with file paths and line numbers.
- Separate code risk, permission risk, and provenance risk.
- Treat a clean scan as "no known issue found", never as certification.

## Covered threats

- Prompt injection and instructions that bypass user approval.
- Destructive shell commands and dynamic code execution.
- Credential, environment-variable, browser-data, and SSH-key access.
- Data upload, unknown network destinations, and direct IP access.
- Persistence through shell profiles, scheduled tasks, or Agent configuration.
- Obfuscation and encoded payloads.
- ZIP path traversal and symbolic links.
- Unpinned dependencies and package installation lifecycle scripts.
- New files and newly introduced findings compared with a prior scan.
- Unverified official/brand claims and suspicious domains.

## Known limitations

- Static analysis cannot prove runtime behavior.
- Regex rules can produce false positives and false negatives.
- The scanner does not establish legal ownership of a brand.
- The scanner does not query package registries, DNS, WHOIS, or malware feeds in the MVP.
- GitHub API rate limits may reduce available repository metadata; commit SHA remains pinned.
- Native binaries require separate signature and sandbox analysis.
