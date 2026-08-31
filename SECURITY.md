# Security policy

## Project status

Plug & Prejudice is pre-release software. No version is currently supported
for security use.

## Reporting a vulnerability

Please use GitHub's private security-advisory workflow for this repository.
Do not open a public issue for a vulnerability that could endanger users.

Include a minimal description, affected revision, impact, and reproduction
steps that do not contain credentials or unrelated private data. Do not attach
live malware, secrets, or raw private plugin repositories.

GitHub private vulnerability reporting is enabled for this repository. Use the
**Report a vulnerability** action on the repository's Security page. A public
issue is appropriate only after coordinated disclosure or when the report has
no security-sensitive details.

## Maintainer response workflow

For a private report, a maintainer should:

1. acknowledge and classify the affected trust boundary without promising that
   an unverified report is exploitable or harmless;
2. reproduce with the smallest synthetic, non-secret input possible, never by
   executing a submitted plugin;
3. record affected revisions, architectures, prerequisites, impact, and known
   limitations in the private advisory;
4. develop and review the fix in the advisory's private fork when early public
   disclosure would put users at risk;
5. run the normal tests plus the security-specific sandbox, hostile-rendering,
   dependency, vulnerability, and reproducibility checks relevant to the
   boundary;
6. coordinate a fixed release, checksums/provenance, upgrade instructions, and
   advisory publication; and
7. request a CVE through GitHub when the vulnerability and release impact
   warrant one.

Do not paste reporter data into public CI logs, issues, commits, or external
models. If a report contains credentials or personal data, minimize access and
ask the reporter to rotate or revoke exposed credentials; do not copy them into
the advisory. Preserve only the evidence required to understand and fix the
problem.

Before the first release, a repository owner must exercise this workflow using
a harmless private test report, confirm that maintainers can access and respond
to it, and remove the test report according to GitHub's supported workflow. The
exercise proves only that the intake path works; it does not validate incident
response to a real vulnerability.

## Security claims

A completed scan is not proof that a plugin is safe. Reports describe observed
facts, supported inferences, unknowns, and explicit analysis limitations.

The supported higher-assurance deployment is the independently installed CLI
launched from the normal host session. Its containment claim assumes that the
broker begins in the real host user and mount namespaces with the normal host
views of `/usr`, `/run`, procfs, and cgroupfs. The broker does not authenticate
an arbitrary caller's namespaces; invocation from an attacker-created user or
mount namespace is outside that claim.

This boundary is intended to inspect hostile plugin files before they are
trusted. It does not make the surrounding desktop session trustworthy after a
same-user malicious plugin has already been enabled and can interfere with the
caller or presentation surface.

## Scope boundary

The normal scanner must never execute target-plugin code. Any future dynamic
analysis would require a separate design, explicit user action, and a stronger
sandbox boundary; it must not be added silently to normal scans.
