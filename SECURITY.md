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
