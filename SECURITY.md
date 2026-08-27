# Security policy

## Supported use

This repository supports only synthetic targets owned by the operator. Do not configure it to
scan public services, third-party repositories, production systems, private networks, or real
user data. The supplied Docker network is internal and the target accepts only synthetic fixtures.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's security advisory workflow. Do not include
production credentials, customer data, or transferable exploit payloads. A useful report includes
the affected version, a sanitized local reproduction, expected behavior, and the smallest safe
regression case.

## Evidence handling

Evidence packets must not contain secrets, raw private prompts, or unsafe payloads. The harness
uses canary tests and redaction, but operators remain responsible for reviewing artifacts before
sharing them.
