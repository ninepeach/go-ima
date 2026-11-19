# Project Instructions — go-ima

Follow the shared global AI engineering rules. This file adds repository-specific context only.

## Purpose
Identity and access management library. Verify its actual APIs and scope from repository code and approved design before implementation.

## Boundaries
- Keep authentication, authorization, and session responsibilities explicit; do not add unrelated infrastructure or application-specific policy.
- Security-sensitive changes require explicit failure behavior, cancellation, and tests for invalid and adversarial inputs.
- Do not assume planned features are implemented. The repository may be at an early stage.
- Obtain approval before changing token formats, persistent identity/session representations, or security contracts.

## Verification
- Determine supported build and test commands from the repository before running them. Do not claim tests passed when no implementation exists.
