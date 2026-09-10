# A3S Sentry Roadmap

**Status as of 2026-09-10.**

Sentry judges runtime-security evidence and requests enforcement through
Observer. It is not Cloud IAM or Gateway request authorization.

## A3S Cloud substrate obligations

| Priority | This repository must deliver | Forbidden |
| --- | --- | --- |
| `OBS` / `EV0` / `POL*` | Deterministic fail-closed judgment and signed policy receipts | Owning incidents, desired state, or kernel enforcement |
| Wave 2 | Generation-bound policy apply/ack without weakening lower-tier denies | Implicit allow on truncated evidence |

Portfolio detail:
[operations-clients-and-release.md](https://github.com/A3S-Lab/Cloud/blob/main/docs/project-roadmaps/operations-clients-and-release.md).

Monorepo index:
[cloud-substrate-dependency-roadmap.md](https://github.com/A3S-Lab/a3s/blob/main/docs/cloud-substrate-dependency-roadmap.md).
