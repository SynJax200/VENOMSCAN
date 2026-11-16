# Third-party notices and licence review

VENOMSCAN is an original implementation. Reference projects were reviewed for concepts only.
No source files were copied, and every listed item was checked against its licence before any
idea was adopted.

## Reviewed reference projects

| Project        | Licence                          | What was used                                                              | Code copied |
| -------------- | -------------------------------- | -------------------------------------------------------------------------- | ----------- |
| GhostScan      | MIT                              | Module decomposition (recon → crawl → checks → report) and dashboard concepts | No          |
| Ducky          | MIT                              | Manual test checklist structure used to design the check catalogue           | No          |
| PROSECUTOR     | No licence declared              | High-level ideas only. No code, assets or text reused                        | No          |
| RedTiger-Tools | Contains stealer / malware / DoS | Excluded entirely. Not reviewed for functionality, not referenced            | No          |

Notes:

- MIT-licensed projects permit reuse with attribution, but VENOMSCAN reimplements every
  behaviour from scratch, so no MIT licence text needs to be carried for them. If any code is
  ever lifted from GhostScan or Ducky, the MIT notice must be reproduced here and in the file
  header.
- PROSECUTOR has no licence, which means all rights are reserved. Only non-copyrightable ideas
  were taken. Do not copy its code without written permission from its author.
- RedTiger-Tools ships credential stealers and DoS tooling. Nothing from that repository is
  present in this codebase, and it must not be added.

## Runtime dependencies

Python packages are declared in `pyproject.toml`, `apps/api/pyproject.toml` and
`workers/pyproject.toml`; JavaScript packages in `apps/web/package.json`. All are consumed as
published packages under their own licences (predominantly MIT, BSD and Apache-2.0). Notable
components:

| Component        | Licence      | Use                                    |
| ---------------- | ------------ | -------------------------------------- |
| FastAPI          | MIT          | HTTP API                               |
| SQLAlchemy       | MIT          | ORM                                    |
| Pydantic         | MIT          | Schemas and settings                   |
| httpx            | BSD-3-Clause | Outbound HTTP (safety chokepoint)      |
| cryptography     | Apache-2.0 / BSD-3-Clause | TLS inspection            |
| dnspython        | ISC          | DNS TXT authorization checks           |
| Celery           | BSD-3-Clause | Background workers                     |
| PyJWT            | MIT          | Access and refresh tokens              |
| Next.js / React  | MIT          | Web application                        |
| Tailwind CSS     | MIT          | Styling                                |
| Recharts         | MIT          | Dashboard charts                       |
| lucide-react     | ISC          | Icons                                  |

Dependency licences are not vendored here; they remain with their respective copyright holders.

## Security tooling policy

Reference material from offensive-security repositories is used for defensive testing design
only. VENOMSCAN does not include credential harvesting, persistence, evasion of monitoring, or
denial-of-service capabilities, and it refuses to scan targets that have not been verified as
authorized.
