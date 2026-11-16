# Writing VENOMSCAN analysis plugins

Plugins add checks without modifying the engine. They are **analysis-only**: the engine
hands them a bounded, read-only payload it already collected, and the plugin returns
finding dicts. Plugins never receive a network client, credentials or the AI key.

Read [SAFETY.md](SAFETY.md) first. Plugins are operator-installed code and you are
responsible for reviewing anything you install.

## File contract

- One `.py` file per plugin; files starting with `_` are ignored.
- Top-level **literal** constants (the API discovers them with `ast`, without importing
  your code):

| Constant | Required | Meaning |
| --- | --- | --- |
| `CHECK_ID` | yes | Must match `venom.plugin.<lowercase>` (2–60 chars) |
| `NAME` | yes | Human title shown in the catalogue |
| `CATEGORY` | yes | Grouping, e.g. `disclosure` |
| `SEVERITY` | yes | One of `critical`, `high`, `medium`, `low`, `info` |
| `PROFILE` | yes | `passive`, `safe` or `active` — profile order gates execution |
| `TIMEOUT_SECONDS` | no | 1–30, default 10 |
| `MEMORY_MB` | no | 64–512, default 256 |

- A callable `run(payload)` must exist. It may be `async`; it returns a list of dicts.
- File size ≤ 200 KB. Duplicate ids are reported and the later file is ignored.

## Execution environment

The parent spawns `python -I -m venomscan_engine.plugins.worker` with:

- a scrubbed environment (no `LLM_API_KEY`, database URLs or credentials),
- a fresh temporary working directory,
- POSIX address-space and CPU limits from `MEMORY_MB`/`TIMEOUT_SECONDS` (timeout only on
  Windows),
- a hard wall-clock kill on timeout.

The payload is capped (~300 KB): scan id, target URL, profile, the root page's collected
evidence (headers etc.), detected technologies, up to 200 endpoints and up to 100 existing
findings. Nothing else is available; do not attempt network access.

After your plugin returns, the parent:

1. accepts at most 25 findings per plugin and 50 per scan,
2. drops any finding whose `url` is outside the authorized scope,
3. forces an allowed severity, normalises confidence and computes the risk score,
4. attaches `check_id` and `category`, then stores and reports the finding.

## Finding dict

```python
{
    "title": "Software version disclosed in response headers",      # required
    "description": "…",                                             # required
    "impact": "…",                                                  # required
    "remediation": "…",                                             # required
    "url": "https://target.example/",                               # required, in scope
    "severity": "low",                                              # optional override
    "category": "disclosure",
    "confidence": 8,                                                # 0–10
    "parameter": None,
    "payload": None,
    "cwe": ["CWE-200"],
    "references": ["https://owasp.org/…"],
}
```

Items missing a required field are dropped silently (fail closed). Strings are truncated;
lists are capped at 10 entries. Keep evidence descriptive but free of secrets — the parent
cannot know what your plugin chose to include.

## Example

`examples/plugins/version_banner.py` demonstrates the whole contract: constants, a sync
`run(payload)`, header inspection from `payload["root"]["headers"]`, and one informational
finding whose URL is the target root.

Enable it locally:

```bash
PLUGIN_DIRS=examples/plugins make api
```

Then check **Learning → Analysis plugins** (or `GET /api/checks/plugins`) for the catalogue
and any discovery problems. Plugins run during the analyzing phase of a scan whose profile
is at or above the plugin's profile.

## Testing

```bash
uv run python -m pytest tests/unit/engine/test_plugins.py
```

Unit tests call `run(payload)` directly for logic and go through
`run_plugin(spec, payload, scope)` to assert isolation, scoping, caps and timeouts. Do the
same for your plugin: assert the empty case, the positive case and any edge conditions, and
verify you never depend on the environment or the filesystem.

## Licensing

VENOMSCAN is not distributed with third-party plugins. Review every plugin's license before
installing it, keep its source pinned, and prefer small, auditable files. Do not copy code
from another project without checking its license.
