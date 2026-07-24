"""agent-airlock — run untrusted/agentic model CLIs without giving them your disk.

Five composable pieces:

- ``jail``      : bwrap-based structural isolation for any agent CLI, with an
                  inside-the-process acceptance probe.
- ``transport`` : export → invoke → import with a canonical effective request
                  hashed over the FULL invocation config, and strict
                  correlation on import.
- ``trustroot`` : two-commit approved-sources protocol without self-reference.
- ``scan``      : payload hygiene — allowlist construction first, deny-scan as
                  defense in depth.
- ``blindpack`` : pre-registered, structurally blinded human-review packs.
"""

__version__ = "0.1.0"
