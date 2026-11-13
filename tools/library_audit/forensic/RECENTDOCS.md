# FORENSIC_RECENTDOCS — Forensic.Execution.RecentDocs

- Captures: recently opened documents from the per-user RecentDocs keys (file name decoded from the leading UTF-16LE of each binary value, owning subkey = file extension, key write time, user) across every NTUSER.DAT on the image.
- Mode: file/registry (glob over HKEY_USERS/*/.../Explorer/RecentDocs/** under the remap).
- Built-in used: none (no built-in RecentDocs artifact; hand-written registry decode).
- Rows on P: 0 — the RecentDocs key exists but is empty on this freshly installed image (no documents opened). Query validated clean (verify + collect, no errors); it returns decoded rows as soon as the key is populated.
