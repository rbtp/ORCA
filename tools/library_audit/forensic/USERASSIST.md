# FORENSIC_USERASSIST — Forensic.Execution.UserAssist

- Captures: program-execution evidence from the per-user UserAssist keys (ROT13-decoded program name, run count, last run time, user) across every NTUSER.DAT on the image.
- Mode: file/registry (runs under the remap).
- Built-in used: Windows.Registry.UserAssist (wrapped; it decodes ROT13 and resolves the per-user hives via Windows.Registry.NTUser/Windows.Sys.Users).
- Rows on P: 2 (clean image: orcatest has only cmd.exe and CortanaUI entries, both with 0 runs / no timestamp).
