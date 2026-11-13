# FORENSIC_PREFETCH

Captures: program execution evidence from Windows Prefetch (C:/Windows/Prefetch/*.pf) —
executable name, full ExecutablePath, RunCount, last-run time(s), .pf create/modify times, files accessed.

- Mode: file (mode 1). Runs under the dead-disk remap, reading C: (= the image).
- Built-in used: Windows.Forensics.Prefetch (called as `Artifact.Windows.Forensics.Prefetch()`).
- Rows on P:: 230. Columns corrected to the 0.77 built-in schema (Executable/CreationTime/
  ModificationTime/LastRunTimes[]) — the spec template's `Name`/`Mtime`/`LastRunTimes[0].Int` do not exist.
