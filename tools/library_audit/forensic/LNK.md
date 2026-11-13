# FORENSIC_LNK (Forensic.Windows.Lnk)

- Captures: recent-file / program-launch evidence from LNK shortcut files (Recent, Desktop, Start Menu, ProgramData) - LNK path + mtime/btime, target path, target MAC timestamps, size, working dir and arguments.
- Mode: file (runs under the dead-disk remap; reads `C:\...\*.lnk`).
- Rows on P:: 85.
- Built-in used: `Windows.Forensics.Lnk` (wrapped; default TargetGlob widened to cover Desktop + whole Start Menu; SuspiciousOnly left off so all LNKs return, Suspicious column retained).
