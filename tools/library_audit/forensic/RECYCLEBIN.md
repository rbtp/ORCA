# FORENSIC_RECYCLEBIN (Forensic.Windows.RecycleBin)

- Captures: deleted-file records from Recycle Bin `$I` metadata files (`C:/$Recycle.Bin/<SID>/$I*`) - original full path, logical file size, deletion time, and the path of the matching `$R` content file (recoverable data).
- Mode: file (runs under the dead-disk remap; globs the image's `$Recycle.Bin`).
- Rows on P:: 0. Genuinely empty on this clean image - `C:/$Recycle.Bin/<SID>/` contains only `desktop.ini`, no `$I` files (nothing has been deleted to the Recycle Bin). Query is correct; it returns rows on any image with deleted files.
- Built-in used: `Windows.Forensics.RecycleBin` (wrapped; Vista+ `$I` format).
