# FORENSIC_USN

Captures: NTFS USN change journal ($Extend/$UsnJrnl:$J) — file create/delete/rename/write
history with a per-event Timestamp, change Reason, reassembled OSPath, Filename, MFTId/ParentMFTId, Usn.

- Mode: raw-NTFS (mode 2). `:rawdrive` -> real drive letter; runs with no remap. Tested `:rawdrive`->`P:`.
- Built-in used: Windows.Forensics.Usn (called as `Artifact.Windows.Forensics.Usn(Device=":rawdrive")`;
  it wraps the device in `pathspec(..., path_type="ntfs")` and reassembles paths from $MFT).
- Rows on P:: 66,071 (USN is NOT empty on this image; ~1.8 GB $J stream).
- Note on the plain plugin form: `parse_usn(device=":rawdrive")` (plain string device) returns 0 rows —
  a bare drive string is not parsed as NTFS. It only works wrapped as
  `parse_usn(device=pathspec(parse=":rawdrive", path_type="ntfs"))`. The built-in does this internally,
  so the built-in is used here.
