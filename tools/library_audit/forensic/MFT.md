# FORENSIC_MFT

Captures: full NTFS Master File Table timeline. Every in-use ($MFT) file record with
all four $STANDARD_INFORMATION (0x10) timestamps — Created, Modified, MFT-changed, Accessed —
plus EntryNumber, FileName, FileSize, OSPath.

- Mode: raw-NTFS (mode 2). Query reads `parse_mft(filename=":rawdrive/$MFT", accessor="ntfs")`;
  agent substitutes the drive letter and runs with no remap. Tested by substituting `:rawdrive`->`P:`.
- Built-in used: none (hand-written `parse_mft`).
- Rows on P:: 792,588 InUse entries (full-disk timeline; large is expected). Collect time ~56s.
