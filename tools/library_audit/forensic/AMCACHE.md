# FORENSIC_AMCACHE

Captures: program presence/execution from Amcache.hve (InventoryApplicationFile) — program name,
registration time (key last-write), ProgramId, plus Path/Sha1/Size where the hive records them.

- Mode: file/registry (mode 1). Runs under the dead-disk remap; reads C:/Windows/appcompat/Programs/Amcache.hve
  with the `raw_reg` accessor.
- Built-in used: none. The built-in Windows.Forensics.Amcache returned 486 rows but with all fields null on
  this hive (its File/Programs keys are absent). Hand-written raw_reg walk of InventoryApplicationFile instead.
- Rows on P:: 486. On this image each entry stores only ProgramId/FileId, so Path/Sha1/Size are null
  (columns kept for images that do record them); program name + timestamp come from the entry key itself.
