# FORENSIC_SHIMCACHE

Captures: AppCompatCache (ShimCache) execution evidence from the SYSTEM hive — program Path,
file ModificationTime, ExecutionFlag, and Position (cache order, most-recent first).

- Mode: registry (mode 1). Runs under the dead-disk remap; reads
  HKLM/System/ControlSet*/Control/Session Manager/AppCompatCache (= the image's SYSTEM hive).
- Built-in used: Windows.Registry.AppCompatCache (called as `Artifact.Windows.Registry.AppCompatCache()`).
- Rows on P:: 184.
