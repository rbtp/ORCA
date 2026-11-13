# FORENSIC_SHELLBAGS (Forensic.Windows.Shellbags)

- Captures: folder-access history (Shellbags) from per-user NTUSER.DAT and UsrClass.dat hives - full navigated path, folder name, registry/BagMRU timestamp, and the owning user (derived from the hive path).
- Mode: file (runs under the dead-disk remap; the built-in reads the hive files directly with the raw registry parser, so no logged-on user is needed).
- Rows on P:: 0. Genuinely empty on this clean image - the only user profile (orcatest) and the Default profile have no navigated-folder slots (BagMRU holds only MRUListEx/NodeSlots, no numeric item slots), i.e. Explorer folder browsing never created shellbag entries. Query is correct and returns rows on any image with Explorer activity (verified the raw_reg BagMRU glob reaches the image hives).
- Built-in used: `Windows.Forensics.Shellbags` (wrapped; adds a per-user column).
