# FORENSIC_SERVICES — Forensic.System.Services

- Captures: installed services/drivers from the SYSTEM hive (service name, DisplayName, ImagePath, decoded Start type, service Type, run-as account, key write time). CurrentControlSet is resolved from HKLM/System/Select/Current (= ControlSet001 here). NonSystemImagePath flags an ImagePath outside the Windows system dirs (e.g. third-party services under Program Files).
- Mode: file/registry (reads HKLM/System/ControlSet00N/Services via read_reg_key under the remap).
- Built-in used: none (Windows.System.Services uses WMI, which is disabled on a dead disk; hand-written registry query).
- Rows on P: 673 (only keys that have an ImagePath; 16 flagged NonSystemImagePath).
