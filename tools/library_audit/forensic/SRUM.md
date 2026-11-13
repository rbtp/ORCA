# FORENSIC_SRUM (Forensic.Windows.SRUM)

- Captures: per-application and per-network resource usage from the System Resource Usage Monitor DB (`C:/Windows/System32/sru/SRUDB.dat`). Three sources: ApplicationResourceUsage (app + timestamp + fg/bg bytes read/written), NetworkUsage (app + timestamp + BytesSent/BytesRecvd), ExecutionStats (app + timestamp + duration + NetworkBytesRaw).
- Mode: file (runs under the dead-disk remap; reads `C:/.../SRUDB.dat`).
- Rows on P:: 0 - but NOT because the query is wrong. SRUDB.dat (2 MB, populated) on this image is a dirty/unflushed ESE database (captured while the VM was live), and Velociraptor's `parse_ese` refuses it: `parse_ese: Unable to open file ...SRUDB.dat: Page 2326537 exceeds max page 497`. The built-in and this wrapper both return 0 on a dirty DB. On a cleanly shut-down image, or after `esentutl /r SRU` recovery, these sources return rows. Query verified correct (wraps the vetted built-in).
- Built-in used: `Windows.Forensics.SRUM` (wrapped; one source per SRUM table, trimmed to app/timestamp/bytes columns).
