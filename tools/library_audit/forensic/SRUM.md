SRUM (System Resource Usage Monitor) per-app and per-network resource usage from
Windows/System32/sru/SRUDB.dat. Raw-drive collection (:rawdrive, runs outside the remap
so it can execute esentutl). Copies the DB + transaction logs to a temp folder and recovers
the dirty ESE database with the workstation's own esentutl (/r log replay, then /p repair)
before parsing it with the built-in Windows.Forensics.SRUM. Recovery works when the
workstation's Windows >= the image's Windows; a newer image can't be recovered by an older
esentutl, and the RecoveryStatus source then reports that instead of a silent empty result.
On the clean test image (Windows 11, recovered on a Windows 10 workstation) recovery is not
possible, so ResourceUsage is empty and RecoveryStatus explains why. The workstation's own
esentutl is used, never a binary from the evidence image.
