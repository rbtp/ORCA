-- Forensic dead-disk-only collections (see docs/LIBRARY_QUALITY.md): the artifacts a forensic
-- analyst wants off a mounted image regardless of any ATT&CK technique mapping -- MFT, USN journal,
-- Prefetch, Amcache, ShimCache, SRUM, WMI persistence, shellbags, LNK, recycle bin, scheduled tasks,
-- services, autoruns, UserAssist, RecentDocs. applies_live=false so they run only for a DEAD_DISK
-- asset; applies_dead=true. Inserted once; an operator's later edits in the Artifact Library Editor
-- are kept (ON CONFLICT DO NOTHING).

-- Depends on add_live_dead_query_variants.sql; the column adds are repeated with IF NOT EXISTS
-- so this migration works regardless of apply order.
ALTER TABLE ref_artifact_library ADD COLUMN IF NOT EXISTS applies_live boolean NOT NULL DEFAULT true;
ALTER TABLE ref_artifact_library ADD COLUMN IF NOT EXISTS applies_dead boolean NOT NULL DEFAULT true;
ALTER TABLE ref_artifact_library ADD COLUMN IF NOT EXISTS custom_vql_dead text;
ALTER TABLE ref_artifact_library ADD COLUMN IF NOT EXISTS surgical_yaml_dead text;

INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)
VALUES ('FORENSIC_AMCACHE', 'Program presence / execution evidence from the Amcache.hve registry hive on a', 'Windows', 'Forensic', $orcaforensic$name: Forensic.Execution.Amcache
description: |
  Program presence / execution evidence from the Amcache.hve registry hive on a
  mounted dead disk (C:/Windows/appcompat/Programs/Amcache.hve). File/registry
  mode (mode 1): runs under the dead-disk remap and reads the hive with the
  raw_reg accessor. Enumerates every InventoryApplicationFile entry: the program
  name (from the entry key), the entry's registration time (key last-write), the
  ProgramId, and the full path / SHA1 where the hive records them.
type: CLIENT
sources:
- name: Amcache
  query: |
    LET hive = "C:/Windows/appcompat/Programs/Amcache.hve"
    LET root = pathspec(DelegateAccessor="auto", DelegatePath=hive)
    SELECT split(string=Name, sep="[|]")[0] AS Program,
           Name AS AmcacheEntry,
           Mtime AS RegisteredTime,
           { SELECT Data.value FROM glob(globs="/ProgramId", accessor="raw_reg", root=OSPath) } AS ProgramId,
           { SELECT Data.value FROM glob(globs="/LowerCaseLongPath", accessor="raw_reg", root=OSPath) } AS Path,
           { SELECT Data.value FROM glob(globs="/Sha1", accessor="raw_reg", root=OSPath) } AS Sha1,
           { SELECT Data.value FROM glob(globs="/Size", accessor="raw_reg", root=OSPath) } AS Size
    FROM glob(globs="/Root/InventoryApplicationFile/*", accessor="raw_reg", root=root)
    ORDER BY RegisteredTime
$orcaforensic$, false, true, NOW())
ON CONFLICT (t_code) DO NOTHING;

INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)
VALUES ('FORENSIC_AUTORUNS', 'Autostart registry entries from a mounted disk image (dead disk): Run /', 'Windows', 'Forensic', $orcaforensic$name: Forensic.Persistence.Autoruns
description: |
  Autostart registry entries from a mounted disk image (dead disk): Run /
  RunOnce / RunOnceEx / policy Run keys for HKLM (including Wow6432Node) and
  for every user hive under HKEY_USERS, plus the Winlogon Shell / Userinit /
  Taskman / VmApplet / GinaDLL values (HKLM and per-user). Reports the hive,
  key, value name and the command executed at logon/boot.
sources:
- name: Autoruns
  query: |
    LET RunGlobs <= (
      'HKEY_LOCAL_MACHINE/Software/Microsoft/Windows/CurrentVersion/Run/*',
      'HKEY_LOCAL_MACHINE/Software/Microsoft/Windows/CurrentVersion/RunOnce/*',
      'HKEY_LOCAL_MACHINE/Software/Microsoft/Windows/CurrentVersion/RunOnceEx/*',
      'HKEY_LOCAL_MACHINE/Software/Microsoft/Windows/CurrentVersion/RunServices/*',
      'HKEY_LOCAL_MACHINE/Software/Microsoft/Windows/CurrentVersion/RunServicesOnce/*',
      'HKEY_LOCAL_MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/Explorer/Run/*',
      'HKEY_LOCAL_MACHINE/Software/Wow6432Node/Microsoft/Windows/CurrentVersion/Run/*',
      'HKEY_LOCAL_MACHINE/Software/Wow6432Node/Microsoft/Windows/CurrentVersion/RunOnce/*',
      'HKEY_USERS/*/Software/Microsoft/Windows/CurrentVersion/Run/*',
      'HKEY_USERS/*/Software/Microsoft/Windows/CurrentVersion/RunOnce/*',
      'HKEY_USERS/*/Software/Microsoft/Windows/CurrentVersion/RunOnceEx/*',
      'HKEY_USERS/*/Software/Microsoft/Windows/CurrentVersion/Policies/Explorer/Run/*'
    )

    LET WinlogonGlobs <= (
      'HKEY_LOCAL_MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/*',
      'HKEY_USERS/*/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/*'
    )

    LET Runs = SELECT OSPath, Name AS ValueName, Data.value AS Command
      FROM glob(globs=RunGlobs, accessor='registry')
      WHERE Data.type =~ 'SZ' AND Command

    LET Winlogon = SELECT OSPath, Name AS ValueName, Data.value AS Command
      FROM glob(globs=WinlogonGlobs, accessor='registry')
      WHERE ValueName =~ '''^(Shell|Userinit|Taskman|VmApplet|GinaDLL)$''' AND Command

    SELECT if(condition=OSPath =~ '^HKEY_USERS',
              then="HKU\\" + OSPath.Components[1],
              else="HKLM") AS Hive,
           dirname(path=OSPath) AS Key,
           ValueName,
           Command,
           OSPath
    FROM chain(a={SELECT * FROM Runs}, b={SELECT * FROM Winlogon})
    ORDER BY Hive
$orcaforensic$, false, true, NOW())
ON CONFLICT (t_code) DO NOTHING;

INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)
VALUES ('FORENSIC_LNK', 'Recent-file and program-launch evidence parsed from Windows LNK', 'Windows', 'Forensic', $orcaforensic$name: Forensic.Windows.Lnk
description: |
  Recent-file and program-launch evidence parsed from Windows LNK
  shortcut files on a mounted Windows disk image (dead disk). LNK files
  in the Recent folder, Desktop and Start Menu record the target file
  that was opened, its path, size and MAC timestamps, the working
  directory and any arguments - evidence of files that were accessed
  even if the target itself is now gone.

  Wraps the built-in Windows.Forensics.Lnk and widens the default glob
  to cover Recent, Desktop and the whole Start Menu for every user plus
  ProgramData. SuspiciousOnly is left off so every LNK is returned; the
  built-in's Suspicious column still flags anomalies.
reference:
  - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink
parameters:
  - name: TargetGlob
    default: C:\{ProgramData,Users\*\{Desktop,AppData\*\Microsoft\Windows\{Start Menu\Programs,Recent}}}\**\*.lnk
sources:
  - name: Lnk
    query: |
      SELECT SourceFile.OSPath AS LnkFile,
             SourceFile.Mtime AS LnkModified,
             SourceFile.Btime AS LnkCreated,
             StringData.TargetPath AS TargetPath,
             StringData.Arguments AS Arguments,
             StringData.WorkingDir AS WorkingDir,
             LinkTarget.LinkTarget AS LinkTargetName,
             ShellLinkHeader.CreationTime AS TargetCreated,
             ShellLinkHeader.WriteTime AS TargetModified,
             ShellLinkHeader.AccessTime AS TargetAccessed,
             ShellLinkHeader.FileSize AS TargetSize,
             Suspicious
      FROM Artifact.Windows.Forensics.Lnk(TargetGlob=TargetGlob)
$orcaforensic$, false, true, NOW())
ON CONFLICT (t_code) DO NOTHING;

INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)
VALUES ('FORENSIC_MFT', 'Full NTFS Master File Table timeline from a mounted dead disk. Reads the raw', 'Windows', 'Forensic', $orcaforensic$name: Forensic.Filesystem.MFT
description: |
  Full NTFS Master File Table timeline from a mounted dead disk. Reads the raw
  volume ($MFT) and returns every in-use file record with all four
  $STANDARD_INFORMATION (0x10) timestamps (Created, Modified, MFT-changed,
  Accessed). Raw-NTFS mode: the token :rawdrive is replaced by the agent with the
  real drive letter and the query runs without the dead-disk remap.
type: CLIENT
sources:
- name: MFT
  query: |
    SELECT EntryNumber,
           InUse,
           FileName,
           FileSize,
           OSPath,
           Created0x10 AS SI_Created,
           LastModified0x10 AS SI_Modified,
           LastRecordChange0x10 AS SI_MFTModified,
           LastAccess0x10 AS SI_Accessed
    FROM parse_mft(filename=":rawdrive/$MFT", accessor="ntfs")
    WHERE InUse
$orcaforensic$, false, true, NOW())
ON CONFLICT (t_code) DO NOTHING;

INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)
VALUES ('FORENSIC_PREFETCH', 'Program execution evidence from Windows Prefetch (C:/Windows/Prefetch/*.pf) on a', 'Windows', 'Forensic', $orcaforensic$name: Forensic.Execution.Prefetch
description: |
  Program execution evidence from Windows Prefetch (C:/Windows/Prefetch/*.pf) on a
  mounted dead disk. File mode (mode 1): runs under the dead-disk remap, reading C:
  (= the image). Uses the built-in Windows.Forensics.Prefetch, which parses each .pf
  and reports executable name, run count and the embedded run timestamps.
type: CLIENT
sources:
- name: Prefetch
  query: |
    SELECT OSPath,
           Executable,
           ExecutablePath,
           RunCount,
           CreationTime,
           ModificationTime,
           LastRunTimes[0] AS LastRun,
           LastRunTimes,
           FilesAccessed
    FROM Artifact.Windows.Forensics.Prefetch()
$orcaforensic$, false, true, NOW())
ON CONFLICT (t_code) DO NOTHING;

INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)
VALUES ('FORENSIC_RECENTDOCS', 'Recently opened documents from the per-user RecentDocs registry keys of a', 'Windows', 'Forensic', $orcaforensic$name: Forensic.Execution.RecentDocs
description: |
  Recently opened documents from the per-user RecentDocs registry keys of a
  mounted disk image (dead disk). Enumerates
  HKEY_USERS/<user>/Software/Microsoft/Windows/CurrentVersion/Explorer/RecentDocs
  and its per-extension subkeys; the leading UTF-16LE filename is decoded from
  each binary value. Reports the file name, the owning subkey (file extension /
  "RecentDocs" for the global list), the key write time and the user.
  NOTE: the RecentDocs key is empty on a freshly installed image, so a clean
  disk yields no rows; the query is validated against a clean image.
sources:
- name: RecentDocs
  query: |
    SELECT split(string=utf16(string=Data.value), sep="\x00")[0] AS FileName,
           basename(path=dirname(path=OSPath)) AS SubKey,
           OSPath.Components[1] AS User,
           Mtime AS KeyWriteTime,
           Name AS ValueName,
           OSPath
    FROM glob(globs='HKEY_USERS/*/Software/Microsoft/Windows/CurrentVersion/Explorer/RecentDocs/**',
              accessor='registry')
    WHERE Data.type = "REG_BINARY" AND Name != "MRUListEx"
    ORDER BY User
$orcaforensic$, false, true, NOW())
ON CONFLICT (t_code) DO NOTHING;

INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)
VALUES ('FORENSIC_RECYCLEBIN', 'Deleted-file records recovered from the Recycle Bin $I metadata files', 'Windows', 'Forensic', $orcaforensic$name: Forensic.Windows.RecycleBin
description: |
  Deleted-file records recovered from the Recycle Bin $I metadata files
  (C:/$Recycle.Bin/<SID>/$I*) on a mounted Windows disk image (dead
  disk). Each $I file records the original full path, logical size and
  deletion time of a file a user sent to the Recycle Bin; the matching
  $R file (DeletedContentFile) still holds the recoverable content.

  Wraps the built-in Windows.Forensics.RecycleBin (Vista+ $I format;
  does not parse XP-era INFO2 files).
reference:
  - https://www.magnetforensics.com/blog/artifact-profile-recycle-bin/
sources:
  - name: RecycleBin
    query: |
      SELECT DeletedTimestamp,
             OriginalFilePath,
             FileSize,
             Name AS RecycleId,
             OSPath AS MetadataFile,
             RecyclePath AS DeletedContentFile
      FROM Artifact.Windows.Forensics.RecycleBin()
$orcaforensic$, false, true, NOW())
ON CONFLICT (t_code) DO NOTHING;

INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)
VALUES ('FORENSIC_SCHTASKS', 'Scheduled tasks recovered from a mounted Windows disk image (dead disk).', 'Windows', 'Forensic', $orcaforensic$name: Forensic.System.ScheduledTasks
description: |
  Scheduled tasks recovered from a mounted Windows disk image (dead disk).
  Parses the task XML files under C:/Windows/System32/Tasks (via the built-in
  Windows.System.TaskScheduler) and reports the command each task runs, its
  author, the account it runs as, run level and triggers. The same
  registration metadata is mirrored in the TaskCache registry
  (SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache).
sources:
- name: ScheduledTasks
  query: |
    SELECT TaskName,
           Command,
           Arguments,
           _XML.Task.RegistrationInfo.Author AS Author,
           UserId AS RunAsUser,
           RunLevel,
           _XML.Task.Triggers AS Triggers,
           StartBoundary,
           RegistrationTime,
           Mtime,
           OSPath
    FROM Artifact.Windows.System.TaskScheduler()
    ORDER BY TaskName
$orcaforensic$, false, true, NOW())
ON CONFLICT (t_code) DO NOTHING;

INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)
VALUES ('FORENSIC_SERVICES', 'Installed Windows services and drivers from the SYSTEM hive of a mounted', 'Windows', 'Forensic', $orcaforensic$name: Forensic.System.Services
description: |
  Installed Windows services and drivers from the SYSTEM hive of a mounted
  disk image (dead disk). CurrentControlSet is resolved from
  HKLM/System/Select/Current, then every key under ControlSet00N/Services is
  read for ImagePath, Start type, service type, display name and the account
  it runs as. NonSystemImagePath flags an ImagePath that is not under the
  Windows system directories (a common place to hide a malicious service).
sources:
- name: Services
  query: |
    LET SysRe <= '''(?i)(system32|systemroot|%systemroot%|\\windows\\|\\drivers\\|servicing)'''

    LET StartMap <= dict(`0`="0 - Boot", `1`="1 - System", `2`="2 - Automatic",
                         `3`="3 - Manual", `4`="4 - Disabled")

    LET ControlSet <= SELECT format(format="HKEY_LOCAL_MACHINE/System/ControlSet%03d/Services",
                                   args=Data.value) AS Base
      FROM glob(globs='HKEY_LOCAL_MACHINE/System/Select/Current', accessor='registry')

    SELECT ServiceName, DisplayName, ImagePath, StartType, ServiceType,
           RunAsAccount,
           if(condition=NOT ImagePath =~ SysRe, then=TRUE, else=FALSE) AS NonSystemImagePath,
           KeyModTime, OSPath
    FROM foreach(row=ControlSet, query={
       SELECT basename(path=Key.OSPath) AS ServiceName,
              DisplayName || "" AS DisplayName,
              ImagePath || "" AS ImagePath,
              get(item=StartMap, field=format(format="%d", args=Start || -1))
                || format(format="%d", args=Start || -1) AS StartType,
              Type || -1 AS ServiceType,
              ObjectName || "" AS RunAsAccount,
              Key.FileInfo.ModTime AS KeyModTime,
              Key.OSPath AS OSPath
       FROM read_reg_key(globs=Base + '/*', accessor='registry')
    })
    WHERE ImagePath
    ORDER BY ServiceName
$orcaforensic$, false, true, NOW())
ON CONFLICT (t_code) DO NOTHING;

INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)
VALUES ('FORENSIC_SHELLBAGS', 'Folder-access history (Shellbags) recovered from the per-user', 'Windows', 'Forensic', $orcaforensic$name: Forensic.Windows.Shellbags
description: |
  Folder-access history (Shellbags) recovered from the per-user
  NTUSER.DAT and UsrClass.dat registry hives of a mounted Windows disk
  image (dead disk). Shellbags record folders that were browsed in
  Explorer and persist even after the folder or its files are deleted,
  so they are strong evidence of files/paths that once existed.

  Wraps the built-in Windows.Forensics.Shellbags, which reads the hive
  files directly with the raw registry parser (so it works on an image
  with no logged-on user), and adds a per-user column derived from the
  hive path.
reference:
  - https://www.sans.org/blog/computer-forensic-artifacts-windows-7-shellbags/
sources:
  - name: Shellbags
    query: |
      SELECT regex_replace(source=Hive,
                 re='''(?i).*[\\/]Users[\\/]([^\\/]+)[\\/].*''',
                 replace="$1") AS User,
             FullPath,
             Description.LongName || Description.ShortName || "?" AS FolderName,
             ModTime AS RegModified,
             Hive AS HivePath,
             KeyPath,
             Slot
      FROM Artifact.Windows.Forensics.Shellbags()
$orcaforensic$, false, true, NOW())
ON CONFLICT (t_code) DO NOTHING;

INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)
VALUES ('FORENSIC_SHIMCACHE', 'AppCompatCache (ShimCache) execution evidence from the SYSTEM registry hive on a', 'Windows', 'Forensic', $orcaforensic$name: Forensic.Execution.ShimCache
description: |
  AppCompatCache (ShimCache) execution evidence from the SYSTEM registry hive on a
  mounted dead disk. Registry mode (mode 1): runs under the dead-disk remap and
  reads HKLM/System/ControlSet*/Control/Session Manager/AppCompatCache (= the
  image's SYSTEM hive). Each entry records a program path, its file-modification
  time and an execution flag; Position preserves the cache order (recent first).
type: CLIENT
sources:
- name: ShimCache
  query: |
    SELECT Position,
           Path,
           ModificationTime,
           ExecutionFlag
    FROM Artifact.Windows.Registry.AppCompatCache()
    ORDER BY Position
$orcaforensic$, false, true, NOW())
ON CONFLICT (t_code) DO NOTHING;

INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)
VALUES ('FORENSIC_SRUM', 'Per-application and per-network resource usage from the System Resource Usage', 'Windows', 'Forensic', $orcaforensic$name: Forensic.Windows.SRUM
description: |
  Per-application and per-network resource usage from the System Resource Usage
  Monitor database (Windows/System32/sru/SRUDB.dat) on a mounted dead disk. SRUM
  keeps ~30-60 days of which application ran, when, and how many bytes it moved
  over each network - evidence of execution and data movement.

  SRUDB.dat is an ESE database. When the image was captured from a running system
  the on-disk copy is in a dirty (unflushed) state that the ESE parser refuses, so
  this collection first copies the database and its transaction logs to a temp
  folder and recovers them with the workstation's own esentutl (/r log replay,
  then /p repair). Recovery succeeds when the analyst workstation's Windows is the
  same version as, or newer than, the image's; a newer image (e.g. a Windows 11
  image on a Windows 10 workstation) cannot be recovered with the older esentutl -
  the RecoveryStatus source then says so instead of returning a silent empty
  result. The workstation's own esentutl is used, never a binary from the image.

  Runs off the raw mounted volume (:rawdrive), outside the dead-disk remap, because
  recovery needs to execute esentutl (the remap sandbox disables process execution).
reference:
  - https://github.com/libyal/esedb-kb/blob/main/documentation/System%20Resource%20Usage%20Monitor%20(SRUM).asciidoc
sources:
  - name: ResourceUsage
    query: |
      LET tmp <= tempdir()
      LET copied <= SELECT copy(filename=OSPath, dest=tmp + "/" + Name) AS Dest
         FROM glob(globs=":rawdrive/Windows/System32/sru/SRU*", accessor="auto")
      LET db <= tmp + "/SRUDB.dat"
      -- recover the dirty ESE DB with the host esentutl (no-op on a clean DB)
      LET _r <= SELECT ReturnCode FROM execve(argv=["esentutl.exe", "/r", "sru", "/l", tmp, "/s", tmp, "/i"])
      LET _p <= SELECT ReturnCode FROM execve(argv=["esentutl.exe", "/p", db, "/o"])
      -- SELECT * so the exact table columns (which vary by SRUM table) can't throw
      -- "Symbol not found" and abort; empty when the database is still dirty.
      SELECT * FROM Artifact.Windows.Forensics.SRUM(SRUMLocation=db, accessor="file")
      WHERE _Source =~ "Usage|Connect|Execution"
  - name: RecoveryStatus
    query: |
      LET tmp <= tempdir()
      LET copied <= SELECT copy(filename=OSPath, dest=tmp + "/" + Name) AS Dest
         FROM glob(globs=":rawdrive/Windows/System32/sru/SRU*", accessor="auto")
      LET db <= tmp + "/SRUDB.dat"
      LET rec <= SELECT ReturnCode, Stdout + Stderr AS Out FROM execve(argv=["esentutl.exe", "/r", "sru", "/l", tmp, "/s", tmp, "/i"])
      LET rep <= SELECT ReturnCode, Stdout + Stderr AS Out FROM execve(argv=["esentutl.exe", "/p", db, "/o"])
      LET state = SELECT ReturnCode, Stdout FROM execve(argv=["esentutl.exe", "/mh", db])
      SELECT db AS RecoveredDatabase,
             len(list=copied) AS FilesCopied,
             if(condition=state[0].Stdout =~ "State: *Clean", then="Clean (recovered)", else="Dirty (not recovered)") AS DatabaseState,
             if(condition=state[0].Stdout =~ "State: *Clean", then="SRUM parsed from the recovered database.",
                else="Could not recover the SRUM database on this workstation. It is a dirty ESE database, "
                   + "most likely from a newer Windows version than this workstation (esentutl cannot recover "
                   + "a newer database). Recover it on a matching-or-newer Windows host (esentutl /r sru), then re-run.") AS Note
      FROM scope()
$orcaforensic$, false, true, NOW())
ON CONFLICT (t_code) DO NOTHING;

INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)
VALUES ('FORENSIC_USERASSIST', 'Program-execution evidence from the per-user UserAssist registry keys of a', 'Windows', 'Forensic', $orcaforensic$name: Forensic.Execution.UserAssist
description: |
  Program-execution evidence from the per-user UserAssist registry keys of a
  mounted disk image (dead disk). The ROT13-encoded value names are decoded by
  the built-in Windows.Registry.UserAssist (which reads every NTUSER.DAT under
  the image); reports the decoded program name, run count, last run time and
  the user.
sources:
- name: UserAssist
  query: |
    SELECT Name AS Program,
           NumberOfExecutions AS RunCount,
           LastExecution AS LastRun,
           User
    FROM Artifact.Windows.Registry.UserAssist()
    ORDER BY User
$orcaforensic$, false, true, NOW())
ON CONFLICT (t_code) DO NOTHING;

INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)
VALUES ('FORENSIC_USN', 'NTFS USN change journal ($Extend/$UsnJrnl:$J) from a mounted dead disk: file', 'Windows', 'Forensic', $orcaforensic$name: Forensic.Filesystem.USN
description: |
  NTFS USN change journal ($Extend/$UsnJrnl:$J) from a mounted dead disk: file
  create / delete / rename / write history with per-event timestamp and change
  reason. Raw-NTFS mode: the :rawdrive token is replaced by the agent with the
  real drive letter and the query runs without the dead-disk remap. Uses the
  built-in Windows.Forensics.Usn, which parses the $J stream and reassembles the
  full path for each entry from the $MFT.
type: CLIENT
sources:
- name: USN
  query: |
    SELECT Timestamp,
           Filename,
           OSPath,
           Reason,
           FileAttributes,
           MFTId,
           ParentMFTId,
           Usn
    FROM Artifact.Windows.Forensics.Usn(Device=":rawdrive")
$orcaforensic$, false, true, NOW())
ON CONFLICT (t_code) DO NOTHING;

INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)
VALUES ('FORENSIC_WMI_PERSISTENCE', 'WMI permanent event subscriptions (filters, consumers and their', 'Windows', 'Forensic', $orcaforensic$name: Forensic.Windows.WMIPersistence
description: |
  WMI permanent event subscriptions (filters, consumers and their
  bindings) recovered directly from the WMI repository
  (C:/Windows/System32/wbem/Repository/OBJECTS.DATA) on a mounted
  Windows disk image (dead disk).

  The built-in Windows.Persistence.PermanentWMIEvents queries the LIVE
  WMI service (wmi() plugin), which is disabled under the dead-disk
  remap and would read the analyst host rather than the image. Instead
  this artifact carves OBJECTS.DATA with parse_records_with_regex, the
  standard dead-disk technique: __FilterToConsumerBinding records store
  the consumer type/name and the bound __EventFilter name adjacently,
  and __EventFilter records store the WQL trigger query, so both are
  recovered by regex without a running WMI service.

  Every clean Windows image has one benign subscription (the "SCM Event
  Log Consumer" NTEventLogEventConsumer bound to the "SCM Event Log
  Filter"); a CommandLineEventConsumer or ActiveScriptEventConsumer with
  a script/command body (the ScriptedConsumers source) is the classic
  WMI persistence red flag (ATT&CK T1546.003).
reference:
  - https://attack.mitre.org/techniques/T1546/003/
  - https://github.com/davidpany/WMI_Forensics
parameters:
  - name: RepositoryPath
    default: C:/Windows/System32/wbem/Repository/OBJECTS.DATA
sources:
  - name: FilterToConsumerBinding
    description: Consumer/filter bindings, each enriched with the filter's WQL query.
    query: |
      LET Repo = RepositoryPath
      LET RepoStat <= SELECT Mtime FROM stat(filename=Repo, accessor="auto")
      LET Filters = SELECT FilterName, Query
        FROM parse_records_with_regex(file=Repo, accessor="auto",
          regex='''(?P<FilterName>[\x20-\x7e]{3,100})[\x00-\x1f]+(?P<Query>(?i:select)[\s\S]{3,400}?)[\x00-\x1f]+WQL''')
      LET FilterMap <= to_dict(item={
          SELECT FilterName AS _key, Query AS _value FROM Filters
      })
      SELECT ConsumerType,
             ConsumerName,
             FilterName,
             get(item=FilterMap, field=FilterName) AS FilterQuery,
             Repo AS Repository,
             RepoStat[0].Mtime AS RepositoryModified
      FROM parse_records_with_regex(file=Repo, accessor="auto",
          regex='''(?P<ConsumerType>[A-Za-z]+EventConsumer)\.Name="(?P<ConsumerName>[^"]{1,200})"[\x00-\xff]{0,120}?__EventFilter\.Name="(?P<FilterName>[^"]{1,200})"''')
  - name: EventFilters
    description: All __EventFilter trigger queries (WQL) found in the repository.
    query: |
      LET Repo = RepositoryPath
      LET RepoStat <= SELECT Mtime FROM stat(filename=Repo, accessor="auto")
      SELECT FilterName,
             Query,
             Repo AS Repository,
             RepoStat[0].Mtime AS RepositoryModified
      FROM parse_records_with_regex(file=Repo, accessor="auto",
          regex='''(?P<FilterName>[\x20-\x7e]{3,100})[\x00-\x1f]+(?P<Query>(?i:select)[\s\S]{3,400}?)[\x00-\x1f]+WQL''')
  - name: Consumers
    description: |
      Every __EventConsumer instance (by its Type.Name="..." reference),
      with the script/command body for scripted consumers. The
      ScriptOrCommand column is populated for ActiveScriptEventConsumer
      (ScriptText) and CommandLineEventConsumer (command line) instances
      - the classic WMI persistence payload (ATT&CK T1546.003) - and is
      null for benign consumers such as the NTEventLogEventConsumer that
      every clean image carries.
    query: |
      LET Repo = RepositoryPath
      LET RepoStat <= SELECT Mtime FROM stat(filename=Repo, accessor="auto")
      LET ScriptMap <= to_dict(item={
          SELECT ConsumerName AS _key, ScriptOrCommand AS _value
          FROM parse_records_with_regex(file=Repo, accessor="auto",
              regex='''(?P<ConsumerType>ActiveScriptEventConsumer|CommandLineEventConsumer)\.Name="(?P<ConsumerName>[^"]{1,200})"[\x00-\xff]{0,40}?(?P<ScriptOrCommand>[\x20-\x7e]{5,800})''')
      })
      SELECT ConsumerType,
             ConsumerName,
             get(item=ScriptMap, field=ConsumerName) AS ScriptOrCommand,
             Repo AS Repository,
             RepoStat[0].Mtime AS RepositoryModified
      FROM parse_records_with_regex(file=Repo, accessor="auto",
          regex='''(?P<ConsumerType>[A-Za-z]+EventConsumer)\.Name="(?P<ConsumerName>[^"]{1,200})"''')
      GROUP BY ConsumerType, ConsumerName
$orcaforensic$, false, true, NOW())
ON CONFLICT (t_code) DO NOTHING;
