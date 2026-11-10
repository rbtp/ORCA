-- Replace 7 artifact-library techniques that could never run on a Windows
-- host (2026-11-10):
--   T1597, T1597.002  glob(globs='a', 'b') syntax error; now read matching
--                     sites from Chrome/Edge/Firefox history
--   T1574.013         used intbitand() (doesn't exist in VQL); VM_WRITE bit
--                     now tested arithmetically
--   T1555.006, T1578, T1619, T1599.001  read cloud/network-device logs through
--                     variables that are never defined; now collect the
--                     host-side evidence: cloud CLI / PowerShell commands
--                     (Sysmon 1, Security 4688, PowerShell 4104, PSReadLine
--                     history), cloud credential files, portproxy/forwarding
--                     registry settings
-- A row is only replaced while it still holds the original seed text, so a
-- technique an analyst has edited is left alone.

UPDATE ref_artifact_library
SET custom_vql = NULL,
    surgical_yaml = $orca$name: Windows.Detection.CloudSecretsAccess
description: |
  T1555.006 Cloud Secrets Management Stores, from the Windows host: cloud CLI /
  PowerShell commands that read secrets (AWS Secrets Manager / SSM, Azure Key
  Vault, GCP Secret Manager, HashiCorp Vault) and the cloud credential files
  those tools leave in user profiles.
sources:
  - name: SysmonProcessCreation
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.User AS User, EventData.Image AS Image, EventData.CommandLine AS CommandLine,
             EventData.ParentImage AS ParentImage
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 1 AND EventData.CommandLine =~ '(?i)(secretsmanager[ ]+(get-secret-value|list-secrets|batch-get-secret-value)|ssm[ ]+get-parameters?[ ]+.*--with-decryption|keyvault[ ]+secret[ ]+(show|download|list)|gcloud[ ]+secrets[ ]+(versions[ ]+access|list)|Get-(AzKeyVaultSecret|SECSecretValue|SECSecretList|SSMParameter)|vault(.exe)?[ ]+(kv[ ]+get|read)[ ]+)'
  - name: SecurityProcessCreation
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.SubjectUserName AS User, EventData.NewProcessName AS Image,
             EventData.CommandLine AS CommandLine, EventData.ParentProcessName AS ParentImage
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value = 4688 AND EventData.CommandLine =~ '(?i)(secretsmanager[ ]+(get-secret-value|list-secrets|batch-get-secret-value)|ssm[ ]+get-parameters?[ ]+.*--with-decryption|keyvault[ ]+secret[ ]+(show|download|list)|gcloud[ ]+secrets[ ]+(versions[ ]+access|list)|Get-(AzKeyVaultSecret|SECSecretValue|SECSecretList|SSMParameter)|vault(.exe)?[ ]+(kv[ ]+get|read)[ ]+)'
  - name: PowerShellScriptBlocks
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.ScriptBlockId AS ScriptBlockId, EventData.Path AS ScriptPath,
             EventData.ScriptBlockText AS ScriptBlockText
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
      WHERE System.EventID.Value = 4104 AND EventData.ScriptBlockText =~ '(?i)(secretsmanager[ ]+(get-secret-value|list-secrets|batch-get-secret-value)|ssm[ ]+get-parameters?[ ]+.*--with-decryption|keyvault[ ]+secret[ ]+(show|download|list)|gcloud[ ]+secrets[ ]+(versions[ ]+access|list)|Get-(AzKeyVaultSecret|SECSecretValue|SECSecretList|SSMParameter)|vault(.exe)?[ ]+(kv[ ]+get|read)[ ]+)'
  - name: PowerShellHistory
    query: |
      SELECT * FROM foreach(
        row={ SELECT OSPath FROM glob(globs='C:/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt') },
        query={ SELECT OSPath AS HistoryFile, Line FROM parse_lines(filename=OSPath) WHERE Line =~ '(?i)(secretsmanager[ ]+(get-secret-value|list-secrets|batch-get-secret-value)|ssm[ ]+get-parameters?[ ]+.*--with-decryption|keyvault[ ]+secret[ ]+(show|download|list)|gcloud[ ]+secrets[ ]+(versions[ ]+access|list)|Get-(AzKeyVaultSecret|SECSecretValue|SECSecretList|SSMParameter)|vault(.exe)?[ ]+(kv[ ]+get|read)[ ]+)' })
  - name: CloudCredentialFiles
    query: |
      SELECT OSPath, Size, Mtime, Btime
      FROM glob(globs=['C:/Users/*/.aws/credentials', 'C:/Users/*/.aws/config',
                       'C:/Users/*/.azure/msal_token_cache.*', 'C:/Users/*/.azure/accessTokens.json',
                       'C:/Users/*/.azure/azureProfile.json',
                       'C:/Users/*/AppData/Roaming/gcloud/credentials.db',
                       'C:/Users/*/AppData/Roaming/gcloud/access_tokens.db',
                       'C:/Users/*/AppData/Roaming/gcloud/application_default_credentials.json'])
$orca$,
    updated_at = NOW()
WHERE t_code = 'T1555.006'
  AND md5(coalesce(custom_vql, '') || '|' || coalesce(surgical_yaml, '')) = 'f66abc96cb886a7a2ec315629a0b0876';

UPDATE ref_artifact_library
SET custom_vql = NULL,
    surgical_yaml = $orca$name: Windows.Detection.ModifyCloudComputeInfrastructure
description: |
  T1578 Modify Cloud Compute Infrastructure, from the Windows host: AWS / Azure /
  GCP CLI and PowerShell commands that create, delete, snapshot or modify
  instances, disks, snapshots and images.
sources:
  - name: SysmonProcessCreation
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.User AS User, EventData.Image AS Image, EventData.CommandLine AS CommandLine,
             EventData.ParentImage AS ParentImage
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 1 AND EventData.CommandLine =~ '(?i)(ec2[ ]+(run-instances|terminate-instances|modify-instance-attribute|create-snapshot|delete-snapshot|create-volume|delete-volume|modify-snapshot-attribute|create-image|copy-snapshot)|(^|[ /])az(.cmd)?[ ]+(vm|disk|snapshot|image)[ ]+(create|delete|update|deallocate|grant-access)|gcloud[ ]+compute[ ]+(instances|disks|snapshots|images)[ ]+(create|delete|snapshot)|(New|Remove|Update)-(AzVM|AzDisk|AzSnapshot|AzImage)([ ]|$)|(New|Remove|Edit)-EC2(Instance|Snapshot|Volume|Image)([ ]|$)|Grant-AzSnapshotAccess)'
  - name: SecurityProcessCreation
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.SubjectUserName AS User, EventData.NewProcessName AS Image,
             EventData.CommandLine AS CommandLine, EventData.ParentProcessName AS ParentImage
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value = 4688 AND EventData.CommandLine =~ '(?i)(ec2[ ]+(run-instances|terminate-instances|modify-instance-attribute|create-snapshot|delete-snapshot|create-volume|delete-volume|modify-snapshot-attribute|create-image|copy-snapshot)|(^|[ /])az(.cmd)?[ ]+(vm|disk|snapshot|image)[ ]+(create|delete|update|deallocate|grant-access)|gcloud[ ]+compute[ ]+(instances|disks|snapshots|images)[ ]+(create|delete|snapshot)|(New|Remove|Update)-(AzVM|AzDisk|AzSnapshot|AzImage)([ ]|$)|(New|Remove|Edit)-EC2(Instance|Snapshot|Volume|Image)([ ]|$)|Grant-AzSnapshotAccess)'
  - name: PowerShellScriptBlocks
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.ScriptBlockId AS ScriptBlockId, EventData.Path AS ScriptPath,
             EventData.ScriptBlockText AS ScriptBlockText
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
      WHERE System.EventID.Value = 4104 AND EventData.ScriptBlockText =~ '(?i)(ec2[ ]+(run-instances|terminate-instances|modify-instance-attribute|create-snapshot|delete-snapshot|create-volume|delete-volume|modify-snapshot-attribute|create-image|copy-snapshot)|(^|[ /])az(.cmd)?[ ]+(vm|disk|snapshot|image)[ ]+(create|delete|update|deallocate|grant-access)|gcloud[ ]+compute[ ]+(instances|disks|snapshots|images)[ ]+(create|delete|snapshot)|(New|Remove|Update)-(AzVM|AzDisk|AzSnapshot|AzImage)([ ]|$)|(New|Remove|Edit)-EC2(Instance|Snapshot|Volume|Image)([ ]|$)|Grant-AzSnapshotAccess)'
  - name: PowerShellHistory
    query: |
      SELECT * FROM foreach(
        row={ SELECT OSPath FROM glob(globs='C:/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt') },
        query={ SELECT OSPath AS HistoryFile, Line FROM parse_lines(filename=OSPath) WHERE Line =~ '(?i)(ec2[ ]+(run-instances|terminate-instances|modify-instance-attribute|create-snapshot|delete-snapshot|create-volume|delete-volume|modify-snapshot-attribute|create-image|copy-snapshot)|(^|[ /])az(.cmd)?[ ]+(vm|disk|snapshot|image)[ ]+(create|delete|update|deallocate|grant-access)|gcloud[ ]+compute[ ]+(instances|disks|snapshots|images)[ ]+(create|delete|snapshot)|(New|Remove|Update)-(AzVM|AzDisk|AzSnapshot|AzImage)([ ]|$)|(New|Remove|Edit)-EC2(Instance|Snapshot|Volume|Image)([ ]|$)|Grant-AzSnapshotAccess)' })
$orca$,
    updated_at = NOW()
WHERE t_code = 'T1578'
  AND md5(coalesce(custom_vql, '') || '|' || coalesce(surgical_yaml, '')) = '66d3999b8d28e6d4a2c9362154f7c169';

UPDATE ref_artifact_library
SET custom_vql = NULL,
    surgical_yaml = $orca$name: Windows.Detection.CloudStorageObjectDiscovery
description: |
  T1619 Cloud Storage Object Discovery, from the Windows host: commands that
  enumerate buckets, containers and objects (AWS S3, Azure Storage, GCS,
  azcopy, rclone).
sources:
  - name: SysmonProcessCreation
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.User AS User, EventData.Image AS Image, EventData.CommandLine AS CommandLine,
             EventData.ParentImage AS ParentImage
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 1 AND EventData.CommandLine =~ '(?i)((^|[ /])aws(.exe)?[ ]+s3[ ]+ls|s3api[ ]+(list-objects|list-objects-v2|list-buckets|list-object-versions|get-bucket-acl|get-bucket-location)|(^|[ /])az(.cmd)?[ ]+storage[ ]+(blob|container|share|account|fs)[ ]+list|gsutil(.cmd)?[ ]+ls|gcloud[ ]+storage[ ]+(ls|buckets[ ]+list|objects[ ]+list)|Get-(S3Object|S3Bucket|AzStorageBlob|AzStorageContainer|AzStorageAccount|GcsObject|GcsBucket)([ ]|$)|azcopy(.exe)?[ ]+(list|ls)|rclone(.exe)?[ ]+(ls|lsd|lsf|lsl)[ ]+)'
  - name: SecurityProcessCreation
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.SubjectUserName AS User, EventData.NewProcessName AS Image,
             EventData.CommandLine AS CommandLine, EventData.ParentProcessName AS ParentImage
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value = 4688 AND EventData.CommandLine =~ '(?i)((^|[ /])aws(.exe)?[ ]+s3[ ]+ls|s3api[ ]+(list-objects|list-objects-v2|list-buckets|list-object-versions|get-bucket-acl|get-bucket-location)|(^|[ /])az(.cmd)?[ ]+storage[ ]+(blob|container|share|account|fs)[ ]+list|gsutil(.cmd)?[ ]+ls|gcloud[ ]+storage[ ]+(ls|buckets[ ]+list|objects[ ]+list)|Get-(S3Object|S3Bucket|AzStorageBlob|AzStorageContainer|AzStorageAccount|GcsObject|GcsBucket)([ ]|$)|azcopy(.exe)?[ ]+(list|ls)|rclone(.exe)?[ ]+(ls|lsd|lsf|lsl)[ ]+)'
  - name: PowerShellScriptBlocks
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.ScriptBlockId AS ScriptBlockId, EventData.Path AS ScriptPath,
             EventData.ScriptBlockText AS ScriptBlockText
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
      WHERE System.EventID.Value = 4104 AND EventData.ScriptBlockText =~ '(?i)((^|[ /])aws(.exe)?[ ]+s3[ ]+ls|s3api[ ]+(list-objects|list-objects-v2|list-buckets|list-object-versions|get-bucket-acl|get-bucket-location)|(^|[ /])az(.cmd)?[ ]+storage[ ]+(blob|container|share|account|fs)[ ]+list|gsutil(.cmd)?[ ]+ls|gcloud[ ]+storage[ ]+(ls|buckets[ ]+list|objects[ ]+list)|Get-(S3Object|S3Bucket|AzStorageBlob|AzStorageContainer|AzStorageAccount|GcsObject|GcsBucket)([ ]|$)|azcopy(.exe)?[ ]+(list|ls)|rclone(.exe)?[ ]+(ls|lsd|lsf|lsl)[ ]+)'
  - name: PowerShellHistory
    query: |
      SELECT * FROM foreach(
        row={ SELECT OSPath FROM glob(globs='C:/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt') },
        query={ SELECT OSPath AS HistoryFile, Line FROM parse_lines(filename=OSPath) WHERE Line =~ '(?i)((^|[ /])aws(.exe)?[ ]+s3[ ]+ls|s3api[ ]+(list-objects|list-objects-v2|list-buckets|list-object-versions|get-bucket-acl|get-bucket-location)|(^|[ /])az(.cmd)?[ ]+storage[ ]+(blob|container|share|account|fs)[ ]+list|gsutil(.cmd)?[ ]+ls|gcloud[ ]+storage[ ]+(ls|buckets[ ]+list|objects[ ]+list)|Get-(S3Object|S3Bucket|AzStorageBlob|AzStorageContainer|AzStorageAccount|GcsObject|GcsBucket)([ ]|$)|azcopy(.exe)?[ ]+(list|ls)|rclone(.exe)?[ ]+(ls|lsd|lsf|lsl)[ ]+)' })
$orca$,
    updated_at = NOW()
WHERE t_code = 'T1619'
  AND md5(coalesce(custom_vql, '') || '|' || coalesce(surgical_yaml, '')) = '54751b92b5c6abc84d780118c68aa88a';

UPDATE ref_artifact_library
SET custom_vql = NULL,
    surgical_yaml = $orca$name: Windows.Detection.NATTraversal
description: |
  T1599.001 NAT Traversal, from the Windows host: port-proxy / NAT / IP
  forwarding set up on the machine (netsh portproxy, NetNat, routing) and the
  registry settings that persist it.
sources:
  - name: SysmonProcessCreation
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.User AS User, EventData.Image AS Image, EventData.CommandLine AS CommandLine,
             EventData.ParentImage AS ParentImage
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 1 AND EventData.CommandLine =~ '(?i)(netsh(.exe)?[ ]+(interface[ ]+portproxy[ ]+(add|set)|routing[ ]+ip[ ]+nat|interface[ ]+ipv4[ ]+set[ ]+interface[ ]+.*forwarding=enabled)|(New|Add)-NetNat|Set-NetIPInterface[ ]+.*-Forwarding[ ]+Enabled|IPEnableRouter)'
  - name: SecurityProcessCreation
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.SubjectUserName AS User, EventData.NewProcessName AS Image,
             EventData.CommandLine AS CommandLine, EventData.ParentProcessName AS ParentImage
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value = 4688 AND EventData.CommandLine =~ '(?i)(netsh(.exe)?[ ]+(interface[ ]+portproxy[ ]+(add|set)|routing[ ]+ip[ ]+nat|interface[ ]+ipv4[ ]+set[ ]+interface[ ]+.*forwarding=enabled)|(New|Add)-NetNat|Set-NetIPInterface[ ]+.*-Forwarding[ ]+Enabled|IPEnableRouter)'
  - name: PowerShellScriptBlocks
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.ScriptBlockId AS ScriptBlockId, EventData.Path AS ScriptPath,
             EventData.ScriptBlockText AS ScriptBlockText
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
      WHERE System.EventID.Value = 4104 AND EventData.ScriptBlockText =~ '(?i)(netsh(.exe)?[ ]+(interface[ ]+portproxy[ ]+(add|set)|routing[ ]+ip[ ]+nat|interface[ ]+ipv4[ ]+set[ ]+interface[ ]+.*forwarding=enabled)|(New|Add)-NetNat|Set-NetIPInterface[ ]+.*-Forwarding[ ]+Enabled|IPEnableRouter)'
  - name: PowerShellHistory
    query: |
      SELECT * FROM foreach(
        row={ SELECT OSPath FROM glob(globs='C:/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt') },
        query={ SELECT OSPath AS HistoryFile, Line FROM parse_lines(filename=OSPath) WHERE Line =~ '(?i)(netsh(.exe)?[ ]+(interface[ ]+portproxy[ ]+(add|set)|routing[ ]+ip[ ]+nat|interface[ ]+ipv4[ ]+set[ ]+interface[ ]+.*forwarding=enabled)|(New|Add)-NetNat|Set-NetIPInterface[ ]+.*-Forwarding[ ]+Enabled|IPEnableRouter)' })
  - name: PortProxyRules
    query: |
      SELECT OSPath AS Key, Name AS Listen, Data.value AS ConnectTo, Mtime
      FROM glob(globs='HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/PortProxy/**', accessor='registry')
      WHERE NOT IsDir
  - name: IPForwarding
    query: |
      SELECT OSPath AS Key, Name, Data.value AS Value, Mtime
      FROM glob(globs='HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/Tcpip/Parameters/IPEnableRouter', accessor='registry')
      WHERE Data.value = 1
$orca$,
    updated_at = NOW()
WHERE t_code = 'T1599.001'
  AND md5(coalesce(custom_vql, '') || '|' || coalesce(surgical_yaml, '')) = '6e5be27bd7968e189cf99dac9894620e';

UPDATE ref_artifact_library
SET custom_vql = $orca$SELECT * FROM chain(
  chromium={ SELECT * FROM foreach(
    row={ SELECT OSPath FROM glob(globs=['C:/Users/*/AppData/Local/Google/Chrome/User Data/*/History',
                                         'C:/Users/*/AppData/Local/Microsoft/Edge/User Data/*/History']) },
    query={ SELECT OSPath AS HistoryFile, url AS URL, title AS Title, visit_count AS Visits,
                   timestamp(winfiletime=last_visit_time * 10) AS LastVisit
            FROM sqlite(file=OSPath, query='SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 2000')
            WHERE URL =~ '(?i)^https?://([^/]*[.])?(shodan|censys|zoomeye|fofa|binaryedge|greynoise|intelx|dehashed|leakcheck|snusbase|haveibeenpwned|exploit-db|virustotal|hybrid-analysis|recordedfuture|maltego|criminalip|netlas|hunter|leakix)[.]' }) },
  firefox={ SELECT * FROM foreach(
    row={ SELECT OSPath FROM glob(globs='C:/Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite') },
    query={ SELECT OSPath AS HistoryFile, url AS URL, title AS Title, visit_count AS Visits,
                   timestamp(epoch=last_visit_date / 1000000) AS LastVisit
            FROM sqlite(file=OSPath, query='SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 2000')
            WHERE URL =~ '(?i)^https?://([^/]*[.])?(shodan|censys|zoomeye|fofa|binaryedge|greynoise|intelx|dehashed|leakcheck|snusbase|haveibeenpwned|exploit-db|virustotal|hybrid-analysis|recordedfuture|maltego|criminalip|netlas|hunter|leakix)[.]' }) })$orca$,
    surgical_yaml = NULL,
    updated_at = NOW()
WHERE t_code = 'T1597'
  AND md5(coalesce(custom_vql, '') || '|' || coalesce(surgical_yaml, '')) = 'ea039d22771f5aab84cb62b9f221f443';

UPDATE ref_artifact_library
SET custom_vql = $orca$SELECT * FROM chain(
  chromium={ SELECT * FROM foreach(
    row={ SELECT OSPath FROM glob(globs=['C:/Users/*/AppData/Local/Google/Chrome/User Data/*/History',
                                         'C:/Users/*/AppData/Local/Microsoft/Edge/User Data/*/History']) },
    query={ SELECT OSPath AS HistoryFile, url AS URL, title AS Title, visit_count AS Visits,
                   timestamp(winfiletime=last_visit_time * 10) AS LastVisit
            FROM sqlite(file=OSPath, query='SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 2000')
            WHERE URL =~ '(?i)^https?://([^/]*[.])?(breachforums|exploit|xss|cracked|nulled|leakbase|russianmarket|2easy|bidencash|dehashed|snusbase|leakcheck|intelx|zerodium|crdpro)[.]' }) },
  firefox={ SELECT * FROM foreach(
    row={ SELECT OSPath FROM glob(globs='C:/Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite') },
    query={ SELECT OSPath AS HistoryFile, url AS URL, title AS Title, visit_count AS Visits,
                   timestamp(epoch=last_visit_date / 1000000) AS LastVisit
            FROM sqlite(file=OSPath, query='SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 2000')
            WHERE URL =~ '(?i)^https?://([^/]*[.])?(breachforums|exploit|xss|cracked|nulled|leakbase|russianmarket|2easy|bidencash|dehashed|snusbase|leakcheck|intelx|zerodium|crdpro)[.]' }) })$orca$,
    surgical_yaml = NULL,
    updated_at = NOW()
WHERE t_code = 'T1597.002'
  AND md5(coalesce(custom_vql, '') || '|' || coalesce(surgical_yaml, '')) = 'ea039d22771f5aab84cb62b9f221f443';

UPDATE ref_artifact_library
SET custom_vql = NULL,
    surgical_yaml = $orca$name: Windows.Detection.KernelCallbackTableHijack
description: Detect KernelCallbackTable hijacking through process access with VM_WRITE to GUI processes and correlated process behavior
sources:
  - name: WriteProcessMemoryEvents
    query: |
      LET HasVmWrite(a) = int(int=int(int=a) / 32) - 2 * int(int=int(int=a) / 64) = 1
      SELECT System.TimeCreated.SystemTime AS Timestamp, EventData.SourceProcessId AS SourceProcessId,
             EventData.SourceImage AS SourceImage, EventData.TargetProcessId AS TargetProcessId,
             EventData.TargetImage AS TargetImage, EventData.GrantedAccess AS GrantedAccess, EventData.CallTrace AS CallTrace
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 10 AND EventData.TargetImage =~ '(?i)(explorer|notepad|calc)[.]exe$'
        AND HasVmWrite(a=EventData.GrantedAccess)
  - name: ProcessCreationEvents
    query: |
      SELECT System.TimeCreated.SystemTime AS Timestamp, EventData.ProcessId AS ProcessId, EventData.Image AS Image,
             EventData.CommandLine AS CommandLine, EventData.ParentProcessId AS ParentProcessId, EventData.ParentImage AS ParentImage
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 1 AND EventData.ParentImage =~ '(?i)(explorer|notepad|calc)[.]exe$'
        AND NOT EventData.Image =~ '(?i)(explorer|notepad|calc|conhost|werfault)[.]exe$'
  - name: NetworkConnections
    query: |
      SELECT System.TimeCreated.SystemTime AS Timestamp, EventData.ProcessId AS ProcessId, EventData.Image AS Image,
             EventData.DestinationIp AS DestinationIp, EventData.DestinationPort AS DestinationPort
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 3 AND EventData.Image =~ '(?i)(notepad|calc)[.]exe$'
$orca$,
    updated_at = NOW()
WHERE t_code = 'T1574.013'
  AND md5(coalesce(custom_vql, '') || '|' || coalesce(surgical_yaml, '')) = 'f7abac02a62589be1398ada07ca20fa2';
