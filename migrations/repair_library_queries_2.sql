-- Round 2 of the artifact-library repair (see docs/LIBRARY_QUALITY.md): hand-written repairs of the
-- queries the automatic repair could not fix or had to hold back (too broad), each tested against the
-- Atomic Red Team attack VM's disk and checked for noise on a normal workstation.
-- A column is replaced only while it still holds the original seed text or the round-1 repaired text
-- (md5 guard, line endings ignored): queries edited in the Artifact Library Editor are kept.

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.NTDS.CredentialDumping
description: Detect NTDS.dit credential dumping through process monitoring, file access, and VSS activity
sources:
- name: ProcessCreation
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.NewProcessName AS ProcessName, EventData.CommandLine AS CommandLine,
           EventData.ParentProcessName AS ParentProcess, EventData.SubjectUserName AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688 AND
          (EventData.NewProcessName =~ '''(?i)\\(ntdsutil|diskshadow)\.exe$''' OR
           EventData.CommandLine =~ '''(?i)(vssadmin.*create\s+shadow|shadowcopy\s+call\s+create|ntdsutil.*(ifm|ac.*i.*ntds)|esentutl.*ntds|HarddiskVolumeShadowCopy.*(ntds|SYSTEM|SAM))''')
- name: FileAccess
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           System.EventID.Value AS EventID, EventData.Image AS ProcessImage, EventData.TargetFilename AS TargetFilename
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value IN (2, 11) AND
          EventData.TargetFilename =~ '''(?i)ntds\.dit$'''
- name: VSSActivity
  query: |
    -- Security 8222 (provider VSSAudit): "A shadow copy was created"; Data = [SID, user, PID, process, ..., volume, shadow device]
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
           EventData.Data[1] AS User, EventData.Data[3] AS Process, EventData.Data[9] AS ShadowDevice
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 8222 AND System.Provider.Name = 'VSSAudit'
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1003.003' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('68348d73269e7f83d91f8a88d4b391af', 'f99bb2f02528f3ba129c23462e974074');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.DirectVolumeAccess
description: Detect direct volume / raw disk access (\.\C:, \.\PhysicalDriveN, shadow copy devices) that bypasses file system monitoring
sources:
- name: SysmonProcessCreation
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.Image AS ProcessName, EventData.CommandLine AS CommandLine,
           EventData.ParentImage AS ParentProcess, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.CommandLine =~ '''(?i)\x5c\x5c[.?]\x5c(PhysicalDrive\d+|[a-z]:(\x5c?["']|[^\x5ca-z0-9]|$)|HarddiskVolume\d+([^\x5c\d]|$)|GLOBALROOT\x5cDevice\x5cHarddiskVolumeShadowCopy)'''
           OR EventData.Image =~ '''(?i)\x5c(dd|rawcopy(64)?|ninjacopy)\.exe$''')
- name: SecurityProcessCreation
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.NewProcessName AS ProcessName, EventData.CommandLine AS CommandLine,
           EventData.ParentProcessName AS ParentProcess, EventData.SubjectUserName AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688
      AND (EventData.CommandLine =~ '''(?i)\x5c\x5c[.?]\x5c(PhysicalDrive\d+|[a-z]:(\x5c?["']|[^\x5ca-z0-9]|$)|HarddiskVolume\d+([^\x5c\d]|$)|GLOBALROOT\x5cDevice\x5cHarddiskVolumeShadowCopy)'''
           OR EventData.NewProcessName =~ '''(?i)\x5c(dd|rawcopy(64)?|ninjacopy)\.exe$''')
- name: PowerShellScriptBlocks
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.ScriptBlockText AS ScriptBlock, EventData.Path AS ScriptPath
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
    WHERE System.EventID.Value = 4104
      AND EventData.ScriptBlockText =~ '''(?i)\x5c\x5c[.?]\x5c(PhysicalDrive\d+|[a-z]:(\x5c?["']|[^\x5ca-z0-9]|$)|HarddiskVolume\d+([^\x5c\d]|$))'''
      AND EventData.ScriptBlockText =~ '''(?i)(FileStream|CreateFile|ReadFile|Get-ForensicFile|Invoke-NinjaCopy)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1006' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('f3c446982cb5000f9022534b8e19f172', '8ef76a155fdf4deba4172dfadf445bd4');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentProcess, EventData.User AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND (EventData.CommandLine =~ '''(?i)\x5c\x5c[.?]\x5c(PhysicalDrive\d+|[a-z]:(\x5c?["']|[^\x5ca-z0-9]|$)|HarddiskVolume\d+([^\x5c\d]|$)|GLOBALROOT\x5cDevice\x5cHarddiskVolumeShadowCopy)''' OR EventData.Image =~ '''(?i)\x5c(dd|rawcopy(64)?|ninjacopy)\.exe$''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1006' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('73de8deb7a519c07e4bf066a1fc23149');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.TrafficDuplication
description: |
  Traffic duplication (ATT&CK T1020.001) is configured on cloud or network devices, so ATT&CK's data sources
  are cloud/network logs, not the host. The one host-side trace is an admin workstation issuing the
  mirroring commands (cloud CLIs / PowerShell modules, network-device sessions). The old query read
  cloudtrail.csv / network-config.txt / a Linux syslog through artifacts that don't exist (verify failed).
sources:
- name: MirrorCommandsSysmon
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.Image AS Process, EventData.CommandLine AS CommandLine, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.CommandLine =~ '''(?i)(create-traffic-mirror-(session|target|filter)|modify-traffic-mirror|New-EC2TrafficMirror|az network vnet-tap|New-AzVirtualNetworkTap|gcloud compute packet-mirrorings|monitor session \d+ (source|destination))'''
- name: MirrorCommandsSecurity
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.NewProcessName AS Process, EventData.CommandLine AS CommandLine, EventData.SubjectUserName AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688
      AND EventData.CommandLine =~ '''(?i)(create-traffic-mirror-(session|target|filter)|modify-traffic-mirror|New-EC2TrafficMirror|az network vnet-tap|New-AzVirtualNetworkTap|gcloud compute packet-mirrorings|monitor session \d+ (source|destination))'''
- name: MirrorCommandsPowerShell
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.Path AS Script, EventData.ScriptBlockText AS ScriptBlock
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
    WHERE System.EventID.Value = 4104
      AND EventData.ScriptBlockText =~ '''(?i)(New-EC2TrafficMirror|New-AzVirtualNetworkTap|create-traffic-mirror-session|packet-mirrorings create)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1020.001' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('155144ff28a57b8b62b0191bfc0d1bf7');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, EventData.Image AS Process, EventData.CommandLine AS CommandLine, EventData.User AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND EventData.CommandLine =~ '''(?i)(create-traffic-mirror-(session|target|filter)|modify-traffic-mirror|New-EC2TrafficMirror|az network vnet-tap|New-AzVirtualNetworkTap|gcloud compute packet-mirrorings|monitor session \d+ (source|destination))'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1020.001' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('9d1d5e65a2d48311112ed25dbf707430');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.BinaryPadding
description: |
  Detects padded binaries (ATT&CK T1027.001): unusually large executables written to or run from
  temp / download / public folders (where installed software doesn't live), one row per binary.
  file() doesn't exist in VQL (stat(filename=...) does); file creation is Sysmon 11 TargetFilename, not Image.
sources:
- name: LargeBinaryCreation
  query: |
    SELECT min(item=System.TimeCreated.SystemTime) AS FirstSeen, System.Computer AS Computer,
           EventData.Image AS CreatingProcess, EventData.TargetFilename AS FilePath,
           stat(filename=EventData.TargetFilename).Size AS FileSize, count() AS Writes
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 11
      AND EventData.TargetFilename =~ '''(?i)\.(exe|dll|scr|bin|com)$'''
      AND EventData.TargetFilename =~ '''(?i)\\(appdata\\local\\temp|windows\\temp|users\\public|downloads|perflogs)\\'''
      AND FileSize > 10485760
    GROUP BY FilePath
- name: LargeBinaryExecution
  query: |
    SELECT min(item=System.TimeCreated.SystemTime) AS FirstSeen, System.Computer AS Computer,
           EventData.Image AS ImagePath, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage,
           EventData.Hashes AS Hashes, stat(filename=EventData.Image).Size AS FileSize, count() AS Runs
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.Image =~ '''(?i)\\(appdata\\local\\temp|windows\\temp|users\\public|downloads|perflogs)\\'''
      AND FileSize > 10485760
    GROUP BY ImagePath
- name: LargeBinaryExecutionSecurity
  query: |
    SELECT min(item=System.TimeCreated.SystemTime) AS FirstSeen, System.Computer AS Computer,
           EventData.NewProcessName AS ImagePath, EventData.CommandLine AS CommandLine,
           EventData.ParentProcessName AS ParentProcess, stat(filename=EventData.NewProcessName).Size AS FileSize, count() AS Runs
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688
      AND EventData.NewProcessName =~ '''(?i)\\(appdata\\local\\temp|windows\\temp|users\\public|downloads|perflogs)\\'''
      AND FileSize > 10485760
    GROUP BY ImagePath
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1027.001' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('a15f6cb17a4d84a8d15381415a15850c', '286bedadf5b12ab8b366649c29df4de3');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT min(item=System.TimeCreated.SystemTime) AS FirstSeen, System.Computer AS Computer, EventData.Image AS ImagePath, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.Hashes AS Hashes, stat(filename=EventData.Image).Size AS FileSize, count() AS Runs FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND EventData.Image =~ '''(?i)\\(appdata\\local\\temp|windows\\temp|users\\public|downloads|perflogs)\\''' AND FileSize > 10485760 GROUP BY ImagePath
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1027.001' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('05954f7732f3d248b3a3050cb2227f78', 'e7019bde903c34d44c95868072cff625');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.T1027005.IndicatorRemovalCorrelation
description: |
  Indicator removal from tools: a tool is detected by AV, then modified (repacked, strings changed) and dropped / run again.
  Defender detections (1116/1117) + executables written to and run from user-writable folders, to line up by time and path.
sources:
- name: AVDetections
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
           EventData.`Threat Name` AS ThreatName, EventData.`Severity Name` AS Severity, EventData.Path AS Path,
           EventData.`Process Name` AS ProcessName, EventData.`Action Name` AS Action, EventData.`Detection User` AS DetectionUser
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx')
    WHERE System.EventID.Value IN (1116, 1117)
- name: SubsequentFileCreation
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image,
           EventData.TargetFilename AS TargetFilename, EventData.ProcessGuid AS ProcessGuid
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 11
      AND EventData.TargetFilename =~ '''(?i)\x5c(users\x5c[^\x5c]+\x5c(appdata|downloads|desktop|documents)|programdata|windows\x5ctemp|perflogs|users\x5cpublic)\x5c.*\.(exe|dll|scr|ps1|bat|vbs|js|hta)$'''
      AND NOT EventData.TargetFilename =~ '''(?i)\x5cappdata\x5clocal\x5c(microsoft\x5c(onedrive|edgeupdate|teams|windowsapps)|packages|temp\x5c[0-9a-f-]{36}\x5c)'''
- name: ProcessExecution
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image,
           EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.Hashes AS Hashes,
           EventData.OriginalFileName AS OriginalFileName, EventData.ProcessGuid AS ProcessGuid
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.Image =~ '''(?i)\x5c(users\x5c[^\x5c]+\x5c(appdata|downloads|desktop|documents)|programdata|windows\x5ctemp|perflogs|users\x5cpublic)\x5c'''
      AND NOT EventData.Image =~ '''(?i)\x5cappdata\x5clocal\x5c(microsoft\x5c(onedrive|edgeupdate|teams|windowsapps)|packages)\x5c'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1027.005' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('03cbbbe14696d11f367e613ae08bebbe', '1ca1cf33ce38b3f8b22f6f94c31c3123');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.`Threat Name` AS ThreatName, EventData.`Severity Name` AS Severity, EventData.Path AS Path, EventData.`Process Name` AS ProcessName, EventData.`Action Name` AS Action FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx') WHERE System.EventID.Value IN (1116, 1117) AND EventData.`Threat Name` =~ '''.'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1027.005' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('99a6f29fb9eac35b8bdeffa091f42234');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.FilelessStorage
description: |
  Detects fileless storage (ATT&CK T1027.011): long encoded blobs written into registry values (Sysmon 13,
  Security 4657) and permanent WMI event consumers (WMI-Activity 5861). The old query used len(list=) on a
  string (verify failed, so it never ran), System.EventID without .Value, and read WMI events from Security.
sources:
  - name: RegistryBlobSysmon
    query: |
      SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
             EventData.Image AS Process, EventData.TargetObject AS RegistryPath, EventData.Details AS Value
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 13
        AND EventData.Details =~ '''[A-Za-z0-9+/=]{200,}'''
        AND NOT EventData.Image =~ '''(?i)^C:\\(Windows\\(System32|SysWOW64|servicing)|Program Files( \(x86\))?\\(Microsoft|Windows Defender|Google\\Chrome|Mozilla))\\'''
  - name: RegistryBlobSecurity
    query: |
      SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
             EventData.ProcessName AS Process, EventData.ObjectName AS RegistryPath,
             EventData.ObjectValueName AS ValueName, EventData.NewValue AS Value, EventData.SubjectUserName AS User
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value = 4657
        AND EventData.NewValue =~ '''[A-Za-z0-9+/=]{200,}'''
  - name: WMIPermanentConsumers
    query: |
      SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
             UserData.Operation_ESStoConsumerBinding.Namespace AS Namespace,
             UserData.Operation_ESStoConsumerBinding.ESS AS EventFilter,
             UserData.Operation_ESStoConsumerBinding.CONSUMER AS Consumer,
             UserData.Operation_ESStoConsumerBinding.PossibleCause AS Details
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-WMI-Activity%4Operational.evtx')
      WHERE System.EventID.Value = 5861
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1027.011' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('9ce5dd446cbecbcb3476a71e38e11303');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, EventData.Image AS Process, EventData.TargetObject AS RegistryPath, EventData.Details AS Value FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 13 AND EventData.Details =~ '''[A-Za-z0-9+/=]{200,}''' AND NOT EventData.Image =~ '''(?i)^C:\\(Windows\\(System32|SysWOW64|servicing)|Program Files( \(x86\))?\\(Microsoft|Windows Defender|Google\\Chrome|Mozilla))\\'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1027.011' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('7eeb8c5a298a8c518f3e3f2c0f3f1fd4');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.T1027_013.EncodedPayloadDetection
description: |
  Encrypted/encoded files: payloads decoded or decrypted on the host (certutil -decode, openssl enc -d,
  PowerShell FromBase64String written to disk, expand/extrac32 of disguised cabinets) and encoded blobs
  dropped with misleading extensions.
sources:
- name: SysmonDecoderProcesses
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessName,
           EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentProcess, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.CommandLine =~ '''(?is)(certutil(\.exe)?"?\s+.*-decode(hex)?\b|openssl(\.exe)?"?\s+(enc|aes-\S+|des\S*)\s+.*-d\b|frombase64string.*(writeallbytes|set-content|out-file)|convertto-securestring.*-key.*(securestringtobstr|getnetworkcredential)|\bbase64\s+(-d|--decode)\b|\b(expand|extrac32)(\.exe)?"?\s+.*\.(txt|jpg|png|log|dat)\b)'''
- name: SecurityDecoderProcesses
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.NewProcessName AS ProcessName,
           EventData.CommandLine AS CommandLine, EventData.ParentProcessName AS ParentProcess, EventData.SubjectUserName AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688
      AND EventData.CommandLine =~ '''(?is)(certutil(\.exe)?"?\s+.*-decode(hex)?\b|openssl(\.exe)?"?\s+(enc|aes-\S+|des\S*)\s+.*-d\b|frombase64string.*(writeallbytes|set-content|out-file)|convertto-securestring.*-key.*(securestringtobstr|getnetworkcredential)|\bbase64\s+(-d|--decode)\b)'''
- name: PowerShellDecodeToFile
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ScriptBlockText AS ScriptBlockText,
           EventData.Path AS Path
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
    WHERE System.EventID.Value = 4104
      AND EventData.ScriptBlockText =~ '''(?i)frombase64string'''
      AND EventData.ScriptBlockText =~ '''(?i)(writeallbytes|set-content|out-file|\.decrypt\(|createdecryptor|-bxor)'''
      AND NOT EventData.Path =~ '''(?i)^C:\\(Windows|Program Files|Program Files \(x86\))\\'''
- name: DisguisedEncodedFileDrops
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image,
           EventData.TargetFilename AS TargetFilename
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 11
      AND EventData.TargetFilename =~ '''(?i)(\\Windows\\Registration\\[0-9a-f-]{36}\.[0-9a-f-]{36}\.crmlog$|\.(b64|enc|encrypted)$)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1027.013' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('46dad70163679c9e5aeb8cf71333785e');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$LET sysmon = SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentProcess, EventData.User AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND EventData.CommandLine =~ '''(?is)(certutil(\.exe)?"?\s+.*-decode(hex)?\b|openssl(\.exe)?"?\s+(enc|aes-\S+|des\S*)\s+.*-d\b|frombase64string.*(writeallbytes|set-content|out-file)|convertto-securestring.*-key.*(securestringtobstr|getnetworkcredential)|\bbase64\s+(-d|--decode)\b)'''
LET security = SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.NewProcessName AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentProcessName AS ParentProcess, EventData.SubjectUserName AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx') WHERE System.EventID.Value = 4688 AND EventData.CommandLine =~ '''(?is)(certutil(\.exe)?"?\s+.*-decode(hex)?\b|openssl(\.exe)?"?\s+(enc|aes-\S+|des\S*)\s+.*-d\b|frombase64string.*(writeallbytes|set-content|out-file)|convertto-securestring.*-key.*(securestringtobstr|getnetworkcredential)|\bbase64\s+(-d|--decode)\b)'''
SELECT * FROM chain(a={SELECT * FROM sysmon}, b={SELECT * FROM if(condition=len(list=sysmon)=0, then={SELECT * FROM security})})
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1027.013' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('33859a6ba46d6f8d7c30afba46c1ac21');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.PolymorphicCode
description: |
  Polymorphic / self-modifying code leaves one program path with several different file hashes over time.
  Lists executables and unsigned DLLs in user-writable folders that Sysmon saw run or load with more than
  one hash, plus programs in user-writable folders started by script hosts (how rebuilt payloads are launched).
sources:
  - name: ExecutableHashChanges
    query: |
      LET runs = SELECT EventData.Image AS Image, EventData.Hashes AS Hashes,
                        min(item=System.TimeCreated.SystemTime) AS FirstSeen, System.Computer AS Computer
        FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
        WHERE System.EventID.Value = 1
          AND EventData.Image =~ '''(?i)\\(Users|ProgramData|Temp|PerfLogs|Windows\\Temp)\\'''
        GROUP BY Image, Hashes
      SELECT * FROM foreach(row={
        SELECT Image, Computer, count() AS DistinctHashes, enumerate(items=Hashes) AS Hashes, min(item=FirstSeen) AS EventTime
        FROM runs GROUP BY Image
      }) WHERE DistinctHashes > 1
  - name: DllHashChanges
    query: |
      LET loads = SELECT EventData.ImageLoaded AS ImageLoaded, EventData.Hashes AS Hashes,
                         min(item=System.TimeCreated.SystemTime) AS FirstSeen, System.Computer AS Computer
        FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
        WHERE System.EventID.Value = 7
          AND EventData.ImageLoaded =~ '''(?i)\\(Users|ProgramData|Temp|PerfLogs|Windows\\Temp)\\'''
          AND EventData.Signed = 'false'
        GROUP BY ImageLoaded, Hashes
      SELECT * FROM foreach(row={
        SELECT ImageLoaded, Computer, count() AS DistinctHashes, enumerate(items=Hashes) AS Hashes, min(item=FirstSeen) AS EventTime
        FROM loads GROUP BY ImageLoaded
      }) WHERE DistinctHashes > 1
  - name: ScriptHostLaunchedUserFolderBinary
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage,
             EventData.Hashes AS Hashes
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 1
        AND EventData.ParentImage =~ '''(?i)\\(powershell|pwsh|cmd|wscript|cscript|mshta)\.exe$'''
        AND EventData.Image =~ '''(?i)\\(Users\\[^\\]+\\AppData|Users\\Public|ProgramData|Windows\\Temp)\\[^\\]*\.exe$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1027.014' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('75d8932eb49b11552d681062f86305c8');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ProcessId AS ProcessId, EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.ParentCommandLine AS ParentCommandLine, EventData.Hashes AS Hashes FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND EventData.ParentImage =~ '''(?i)\\(powershell|pwsh|cmd|wscript|cscript|mshta)\.exe$''' AND EventData.Image =~ '''(?i)\\(Users\\[^\\]+\\AppData|Users\\Public|ProgramData|Windows\\Temp)\\[^\\]*\.exe$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1027.014' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('762b22e9304429b8e6dbdf321e0f0aac');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.Windows.Detection.JunkCodeInsertion
description: |
  Detects possible junk-code-inflated executables (ATT&CK T1027.016): large executables run or written in
  temp / download / public folders (one row per binary), and processes from those folders opening other
  processes with full access. stat() takes filename=, not path= (verify failed, so this never ran);
  GrantedAccess is a number.
sources:
- name: SuspiciousLargeExecutables
  query: |
    SELECT min(item=System.TimeCreated.SystemTime) AS FirstSeen, System.Computer AS Computer,
           EventData.Image AS ProcessImage, EventData.CommandLine AS CommandLine, EventData.Hashes AS Hashes,
           stat(filename=EventData.Image).Size AS FileSize, count() AS Runs
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.Image =~ '''(?i)\\(appdata\\local\\temp|windows\\temp|users\\public|downloads)\\'''
      AND FileSize > 5242880
    GROUP BY ProcessImage
- name: MemoryInjectionAttempts
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.SourceImage AS SourceImage, EventData.TargetImage AS TargetImage,
           format(format='0x%x', args=EventData.GrantedAccess) AS AccessRights, EventData.CallTrace AS CallTrace
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 10
      AND EventData.SourceImage =~ '''(?i)\\(appdata\\local\\temp|windows\\temp|users\\public|downloads)\\'''
      AND EventData.GrantedAccess IN (2035711, 2097151)
- name: SuspiciousFileCreation
  query: |
    SELECT min(item=System.TimeCreated.SystemTime) AS FirstSeen, System.Computer AS Computer,
           EventData.TargetFilename AS FilePath, EventData.Image AS CreatingProcess,
           stat(filename=EventData.TargetFilename).Size AS FileSize, count() AS Writes
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 11
      AND EventData.TargetFilename =~ '''(?i)\.(exe|dll|scr|com)$'''
      AND EventData.TargetFilename =~ '''(?i)\\(appdata\\local\\temp|windows\\temp|users\\public|downloads)\\'''
      AND FileSize > 2097152
    GROUP BY FilePath
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1027.016' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('7d0381f6bb9d7d76afb9ee0d6e380bd3', '50b54eb2273fe4075dfb050e1a839adf');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT min(item=System.TimeCreated.SystemTime) AS FirstSeen, System.Computer AS Computer, EventData.Image AS ProcessImage, EventData.CommandLine AS CommandLine, EventData.Hashes AS Hashes, stat(filename=EventData.Image).Size AS FileSize, count() AS Runs FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND EventData.Image =~ '''(?i)\\(appdata\\local\\temp|windows\\temp|users\\public|downloads)\\''' AND FileSize > 10485760 GROUP BY ProcessImage
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1027.016' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('0570ed09181094c2930336ed12e0c035');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.Scheduled.Transfer.Detection
description: Detects scheduled data exfiltration patterns across scheduled tasks, task executions and recurring outbound connections
sources:
- name: ScheduledTasks
  query: |
    SELECT OSPath, Mtime,
           parse_string_with_regex(string=Xml, regex='''<Command>(?P<Command>[^<]*)</Command>''').Command AS Command,
           parse_string_with_regex(string=Xml, regex='''<Arguments>(?P<Arguments>[^<]*)</Arguments>''').Arguments AS Arguments
    FROM foreach(row={SELECT OSPath, Mtime FROM glob(globs='C:/Windows/System32/Tasks/**') WHERE NOT IsDir},
                 query={SELECT OSPath, Mtime, utf16(string=read_file(filename=OSPath, length=200000)) AS Xml FROM scope()})
    WHERE Xml =~ '''(?i)<(Command|Arguments)>[^<]*(ftp|sftp|scp|rsync|curl|wget|bitsadmin|rclone|Invoke-WebRequest|Invoke-RestMethod|iwr |irm |UploadFile|UploadData|WebClient|Start-BitsTransfer)'''
- name: RecurringNetworkConnections
  query: |
    SELECT * FROM foreach(row={
      SELECT Image, DestinationIp, min(item=EventTime) AS FirstSeen, max(item=EventTime) AS LastSeen,
             count() AS ConnectionCount, Computer
      FROM foreach(row={
        SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
               EventData.Image AS Image, EventData.DestinationIp AS DestinationIp,
               format(format='%v|%v', args=[EventData.Image, EventData.DestinationIp]) AS Key
        FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
        WHERE System.EventID.Value = 3 AND EventData.Initiated
          AND NOT EventData.DestinationIp =~ '''^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|::1$|0:0:0:0:0:0:0:1$|fe80:|f[cd][0-9a-f]{2}:)'''
          AND NOT EventData.Image =~ '''(?i)\x5c(msedge|chrome|firefox|msedgewebview2|svchost|MsMpEng|MpDefenderCoreService|OneDrive|Teams|ms-teams|SearchApp|backgroundTaskHost|WmiPrvSE|smartscreen|SecurityHealthService|CompatTelRunner|wermgr)\.exe$'''})
      GROUP BY Key})
    WHERE ConnectionCount > 5
- name: SchedulerExecutions
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           System.EventID.Value AS EventID, EventData.TaskName AS TaskName, EventData.ActionName AS ActionName,
           EventData.ResultCode AS ResultCode, EventData.UserContext AS UserContext
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler%4Operational.evtx')
    WHERE System.EventID.Value IN (106, 200, 201)
      AND ((EventData.TaskName =~ '''(?i)(backup|sync|transfer|export|upload|exfil)'''
            AND NOT EventData.TaskName =~ '''^\x5cMicrosoft\x5c''')
           OR EventData.ActionName =~ '''(?i)\x5c(curl|wget|ftp|sftp|scp|pscp|rclone|bitsadmin)\.exe$''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1029' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('f008e65369400763a8815f40d95915c6', '1174b2a3cc44f95e3ca4ef056d7ffeaf');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT * FROM foreach(row={SELECT Image, DestinationIp, min(item=EventTime) AS FirstSeen, max(item=EventTime) AS LastSeen, count() AS ConnectionCount, Computer FROM foreach(row={SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.DestinationIp AS DestinationIp, format(format='%v|%v', args=[EventData.Image, EventData.DestinationIp]) AS Key FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 3 AND EventData.Initiated AND NOT EventData.DestinationIp =~ '''^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|::1$|0:0:0:0:0:0:0:1$|fe80:|f[cd][0-9a-f]{2}:)''' AND NOT EventData.Image =~ '''(?i)\x5c(msedge|chrome|firefox|msedgewebview2|svchost|MsMpEng|MpDefenderCoreService|OneDrive|Teams|ms-teams|SearchApp|backgroundTaskHost|WmiPrvSE|smartscreen|SecurityHealthService|CompatTelRunner|wermgr)\.exe$'''}) GROUP BY Key}) WHERE ConnectionCount > 5
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1029' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('499c779ae7ac9562936499419a892524', 'd879ae3f26b21250d0228f070f0d18d8');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.T1036_005.MasqueradingLegitimateNames
description: |
  Processes / files named like Windows system binaries outside the folders those binaries live in,
  svchost.exe not started by services.exe, and Run keys pointing at system-binary names outside System32.
sources:
  - name: SysmonProcessCreation
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image,
             EventData.OriginalFileName AS OriginalFileName, EventData.CommandLine AS CommandLine,
             EventData.ParentImage AS ParentImage, EventData.User AS User, EventData.Hashes AS Hashes
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 1
        AND ((EventData.Image =~ '''(?i)\x5c(svchost|lsass|winlogon|csrss|smss|services|wininit|spoolsv|taskhostw|lsm|rundll32|dllhost|conhost|ctfmon|dwm|sihost)\.exe$'''
              AND NOT EventData.Image =~ '''(?i)^[a-z]:\x5cwindows\x5c(system32|syswow64|winsxs)\x5c''')
          OR (EventData.Image =~ '''(?i)\x5cexplorer\.exe$''' AND NOT EventData.Image =~ '''(?i)^[a-z]:\x5cwindows\x5c(explorer\.exe|syswow64\x5cexplorer\.exe)$''')
          OR (EventData.Image =~ '''(?i)\x5csvchost\.exe$''' AND NOT EventData.ParentImage =~ '''(?i)\x5c(services|msmpeng|svchost)\.exe$'''))
  - name: SecurityProcessCreation
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.NewProcessName AS ProcessPath,
             EventData.ParentProcessName AS ParentProcess, EventData.CommandLine AS CommandLine, EventData.SubjectUserName AS User
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value = 4688
        AND ((EventData.NewProcessName =~ '''(?i)\x5c(svchost|lsass|winlogon|csrss|smss|services|wininit|spoolsv|taskhostw|lsm|rundll32|dllhost|conhost|ctfmon|dwm|sihost)\.exe$'''
              AND NOT EventData.NewProcessName =~ '''(?i)^[a-z]:\x5cwindows\x5c(system32|syswow64|winsxs)\x5c''')
          OR (EventData.NewProcessName =~ '''(?i)\x5cexplorer\.exe$''' AND NOT EventData.NewProcessName =~ '''(?i)^[a-z]:\x5cwindows\x5c(explorer\.exe|syswow64\x5cexplorer\.exe)$''')
          OR (EventData.NewProcessName =~ '''(?i)\x5csvchost\.exe$''' AND NOT EventData.ParentProcessName =~ '''(?i)\x5c(services|msmpeng|svchost)\.exe$'''))
  - name: SysmonFileCreation
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.TargetFilename AS FilePath,
             EventData.Image AS CreatedBy, EventData.ProcessGuid AS ProcessGuid
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 11
        AND EventData.TargetFilename =~ '''(?i)\x5c(svchost|lsass|winlogon|csrss|smss|services|wininit|spoolsv|taskhostw|rundll32|dllhost|conhost|explorer)\.exe$'''
        AND NOT EventData.TargetFilename =~ '''(?i)^[a-z]:\x5cwindows\x5c(system32|syswow64|winsxs|servicing|softwaredistribution)\x5c'''
  - name: RegistryRunKeys
    query: |
      SELECT OSPath AS Key, Name, Data.value AS ExecutablePath, Mtime
      FROM glob(globs=['HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Run*/*',
                       'HKEY_LOCAL_MACHINE/SOFTWARE/WOW6432Node/Microsoft/Windows/CurrentVersion/Run*/*',
                       'HKEY_USERS/*/Software/Microsoft/Windows/CurrentVersion/Run*/*'], accessor='registry')
      WHERE Data.value =~ '''(?i)\x5c(svchost|lsass|winlogon|csrss|smss|services|wininit|spoolsv|taskhostw|rundll32|dllhost|conhost|explorer)\.exe'''
        AND NOT Data.value =~ '''(?i)^"?[a-z]:\x5cwindows\x5c(system32|syswow64)\x5c(rundll32|dllhost)\.exe'''
        AND NOT Data.value =~ '''(?i)^"?([a-z]:\x5cwindows\x5c(system32|syswow64)\x5c|%(systemroot|windir)%\x5csystem32\x5c)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1036.005' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('aa7f15e771ca50d6bb4374ca234de71a');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$LET sysmon = SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentProcess, EventData.User AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND ((EventData.Image =~ '''(?i)\x5c(svchost|lsass|winlogon|csrss|smss|services|wininit|spoolsv|taskhostw|lsm|rundll32|dllhost|conhost|ctfmon|dwm|sihost)\.exe$''' AND NOT EventData.Image =~ '''(?i)^[a-z]:\x5cwindows\x5c(system32|syswow64|winsxs)\x5c''') OR (EventData.Image =~ '''(?i)\x5csvchost\.exe$''' AND NOT EventData.ParentImage =~ '''(?i)\x5c(services|msmpeng|svchost)\.exe$'''))
LET security = SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.NewProcessName AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentProcessName AS ParentProcess, EventData.SubjectUserName AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx') WHERE System.EventID.Value = 4688 AND ((EventData.NewProcessName =~ '''(?i)\x5c(svchost|lsass|winlogon|csrss|smss|services|wininit|spoolsv|taskhostw|lsm|rundll32|dllhost|conhost|ctfmon|dwm|sihost)\.exe$''' AND NOT EventData.NewProcessName =~ '''(?i)^[a-z]:\x5cwindows\x5c(system32|syswow64|winsxs)\x5c''') OR (EventData.NewProcessName =~ '''(?i)\x5csvchost\.exe$''' AND NOT EventData.ParentProcessName =~ '''(?i)\x5c(services|msmpeng|svchost)\.exe$'''))
SELECT * FROM chain(a={SELECT * FROM sysmon}, b={SELECT * FROM if(condition=len(list=sysmon)=0, then={SELECT * FROM security})})
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1036.005' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('b3059229d2c5671f1c9dae896d14633d');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.DoubleExtensionMasquerading
description: Detect double file extension masquerading (invoice.pdf.exe) in file creation, process execution and recently opened files
sources:
- name: SuspiciousFileCreation
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.TargetFilename AS FilePath, EventData.Image AS CreatorImage, EventData.ProcessId AS CreatorPID
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 11
      AND EventData.TargetFilename =~ '''(?i)\.(txt|jpe?g|pdf|docx?|xlsx?|gif|png|rtf|zip)\.(exe|scr|hta|bat|cmd|vbs|js|pif|com|lnk)$'''
- name: DoubleExtensionExecution
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessPath,
           EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)\.(txt|jpe?g|pdf|docx?|xlsx?|gif|png|rtf|zip)\.(exe|scr|hta|bat|cmd|vbs|js|pif|com)$'''
        OR EventData.CommandLine =~ '''(?i)\.(txt|jpe?g|pdf|docx?|xlsx?|gif|png|rtf)\.(exe|scr|hta|bat|cmd|vbs|js|pif|com)\b''')
- name: SecurityProcessCreation
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.NewProcessName AS ProcessPath,
           EventData.CommandLine AS CommandLine, EventData.ParentProcessName AS ParentImage, EventData.SubjectUserName AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688
      AND EventData.NewProcessName =~ '''(?i)\.(txt|jpe?g|pdf|docx?|xlsx?|gif|png|rtf|zip)\.(exe|scr|hta|bat|cmd|vbs|js|pif|com)$'''
- name: RecentLNKFiles
  query: |
    SELECT OSPath, Mtime, Size
    FROM glob(globs='C:/Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk')
    WHERE OSPath.Basename =~ '''(?i)\.(txt|jpe?g|pdf|docx?|xlsx?|gif|png|rtf)\.(exe|scr|hta|bat|cmd|vbs|js|pif|com)\.lnk$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1036.007' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('32e1b1579530621f5da9901e9f46dffa', '33b4709de0b37ceb07646cd16ec5c938');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessPath, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.ProcessId AS ProcessId FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND EventData.Image =~ '''(?i)\.(txt|jpe?g|pdf|docx?|xlsx?|gif|png|rtf|zip)\.(exe|scr|hta|bat|cmd|vbs|js|pif|com)$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1036.007' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('f6efce09a654d7f7eed7ac52c596ec13', 'ad8d836c03bdb1c641adc6700a78bc4e');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.T1036_008.FileTypeMasquerading
description: |
  Masquerading a file type: executables or scripts saved with a document/image extension, then run.
  File creations of document/image names in user drop folders, processes whose image or command line is a
  document/image name, and files on disk whose extension says document/image but whose content is a
  Windows executable (MZ header).
sources:
- name: SysmonFileCreation
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.TargetFilename AS TargetFilename, EventData.ProcessId AS ProcessId, EventData.Image AS Image
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 11
      AND EventData.TargetFilename =~ '''(?i)\.(jpg|jpeg|gif|png|txt|pdf|doc|docx)$'''
      AND EventData.TargetFilename =~ '''(?i)\\(temp|downloads|appdata|users\\public|desktop|documents)\\'''
      AND EventData.Image =~ '''(?i)\\(powershell|pwsh|cmd|certutil|bitsadmin|curl|mshta|wscript|cscript|rundll32|regsvr32)\.exe$'''
- name: SysmonProcessExecution
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.ProcessId AS ProcessId
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)\.(jpg|jpeg|gif|png|txt|pdf|doc|docx)$''' OR
           EventData.CommandLine =~ '''(?i)(rundll32|regsvr32|mshta|wscript|cscript)(\.exe)?"?\s+"?[^ ,"]*\.(jpg|jpeg|gif|png|txt|pdf|docx?)\b''')
- name: FileHeaderAnalysis
  query: |
    SELECT OSPath, Size, Mtime, Btime, read_file(filename=OSPath, length=2) AS Magic
    FROM glob(globs=['C:/Users/*/Downloads/**', 'C:/Users/*/Desktop/**', 'C:/Users/*/Documents/**',
                     'C:/Users/*/AppData/Local/Temp/**', 'C:/Users/Public/**', 'C:/Windows/Temp/**', 'C:/Temp/**'])
    WHERE NOT IsDir AND Size > 64
      AND Name =~ '''(?i)\.(jpg|jpeg|gif|png|txt|pdf|doc|docx)$'''
      AND read_file(filename=OSPath, length=2) = 'MZ'
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1036.008' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('ce30030eca584214c33853a5ab2b57da', '4f51ec1bfaba629ae0abb54c37e511a9');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.Windows.NetworkLogonScripts
description: Detect network logon script execution via SYSVOL script access, Group Policy script processing and script processes started by the logon/GP script hosts
sources:
- name: GroupPolicyFileAccess
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.ShareName AS ShareName, EventData.RelativeTargetName AS ScriptPath,
           EventData.SubjectUserName AS UserName, EventData.IpAddress AS SourceIp
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 5145 AND EventData.ShareName =~ '''(?i)sysvol|netlogon'''
      AND EventData.RelativeTargetName =~ '''(?i)\.(bat|cmd|ps1|vbs|js|exe)$'''
- name: GroupPolicyProcessing
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           System.EventID.Value AS EventID, EventData.CSEExtensionName AS Extension,
           EventData.ApplicableGPOList AS GPOs, EventData.DescriptionString AS Description
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-GroupPolicy%4Operational.evtx')
    WHERE System.EventID.Value IN (4016, 5016, 6016, 7016) AND EventData.CSEExtensionName =~ '''(?i)scripts'''
- name: ScriptProcessExecution
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.NewProcessName AS ProcessName, EventData.CommandLine AS CommandLine,
           EventData.ParentProcessName AS ParentProcess, EventData.TargetUserName AS UserName
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688
      AND EventData.ParentProcessName =~ '''(?i)\x5c(winlogon|userinit|gpscript)\.exe$'''
      AND (EventData.CommandLine =~ '''(?i)\.(bat|cmd|ps1|vbs|js)\b|\x5csysvol\x5c|\x5cnetlogon\x5c'''
           OR EventData.NewProcessName =~ '''(?i)\x5c(cmd|powershell|pwsh|wscript|cscript|mshta)\.exe$''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1037.003' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('8e7afc99d5c514956ec3bc0dc222f2cb', '37e0ad33951f4d594022d0bd9b9f80a5');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$LET sysmon = SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentProcess, EventData.User AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND EventData.ParentImage =~ '''(?i)\x5c(winlogon|userinit|gpscript)\.exe$''' AND (EventData.CommandLine =~ '''(?i)\.(bat|cmd|ps1|vbs|js)\b|\x5csysvol\x5c|\x5cnetlogon\x5c''' OR EventData.Image =~ '''(?i)\x5c(cmd|powershell|pwsh|wscript|cscript|mshta)\.exe$''') LET security = SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, EventData.NewProcessName AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentProcessName AS ParentProcess, EventData.TargetUserName AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx') WHERE System.EventID.Value = 4688 AND EventData.ParentProcessName =~ '''(?i)\x5c(winlogon|userinit|gpscript)\.exe$''' AND (EventData.CommandLine =~ '''(?i)\.(bat|cmd|ps1|vbs|js)\b|\x5csysvol\x5c|\x5cnetlogon\x5c''' OR EventData.NewProcessName =~ '''(?i)\x5c(cmd|powershell|pwsh|wscript|cscript|mshta)\.exe$''') SELECT * FROM chain(a={SELECT * FROM sysmon}, b={SELECT * FROM if(condition=len(list=sysmon)=0, then={SELECT * FROM security})})
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1037.003' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('98a2e343c751ef6d1b20eeffccfc4639', '61b194a8b81d52834726cf78ec2fdb5d');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.ExfiltrationAlternativeProtocol
description: |
  Exfiltration over alternative protocols (FTP, SMTP, DNS, ICMP, TFTP, SCP/SFTP, HTTP uploads): upload tools and
  commands, non-system programs talking on those ports, DNS queries with data-sized labels, and archives staged first.
sources:
- name: ExfilCommands
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.CommandLine AS CommandLine,
           EventData.ParentImage AS ParentImage, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)\x5c(rclone|pscp|psftp|winscp|scp|sftp|tftp|ncat|nc|nc64|dnscat2?|iodine|megacmd\w*)\.exe$'''
        OR EventData.CommandLine =~ '''(?i)(ftp(\.exe)?"?\s+(-s:|.*-i\b)|tftp(\.exe)?"?\s+-i\s+\S+\s+put|curl(\.exe)?"?\s.*(-T\s|--upload-file|-F\s|--data-binary\s+@|-d\s+@)|invoke-(webrequest|restmethod).*-(infile|method\s+(put|post)).*|send-mailmessage.*-attachments|\.uploadfile\(|\.uploaddata\(|rclone\s+(copy|sync)|ping(\.exe)?"?\s.*-p\s|nslookup(\.exe)?"?\s+[a-z0-9-]{30,}\.)''')
- name: AltProtocolConnections
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.User AS User,
           EventData.DestinationIp AS DestinationIp, EventData.DestinationHostname AS DestinationHostname,
           EventData.DestinationPort AS DestinationPort, EventData.Protocol AS Protocol
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 3
      AND EventData.Initiated =~ '''(?i)^true$'''
      AND EventData.DestinationPort IN (20, 21, 22, 25, 53, 69, 465, 587, 989, 990, 2525)
      AND NOT EventData.Image =~ '''(?i)^(system$|c:\x5cwindows\x5csystem32\x5c(svchost|dns|lsass)\.exe$|c:\x5cprogram files( \(x86\))?\x5c(microsoft office|windows defender|vmware|docker)\x5c)'''
- name: DnsTunnelQueries
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.QueryName AS QueryName,
           EventData.QueryResults AS QueryResults
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 22
      AND EventData.QueryName =~ '''(?i)(^|\.)[a-z0-9_-]{40,}\.|^([a-z0-9]+\.){6,}[a-z]{2,}$'''
      AND NOT EventData.QueryName =~ '''(?i)\.(microsoft|windows|windowsupdate|azure|msftncsi|office|live|akamai(edge)?|cloudfront|googleapis|gvt1|amazonaws|docker|trafficmanager)\.(com|net)$'''
- name: StagedArchives
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.TargetFilename AS TargetFilename
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 11
      AND EventData.TargetFilename =~ '''(?i)\x5c(temp|tmp|users\x5cpublic|programdata|perflogs|appdata\x5croaming)\x5c.*\.(zip|7z|rar|tar|gz|tgz|cab)$'''
      AND NOT EventData.Image =~ '''(?i)\x5c(msiexec|trustedinstaller|tiworker|wuauclt|mousocoreworker|onedrive|teams|ms-teams|setup|msedge|chrome|firefox|code)\.exe$'''
- name: ProcessCreationSecurity
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.NewProcessName AS NewProcessName, EventData.CommandLine AS CommandLine,
           EventData.ParentProcessName AS ParentProcessName, EventData.SubjectUserName AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688
      AND (EventData.NewProcessName =~ '''(?i)\x5c(rclone|pscp|psftp|winscp|scp|sftp|tftp|ncat|nc|nc64|dnscat2?|iodine)\.exe$'''
        OR EventData.CommandLine =~ '''(?i)(ftp(\.exe)?"?\s+(-s:|.*-i\b)|tftp(\.exe)?"?\s+-i\s+\S+\s+put|curl(\.exe)?"?\s.*(-T\s|--upload-file|-F\s|--data-binary\s+@|-d\s+@)|invoke-(webrequest|restmethod).*-(infile|method\s+(put|post))|send-mailmessage.*-attachments|\.uploadfile\(|rclone\s+(copy|sync))''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1048' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('ee93e83a07f356af19523cb26643de50', '7f18f0f0de1f569758822d08a59e6b29');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.DestinationIp AS DestinationIp, EventData.DestinationPort AS DestinationPort, EventData.Protocol AS Protocol FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE (System.EventID.Value = 3 AND EventData.Initiated =~ '''(?i)^true$''' AND EventData.DestinationPort IN (20, 21, 22, 25, 53, 69, 465, 587, 989, 990, 2525) AND NOT EventData.Image =~ '''(?i)^(system$|c:\x5cwindows\x5csystem32\x5c(svchost|dns|lsass)\.exe$|c:\x5cprogram files( \(x86\))?\x5c(microsoft office|windows defender|vmware|docker)\x5c)''') OR (System.EventID.Value = 1 AND EventData.CommandLine =~ '''(?i)(ftp(\.exe)?"?\s+(-s:|.*-i\b)|tftp(\.exe)?"?\s+-i\s+\S+\s+put|curl(\.exe)?"?\s.*(-T\s|--upload-file|-F\s|--data-binary\s+@|-d\s+@)|invoke-(webrequest|restmethod).*-(infile|method\s+(put|post))|send-mailmessage.*-attachments|\.uploadfile\(|rclone\s+(copy|sync))''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1048' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('d70c4147023abd8419f8fb8cbf68f0f8', 'd337aae9447e67281f4bb3ecc1e51670');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.T1052.ExfiltrationPhysicalMedium
description: |
  Exfiltration to removable media: USB storage connected (Partition/Diagnostic 1006 with BusType 7 = USB,
  Security 6416 external device recognised), files written to a drive other than C: by Sysmon 11, and
  the USB storage devices ever connected (SYSTEM hive, USBSTOR).
sources:
- name: USBDiskConnected
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.Manufacturer AS Manufacturer, EventData.Model AS Model, EventData.SerialNumber AS SerialNumber,
           EventData.Capacity AS Capacity, EventData.ParentId AS ParentId
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Partition%4Diagnostic.evtx')
    WHERE System.EventID.Value = 1006 AND str(str=EventData.BusType) = '7'
- name: ExternalDeviceRecognised
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.DeviceDescription AS DeviceDescription, EventData.ClassName AS ClassName,
           EventData.DeviceId AS DeviceId, EventData.SubjectUserName AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 6416
      AND (EventData.DeviceId =~ '''(?i)^(USBSTOR|SWD\\WPDBUSENUM)\\''' OR EventData.ClassName =~ '''(?i)^(DiskDrive|WPD|USB)$''')
- name: FileWritesToOtherDrives
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.Image AS Image, EventData.TargetFilename AS TargetFilename
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 11 AND EventData.TargetFilename =~ '''^[D-Z]:\\'''
- name: USBStorageRegistry
  query: |
    SELECT OSPath.Path AS Key, Mtime AS LastWrite
    FROM glob(globs='HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Enum/USBSTOR/*/*', accessor='registry')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1052' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('f836e1ced16e582f4807ac7bd6708e63', 'cd2a56c5541deba4677f5b909f6b37a2');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.USBExfiltration
description: Detect potential USB-based data exfiltration by correlating device insertion with suspicious file operations
sources:
- name: USBDeviceEvents
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.DeviceDescription AS Device,
           EventData.ClassName AS Class, EventData.DeviceId AS DeviceId, EventData.SubjectUserName AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 6416
      AND (EventData.DeviceId =~ '''(?i)(USBSTOR|^USB\\|^SWD\\WPDBUSENUM)''' OR EventData.ClassName =~ '''(?i)^(DiskDrive|WPD|USB)$''')
- name: SuspiciousFileOperations
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image,
           EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.CommandLine =~ '''(?i)\b(robocopy|xcopy|copy|move|copy-item|move-item)\b.*\s"?[E-Z]:\\'''
- name: FileCreationToUSB
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image,
           EventData.TargetFilename AS TargetFilename, EventData.ProcessId AS ProcessId
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 11
      AND EventData.TargetFilename =~ '''^[E-Z]:\\'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1052.001' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('3489530744ab04945a805dd96b3921d6', 'e607a50e427e2efcd85d299ed5c6518f');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.DeviceDescription AS Device, EventData.ClassName AS Class, EventData.DeviceId AS DeviceId, EventData.SubjectUserName AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx') WHERE System.EventID.Value = 6416 AND (EventData.DeviceId =~ '''(?i)(USBSTOR|^USB\\|^SWD\\WPDBUSENUM)''' OR EventData.ClassName =~ '''(?i)^(DiskDrive|WPD|USB)$''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1052.001' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('124ae09fb8b080854612e1aac7220568', 'f4e6c983630cd2686ee6d7ca91f86e69');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.ProcessInjection
description: |
  Process injection in Sysmon. Opening another process with write/thread rights is normal when a process
  starts a child (Windows hands the parent a full-access handle), so those parent->child pairs (Sysmon 1)
  are left out, as are Windows' own folders and Program Files. What stays: a program from anywhere else
  (user folders, ProgramData, a tools folder) taking write/thread access to a process it didn't start,
  remote threads not started by Windows' session/service processes, and unsigned DLLs from user-writable
  folders loaded into common injection targets.
sources:
  - name: SuspiciousProcessAccess
    query: |
      LET children <= SELECT format(format='%v-%v', args=[EventData.ParentProcessId, EventData.ProcessId]) AS K
        FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
        WHERE System.EventID.Value = 1
      LET child_keys <= children.K
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.SourceProcessId AS SourcePID, EventData.SourceImage AS SourceImage,
             EventData.TargetProcessId AS TargetPID, EventData.TargetImage AS TargetImage,
             format(format='0x%x', args=EventData.GrantedAccess) AS GrantedAccess, EventData.CallTrace AS CallTrace
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 10
        AND format(format='0x%x', args=EventData.GrantedAccess) =~ '''(?i)^0x(1f3fff|1fffff|143a|1438|1f0fff|1f2fff)$'''
        AND EventData.SourceProcessId != EventData.TargetProcessId
        AND NOT EventData.SourceImage =~ '''(?i)^C:\\(Windows|Program Files|Program Files \(x86\))\\'''
        AND NOT format(format='%v-%v', args=[EventData.SourceProcessId, EventData.TargetProcessId]) IN child_keys
  - name: RemoteThreadCreation
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.SourceProcessId AS SourcePID, EventData.SourceImage AS SourceImage,
             EventData.TargetProcessId AS TargetPID, EventData.TargetImage AS TargetImage,
             EventData.StartAddress AS StartAddress, EventData.StartModule AS StartModule, EventData.StartFunction AS StartFunction
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 8
        AND EventData.SourceProcessId != EventData.TargetProcessId
        AND NOT EventData.SourceImage =~ '''(?i)^C:\\Windows\\System32\\(csrss|wininit|winlogon|services|lsass|smss|dwm|svchost|wbem\\WmiPrvSE)\.exe$'''
  - name: SuspiciousDLLLoads
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.ProcessId AS PID, EventData.Image AS Image, EventData.ImageLoaded AS ImageLoaded,
             EventData.Signed AS Signed, EventData.Signature AS Signature, EventData.Hashes AS Hashes
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 7
        AND EventData.Signed = 'false'
        AND EventData.ImageLoaded =~ '''(?i)\\(Users|ProgramData|Temp|PerfLogs|Windows\\Temp)\\'''
        AND EventData.Image =~ '''(?i)\\(explorer|svchost|winlogon|lsass|rundll32|notepad|spoolsv|dllhost|regsvr32)\.exe$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1055' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('1f27f19388e5e77c79931759985862c7');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.DLLInjection
description: DLL injection - remote threads created by non-system processes, injector processes (mavinject /INJECTRUNNING), full-access handles opened by script hosts / user-writable binaries, and unsigned DLLs from user-writable folders loaded by Windows binaries
sources:
- name: RemoteThreadCreation
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.SourceImage AS SourceImage, EventData.SourceProcessId AS SourcePID,
           EventData.TargetImage AS TargetImage, EventData.TargetProcessId AS TargetPID,
           EventData.StartModule AS StartModule, EventData.StartFunction AS StartFunction, EventData.SourceUser AS SourceUser
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 8
      AND NOT EventData.SourceImage =~ '''(?i)^C:\x5cWindows\x5cSystem32\x5c(csrss|wininit|winlogon|services|lsass|smss|dwm|svchost|audiodg|wbem\x5cWmiPrvSE)\.exe$|\x5c(MsMpEng|MsSense|vmtoolsd|VBoxService)\.exe$'''
- name: InjectorProcessCreation
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.Image AS ProcessName, EventData.CommandLine AS CommandLine,
           EventData.ParentImage AS ParentProcess, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)\x5cmavinject(64)?\.exe$''' OR EventData.CommandLine =~ '''(?i)/INJECTRUNNING|Invoke-DllInjection|Invoke-ReflectivePEInjection''')
- name: ProcessAccess
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.SourceImage AS SourceImage, EventData.SourceProcessId AS SourcePID,
           EventData.TargetImage AS TargetImage, EventData.TargetProcessId AS TargetPID,
           format(format='0x%x', args=EventData.GrantedAccess) AS GrantedAccess, EventData.CallTrace AS CallTrace
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 10
      AND EventData.GrantedAccess IN (2047999, 5178, 5242, 1082, 1146)
      AND EventData.SourceImage != EventData.TargetImage
      AND (EventData.SourceImage =~ '''(?i)\x5c(mavinject(64)?|rundll32|regsvr32|powershell|pwsh|cmd|mshta|wscript|cscript|msbuild|installutil)\.exe$'''
           OR EventData.SourceImage =~ '''(?i)\x5c(Users|ProgramData|Windows\x5cTemp|PerfLogs)\x5c''')
      AND NOT EventData.SourceImage =~ '''(?i)\x5cAppData\x5cLocal\x5c(Microsoft\x5c(Teams|OneDrive|WindowsApps)|Programs\x5c(Microsoft VS Code|Python))'''
- name: SuspiciousDLLLoads
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.Image AS Image, EventData.ProcessId AS PID, EventData.ImageLoaded AS ImageLoaded,
           EventData.Signed AS Signed, EventData.Hashes AS Hashes
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 7 AND EventData.Signed = 'false'
      AND EventData.ImageLoaded =~ '''(?i)\x5c(Users\x5c[^\x5c]+\x5c(AppData\x5cLocal\x5cTemp|Downloads|Desktop|Documents)|Users\x5cPublic|ProgramData|Windows\x5cTemp|PerfLogs|AtomicRedTeam)\x5c.*\.(dll|cpl|ocx)$'''
      AND EventData.Image =~ '''(?i)^C:\x5cWindows\x5c'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1055.001' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('876ab634624f4d4a0daf52a780dc955e');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.SourceImage AS SourceImage, EventData.TargetImage AS TargetImage, EventData.StartModule AS StartModule, EventData.StartFunction AS StartFunction, EventData.Image AS Image, EventData.CommandLine AS CommandLine FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE (System.EventID.Value = 8 AND NOT EventData.SourceImage =~ '''(?i)^C:\x5cWindows\x5cSystem32\x5c(csrss|wininit|winlogon|services|lsass|smss|dwm|svchost|audiodg|wbem\x5cWmiPrvSE)\.exe$|\x5c(MsMpEng|MsSense|vmtoolsd|VBoxService)\.exe$''') OR (System.EventID.Value = 1 AND (EventData.Image =~ '''(?i)\x5cmavinject(64)?\.exe$''' OR EventData.CommandLine =~ '''(?i)/INJECTRUNNING|Invoke-DllInjection|Invoke-ReflectivePEInjection'''))
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1055.001' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('dd8676569b17657e122761f46b21da8a');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.TLSCallbackInjection
description: |
  Thread Local Storage callback injection: code written into another process (memory-write handle opens, often from
  unbacked "UNKNOWN" memory), remote threads started in it, and unsigned DLLs loaded from user-writable folders.
sources:
  - name: InjectionHandleOpens
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.SourceImage AS SourceImage,
             EventData.TargetImage AS TargetImage, format(format='0x%x', args=EventData.GrantedAccess) AS GrantedAccess,
             EventData.CallTrace AS CallTrace, EventData.SourceUser AS SourceUser
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 10
        AND EventData.SourceImage != EventData.TargetImage
        AND EventData.GrantedAccess IN (42, 58, 1080, 1082, 5176, 5178, 2035711, 2043903, 2097151)
        AND EventData.TargetImage =~ '''(?i)\x5c(explorer|svchost|lsass|winlogon|spoolsv|services|sihost|taskhostw|runtimebroker|searchprotocolhost|msedge|chrome|firefox|outlook|winword|excel|onedrive|teams|ms-teams|dllhost)\.exe$'''
        AND NOT EventData.SourceImage =~ '''(?i)^c:\x5c(windows\x5c(system32|syswow64)\x5c(csrss|wininit|services|svchost|lsass|smss|wbem\x5cwmiprvse|werfault|taskmgr|searchindexer|dwm|sihost|explorer|conhost|audiodg)\.exe|windows\x5cexplorer\.exe|programdata\x5cmicrosoft\x5cwindows defender\x5c|program files( \(x86\))?\x5c(windows defender|vmware\x5cvmware tools|microsoft\x5cedge(webview)?\x5c|google\x5cchrome\x5c|mozilla firefox\x5c|docker\x5c))'''
  - name: RemoteThreads
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.SourceImage AS SourceImage,
             EventData.TargetImage AS TargetImage, EventData.StartAddress AS StartAddress, EventData.StartModule AS StartModule,
             EventData.StartFunction AS StartFunction
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 8
        AND NOT EventData.SourceImage =~ '''(?i)^c:\x5cwindows\x5c(system32|syswow64)\x5c(csrss|wininit|services|svchost|lsass|smss|werfault|dwm)\.exe$'''
  - name: UnsignedUserPathDllLoads
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.ImageLoaded AS ImageLoaded,
             EventData.Signed AS Signed, EventData.SignatureStatus AS SignatureStatus, EventData.Hashes AS Hashes
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 7
        AND NOT EventData.Signed =~ '''(?i)^true$'''
        AND EventData.ImageLoaded =~ '''(?i)\x5c(users\x5c[^\x5c]+\x5c(appdata\x5c(local\x5ctemp|roaming)|downloads|desktop)|programdata|windows\x5ctemp|users\x5cpublic|perflogs)\x5c'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1055.005' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('63f981e9a8ca0203fa8675ce9e23d955');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.SourceImage AS SourceImage, EventData.TargetImage AS TargetImage, EventData.StartModule AS StartModule, EventData.StartFunction AS StartFunction FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 8 AND NOT EventData.SourceImage =~ '''(?i)^c:\x5cwindows\x5c(system32|syswow64)\x5c(csrss|wininit|services|svchost|lsass|smss|werfault|dwm)\.exe$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1055.005' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('d41d8cd98f00b204e9800998ecf8427e');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.ProcessHollowing
description: |
  Process hollowing: a common Windows binary started without arguments by an unusual parent (script host,
  shell, Office, or a program outside Windows/Program Files), full-access handles to such processes opened
  from shellcode (CallTrace UNKNOWN) or non-system code, and remote threads that start outside any module.
sources:
- name: SuspiciousHollowTargetStart
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ProcessId AS PID,
           EventData.Image AS ProcessImage, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage,
           EventData.ParentCommandLine AS ParentCommandLine, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.Image =~ '''(?i)\\(svchost|notepad|rundll32|regsvr32|dllhost|werfault|searchprotocolhost|calc|mspaint|explorer)\.exe$'''
      AND (
        (EventData.Image =~ '''(?i)\\(svchost|dllhost)\.exe$''' AND NOT EventData.ParentImage =~ '''(?i)^C:\\Windows\\(System32|SysWOW64)\\(services|svchost|dllhost)\.exe$''')
        OR (EventData.CommandLine =~ '''(?i)^"?[^"]*\\(rundll32|regsvr32|notepad|dllhost|werfault|searchprotocolhost|calc|mspaint)(\.exe)?"?\s*$'''
            AND (EventData.ParentImage =~ '''(?i)\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|winword|excel|powerpnt|outlook)\.exe$'''
                 OR NOT EventData.ParentImage =~ '''(?i)^C:\\(Windows|Program Files|Program Files \(x86\))\\'''))
      )
- name: FullAccessToHollowTarget
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.SourceImage AS SourceImage,
           EventData.TargetImage AS TargetImage, EventData.TargetProcessId AS TargetPID,
           format(format='0x%x', args=EventData.GrantedAccess) AS GrantedAccess, EventData.CallTrace AS CallTrace,
           EventData.SourceUser AS SourceUser
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 10
      AND EventData.GrantedAccess IN (2097151, 2047999, 2035711)
      AND EventData.TargetImage =~ '''(?i)\\(svchost|notepad|rundll32|regsvr32|dllhost|explorer|werfault|calc|mspaint|searchprotocolhost)\.exe$'''
      AND (EventData.CallTrace =~ '''UNKNOWN\('''
           OR NOT EventData.SourceImage =~ '''(?i)^C:\\(Windows|Program Files|Program Files \(x86\))\\''')
      AND NOT EventData.SourceImage =~ '''(?i)\\ProgramData\\Microsoft\\Windows Defender\\'''
- name: CreateRemoteThread
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.SourceImage AS SourceImage,
           EventData.TargetImage AS TargetImage, EventData.TargetProcessId AS TargetPID, EventData.StartAddress AS StartAddress,
           EventData.StartModule AS StartModule, EventData.StartFunction AS StartFunction
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 8
      AND NOT EventData.SourceImage =~ '''(?i)^C:\\Windows\\System32\\(csrss|wininit|services|lsass|svchost|dwm|winlogon)\.exe$'''
      AND (NOT EventData.StartModule OR EventData.StartModule = '-'
           OR EventData.SourceImage =~ '''(?i)\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$'''
           OR NOT EventData.SourceImage =~ '''(?i)^C:\\(Windows|Program Files|Program Files \(x86\))\\''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1055.012' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('f0ebfd6678c75283b116140ecd05186b');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ProcessId AS PID, EventData.Image AS ProcessImage, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.ParentCommandLine AS ParentCommandLine FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND EventData.Image =~ '''(?i)\\(svchost|notepad|rundll32|regsvr32|dllhost|werfault|searchprotocolhost|calc|mspaint)\.exe$''' AND ((EventData.Image =~ '''(?i)\\(svchost|dllhost)\.exe$''' AND NOT EventData.ParentImage =~ '''(?i)^C:\\Windows\\(System32|SysWOW64)\\(services|svchost|dllhost)\.exe$''') OR (EventData.CommandLine =~ '''(?i)^"?[^"]*\\(rundll32|regsvr32|notepad|dllhost|werfault|searchprotocolhost|calc|mspaint)(\.exe)?"?\s*$''' AND (EventData.ParentImage =~ '''(?i)\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|winword|excel|powerpnt|outlook)\.exe$''' OR NOT EventData.ParentImage =~ '''(?i)^C:\\(Windows|Program Files|Program Files \(x86\))\\''')))
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1055.012' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('af3201a09632922decc1e1823da0509e');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.T1070.IndicatorRemoval
description: Detects indicator removal activities across multiple log sources and file operations
sources:
- name: EventLogClearing
  query: |
    LET sec = SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.Channel AS Channel,
                     System.EventID.Value AS EventID, UserData.LogFileCleared.SubjectUserName AS User, Message
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value = 1102
    LET sys = SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.Channel AS Channel,
                     System.EventID.Value AS EventID, UserData.LogFileCleared.SubjectUserName AS User, Message
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx')
      WHERE System.EventID.Value = 104 AND System.Provider.Name =~ '''(?i)eventlog'''
    SELECT * FROM chain(a=sec, b=sys)
- name: SysmonFileDeletion
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.ProcessId as PID, EventData.Image as Process,
           EventData.TargetFilename as DeletedFile, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value IN (23, 26)
          AND EventData.TargetFilename =~ '''(?i)\.(evtx|pf)$|\x5cprefetch\x5c|\x5cconsolehost_history\.txt$'''
- name: RegistryLogTampering
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.TargetObject as RegistryKey,
           EventData.Details as NewValue, EventData.Image as Process
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value IN (12, 13, 14)
          AND EventData.TargetObject =~ '''(?i)(\x5cservices\x5ceventlog\x5c[^\x5c]+\x5c(File|MaxSize|Retention|AutoBackupLogFiles|RestrictGuestAccess)$|\x5cservices\x5ceventlog\x5cStart$|\x5cWINEVT\x5cChannels\x5c.*\x5cEnabled$|\x5cpolicies\x5cmicrosoft\x5cwindows\x5ceventlog\x5c|\x5cservices\x5c(sysmon|sysmon64|sysmondrv)\x5c)'''
          AND NOT EventData.Image =~ '''(?i)^c:\x5cwindows\x5c(system32\x5c(svchost|services|wevtutil|msiexec|trustedinstaller)|servicing\x5ctrustedinstaller|winsxs\x5c)'''
- name: ClearingCommands
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.CommandLine AS CommandLine,
           EventData.ParentImage AS ParentImage, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.CommandLine =~ '''(?i)(wevtutil(\.exe)?"?\s+(cl|clear-log|sl\s.*/e:false)|clear-eventlog|remove-eventlog|limit-eventlog|\[System\.Diagnostics\.Eventing\.Reader\.EventLogSession\]|fsutil(\.exe)?"?\s+usn\s+deletejournal|del(ete)?\s.*\.evtx|remove-item.*(\.evtx|consolehost_history|prefetch))'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1070' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('5ff60cb2cdbfdf1443be2bc5e19fb559', 'd8f78abf1528ae0383dea173ad86e6ce');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$LET sec = SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.Channel AS Channel, System.EventID.Value AS EventID, Message FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx') WHERE System.EventID.Value = 1102
LET sys = SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.Channel AS Channel, System.EventID.Value AS EventID, Message FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx') WHERE System.EventID.Value = 104 AND System.Provider.Name =~ '''(?i)eventlog'''
LET smon = SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.Channel AS Channel, System.EventID.Value AS EventID, format(format='%v %v %v', args=[EventData.Image, EventData.TargetFilename, EventData.CommandLine]) AS Message FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE (System.EventID.Value IN (23, 26) AND EventData.TargetFilename =~ '''(?i)\.evtx$''') OR (System.EventID.Value = 1 AND EventData.CommandLine =~ '''(?i)(wevtutil(\.exe)?"?\s+(cl|clear-log)|clear-eventlog|fsutil(\.exe)?"?\s+usn\s+deletejournal)''')
SELECT * FROM chain(a=sec, b=sys, c=smon)
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1070' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('04a16ff75f39ac8288204816b9b85b16', '39a59b4b6fba62017d2a801f7dba514a');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$LET sysmon = SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, 'Sysmon 2 file creation time changed' AS Evidence, EventData.Image AS Process, EventData.TargetFilename AS TargetFile, EventData.CreationUtcTime AS NewCreationTime, EventData.PreviousCreationUtcTime AS PreviousCreationTime, EventData.User AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 2 AND (EventData.CreationUtcTime < EventData.PreviousCreationUtcTime OR EventData.Image =~ '''(?i)\x5c(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$|\x5c(Users|ProgramData|Windows\x5cTemp|PerfLogs)\x5c''') LET ps = SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, 'PowerShell 4104 timestamp change' AS Evidence, EventData.Path AS Process, EventData.ScriptBlockText AS TargetFile, NULL AS NewCreationTime, NULL AS PreviousCreationTime, NULL AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx') WHERE System.EventID.Value = 4104 AND EventData.ScriptBlockText =~ '''(?i)\.(CreationTime|LastWriteTime|LastAccessTime)(Utc)?\s*=|SetFileTime|Invoke-Timestomp|timestomp''' SELECT * FROM chain(a={SELECT * FROM sysmon}, b={SELECT * FROM ps})
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1070.006' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('90a0b2334d149b2d4d75e18d96ddc5e1', 'f37c6c7d14ca61b68a9f08ea654a68c0');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.T1071_001.WebProtocolC2
description: |
  Web protocol C2: HTTP(S) connections to public addresses from script hosts / LOLBins or from programs
  sitting directly in Temp, Public or ProgramData, and DNS lookups of throwaway TLDs by such processes.
sources:
- name: WindowsNetworkConnections
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessName,
           EventData.ProcessId AS ProcessId, EventData.User AS User, EventData.DestinationIp AS DestinationIp,
           EventData.DestinationHostname AS DestinationHostname, EventData.DestinationPort AS DestinationPort
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 3
      AND EventData.DestinationPort IN (80, 443, 8080, 8443, 8000, 8888)
      AND (EventData.Image =~ '''(?i)\\(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|msiexec|curl|wget|installutil|regasm|regsvcs|msbuild|cmstp|odbcconf|forfiles)\.exe$'''
           OR EventData.Image =~ '''(?i)\\(AppData\\Local\\Temp|Users\\Public|Windows\\Temp|ProgramData|PerfLogs)\\[^\\]+\.exe$''')
      AND NOT EventData.DestinationIp =~ '''^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|::1$|fe80:|0:0:0:0:0:0:0:1$)'''
- name: SuspiciousDNSQueries
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image,
           EventData.QueryName AS QueryName, EventData.QueryResults AS QueryResults
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 22
      AND NOT EventData.Image =~ '''(?i)\\(chrome|firefox|msedge|iexplore|opera|brave|msedgewebview2)\.exe$'''
      AND (EventData.QueryName =~ '''(?i)\.(tk|ml|ga|cf|gq|top|xyz|zip|mov|ru|su|onion|duckdns\.org|ngrok\.io|ngrok-free\.app|trycloudflare\.com|serveo\.net|pastebin\.com)$'''
           )
- name: CustomUserAgentWebRequests
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image,
           EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.CommandLine =~ '''(?is)((invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b|net\.webclient).*-useragent\s|\bcurl(\.exe)?"?\s.*\s(-A|--user-agent)\s|headers\.add\(\s*["']user-agent)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1071.001' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('8a3ba5ddb7ecb24ed8ead10ef41abbf9');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessName, EventData.ProcessId AS ProcessId, EventData.DestinationIp AS DestinationIp, EventData.DestinationHostname AS DestinationHostname, EventData.DestinationPort AS DestinationPort, EventData.Protocol AS Protocol FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 3 AND EventData.DestinationPort IN (80, 443, 8080, 8443, 8000, 8888) AND (EventData.Image =~ '''(?i)\\(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|msiexec|curl|wget|installutil|regasm|regsvcs|msbuild|cmstp|odbcconf|forfiles)\.exe$''' OR EventData.Image =~ '''(?i)\\(AppData\\Local\\Temp|Users\\Public|Windows\\Temp|ProgramData|PerfLogs)\\[^\\]+\.exe$''') AND NOT EventData.DestinationIp =~ '''^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|::1$|fe80:|0:0:0:0:0:0:0:1$)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1071.001' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('e7b259476b7c2223d2408655f4696233', 'd4f2ce752bf171ad372c9b8a3dda8a29');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.DNS.Tunneling.Detection
description: Detect DNS tunneling and C2 communication via DNS queries
sources:
- name: SysmonDNSQueries
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.ProcessId AS ProcessId, EventData.Image AS Image,
           EventData.QueryName AS QueryName, EventData.QueryResults AS QueryResults,
           len(list=split(string=EventData.QueryName, sep='[.]')[0]) AS SubdomainLength
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 22 AND (
      len(list=split(string=EventData.QueryName, sep='[.]')[0]) > 40 OR
      EventData.QueryName =~ '''(?i)^[a-z0-9-]{25,}[.]''' OR
      len(list=split(string=EventData.QueryName, sep='[.]')) > 6
    )
- name: SysmonNetworkConnections
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.ProcessId AS ProcessId, EventData.Image AS Image,
           EventData.DestinationIp AS DestinationIp, EventData.DestinationPort AS DestinationPort
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 3 AND EventData.DestinationPort = 53 AND
          EventData.Image =~ '''(?i)\\(powershell|pwsh|rundll32|python|cmd|wscript|cscript|mshta|nslookup)\.exe$'''
- name: ProcessDNSTools
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1 AND
          EventData.CommandLine =~ '''(?i)(nslookup\s+.*-(q|type)=txt|Resolve-DnsName\s+.*-Type\s+TXT|dnscat|iodine|dns2tcp|Invoke-DNS)'''
- name: PowerShellDNSCommands
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.ScriptBlockText AS Command
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
    WHERE System.EventID.Value = 4104 AND
          EventData.ScriptBlockText =~ '''(?i)(resolve-dnsname|nslookup|\[system\.net\.dns\])'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1071.004' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('662c19c4fbf5c3c6dec89362b57b7213', '32765f16fa3c1862294149174d2ba8dd');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: CloudAccountCompromise.Detection
description: Host-side traces of cloud account use - Azure AD / Entra sign-in and token events, cloud admin consoles in Chrome/Edge history, and stored cloud CLI credentials
sources:
- name: WindowsCloudAuthentication
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           System.EventID.Value AS EventID, System.Level AS Level, Message
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-AAD%4Operational.evtx')
    WHERE Message =~ '''(?i)(token|sign-?in|logon|authentication|PRT|refresh|account)'''
      AND NOT Message =~ '''(?i)Enumeration status set for existing webaccounts'''
- name: BrowserCloudArtifacts
  query: |
    SELECT visit_time AS VisitTime, User, visited_url AS URL, title AS Title, visit_count AS VisitCount, OSPath
    FROM Artifact.Windows.Applications.Chrome.History()
    WHERE visited_url =~ '''(?i)^https?://(portal\.azure\.com|entra\.microsoft\.com|admin\.microsoft\.com|console\.aws\.amazon\.com|signin\.aws\.amazon\.com|[a-z0-9-]+\.awsapps\.com|console\.cloud\.google\.com|admin\.google\.com|login\.microsoftonline\.com)'''
- name: StoredCloudCredentials
  query: |
    SELECT OSPath, Mtime, Size
    FROM glob(globs=['C:/Users/*/.aws/credentials', 'C:/Users/*/.aws/config', 'C:/Users/*/.azure/*.json',
                     'C:/Users/*/.azure/msal_token_cache.*', 'C:/Users/*/AppData/Roaming/gcloud/credentials.db',
                     'C:/Users/*/AppData/Roaming/gcloud/access_tokens.db', 'C:/Users/*/AppData/Roaming/gcloud/legacy_credentials/**',
                     'C:/Users/*/.config/gcloud/**/*.json'])
    WHERE NOT IsDir
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1078.004' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('b20c1edc5202a6b9c45d577c0e749eaf', '672e2058731b764d2bee65acd7baa237');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT OSPath, Mtime, Size FROM glob(globs=['C:/Users/*/.aws/credentials', 'C:/Users/*/.aws/config', 'C:/Users/*/.azure/*.json', 'C:/Users/*/.azure/msal_token_cache.*', 'C:/Users/*/AppData/Roaming/gcloud/credentials.db', 'C:/Users/*/AppData/Roaming/gcloud/access_tokens.db', 'C:/Users/*/AppData/Roaming/gcloud/legacy_credentials/**', 'C:/Users/*/.config/gcloud/**/*.json']) WHERE NOT IsDir
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1078.004' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('a5737bbee4d044d2cc3daa764e36bb8e', 'a17fe8e75c14b97942cb07688aaf429a');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Custom.TaintSharedContent
description: Detects tainted shared content via file drops on shares and programs run from shares
sources:
- name: FileCreationOnShares
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ProcessId AS ProcessId, EventData.Image AS Image,
           EventData.TargetFilename AS TargetFilename, EventData.ProcessGuid AS ProcessGuid
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 11
      AND EventData.TargetFilename =~ '''(?i)^(\x5c\x5c[^\x5c]+\x5c[^\x5c]+\x5c|\x5cdevice\x5cmup\x5c|[a-z]:\x5c(users\x5cpublic|shares?|shared)\x5c).*\.(lnk|exe|dll|scr|bat|cmd|vbs|js|hta|ps1|url|desktop\.ini)$'''
- name: NetworkShareAccess
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.SubjectUserName AS User, EventData.IpAddress AS SourceIp,
           EventData.ShareName AS ShareName, EventData.RelativeTargetName AS RelativeTargetName, EventData.AccessMask AS AccessMask
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 5145
      AND NOT EventData.ShareName =~ '''(?i)IPC\$$'''
      AND EventData.RelativeTargetName =~ '''(?i)\.(lnk|exe|dll|scr|bat|cmd|vbs|js|hta|ps1|url)$|desktop\.ini$'''
      AND EventData.AccessList =~ '''%%4417|%%4418|%%4420|%%4423|%%1537'''
- name: ProcessExecutionFromShares
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.CommandLine AS CommandLine,
           EventData.ParentImage AS ParentImage, EventData.ProcessGuid AS ProcessGuid
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.Image =~ '''(?i)^(\x5c\x5c[^\x5c]+\x5c[^\x5c]+\x5c|\x5cdevice\x5cmup\x5c)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1080' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('055b61805c05de87a6c93503680f4191', '25afd01714a43533f15f1842fcd45783');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ProcessId AS ProcessId, EventData.Image AS Image, EventData.TargetFilename AS TargetFilename, EventData.ProcessGuid AS ProcessGuid FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 11 AND EventData.TargetFilename =~ '''(?i)^(\x5c\x5c[^\x5c]+\x5c[^\x5c]+\x5c|\x5cdevice\x5cmup\x5c|[a-z]:\x5c(users\x5cpublic|shares?|shared)\x5c).*\.(lnk|exe|dll|scr|bat|cmd|vbs|js|hta|ps1|url)$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1080' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('7a1eaaccf3d84bb28eeba91dc92b6628', 'a58359c37ecc34e34d3defabd8c81efb');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Custom.SystemInfoDiscovery
description: |
  T1082 System Information Discovery: systeminfo/hostname, OS/hardware WMI queries, `ver`, registry queries of
  the OS version key, from process creation (Sysmon 1, Security 4688) and PowerShell script blocks (4104,
  excluding Windows' and Program Files' own modules).
sources:
- name: SysmonProcessCreation
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessName,
           EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentProcess, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)\\(systeminfo|hostname)\.exe$'''
           OR EventData.CommandLine =~ '''(?i)(\bget-computerinfo\b|win32_(operatingsystem|computersystem|bios|processor|quickfixengineering)\b|\bwmic(\.exe)?"?\s+(/\S+\s+)*(os|computersystem|bios|cpu|qfe|baseboard)\b|\bcmd(\.exe)?"?\s+/[ck]\s+"?ver\b|reg(\.exe)?"?\s+query\s+"?HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion|\[environment\]::osversion|\bgwmi\b.*win32_)''')
- name: SecurityProcessCreation
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.NewProcessName AS ProcessName,
           EventData.CommandLine AS CommandLine, EventData.ParentProcessName AS ParentProcess, EventData.SubjectUserName AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688
      AND (EventData.NewProcessName =~ '''(?i)\\(systeminfo|hostname)\.exe$'''
           OR EventData.CommandLine =~ '''(?i)(\bget-computerinfo\b|win32_(operatingsystem|computersystem|bios|processor|quickfixengineering)\b|\bwmic(\.exe)?"?\s+(/\S+\s+)*(os|computersystem|bios|cpu|qfe|baseboard)\b|\bcmd(\.exe)?"?\s+/[ck]\s+"?ver\b|reg(\.exe)?"?\s+query\s+"?HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion)''')
- name: PowerShellScriptBlocks
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ScriptBlockText AS ScriptBlock,
           EventData.Path AS ScriptPath, System.Security.UserID AS UserSid
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
    WHERE System.EventID.Value = 4104
      AND EventData.ScriptBlockText =~ '''(?i)(\bget-computerinfo\b|win32_(operatingsystem|computersystem|bios)\b|\bsysteminfo(\.exe)?\b|\[environment\]::osversion)'''
      AND NOT EventData.Path =~ '''(?i)^C:\\(Windows|Program Files|Program Files \(x86\))\\'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1082' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('d1eec8491bc927abf7c3bb1e1fe56a80');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$LET sysmon = SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentProcess, EventData.User AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND (EventData.Image =~ '''(?i)\\(systeminfo|hostname)\.exe$''' OR EventData.CommandLine =~ '''(?i)(\bget-computerinfo\b|win32_(operatingsystem|computersystem|bios|processor|quickfixengineering)\b|\bwmic(\.exe)?"?\s+(/\S+\s+)*(os|computersystem|bios|cpu|qfe|baseboard)\b|\bcmd(\.exe)?"?\s+/[ck]\s+"?ver\b|reg(\.exe)?"?\s+query\s+"?HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion)''')
LET security = SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.NewProcessName AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentProcessName AS ParentProcess, EventData.SubjectUserName AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx') WHERE System.EventID.Value = 4688 AND (EventData.NewProcessName =~ '''(?i)\\(systeminfo|hostname)\.exe$''' OR EventData.CommandLine =~ '''(?i)(\bget-computerinfo\b|win32_(operatingsystem|computersystem|bios|processor|quickfixengineering)\b|\bwmic(\.exe)?"?\s+(/\S+\s+)*(os|computersystem|bios|cpu|qfe|baseboard)\b|\bcmd(\.exe)?"?\s+/[ck]\s+"?ver\b|reg(\.exe)?"?\s+query\s+"?HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion)''')
SELECT * FROM chain(a={SELECT * FROM sysmon}, b={SELECT * FROM if(condition=len(list=sysmon)=0, then={SELECT * FROM security})})
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1082' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('1518f2c52b3502809ed684a0d9d4586b');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.T1090_002_ExternalProxy
description: |
  External proxy use: script hosts / LOLBins connecting out to public addresses on non-web ports (Sysmon 3),
  proxy and tunnelling tools started on the host (Sysmon 1), and per-user proxy settings in the registry.
sources:
- name: SysmonNetworkConnections
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.Image AS ProcessName, EventData.DestinationIp AS DestinationIp,
           EventData.DestinationPort AS DestinationPort, EventData.DestinationHostname AS DestinationHostname
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 3
      AND EventData.Initiated
      AND EventData.Image =~ '''(?i)\\(rundll32|mshta|wscript|cscript|powershell|pwsh|regsvr32|plink|ssh|socat|ncat|nc|htran|chisel|ngrok|frpc|tor)\.exe$'''
      AND NOT EventData.DestinationPort IN (80, 443, 53)
      AND NOT EventData.DestinationIp =~ '''^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|0:0:0:0:0:0:0:1|::1|fe80:)'''
- name: ProxyRegistrySettings
  query: |
    SELECT OSPath.Path AS Key, Data.value AS ProxyServer, Mtime AS LastWrite
    FROM glob(globs='HKEY_USERS/*/Software/Microsoft/Windows/CurrentVersion/Internet Settings/ProxyServer', accessor='registry')
    WHERE Data.value
- name: SysmonProcessCreation
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)\\(htran|zxproxy|zxportmap|proxychains|socat|chisel|ngrok|frpc|ligolo|tor|plink)\.exe$'''
           OR EventData.CommandLine =~ '''(?i)(htran|zxproxy|zxportmap|proxychains|socat\s.*tcp|\bnc(\.exe)?\s.*-e\s|chisel\s+client|ngrok\s+tcp|plink.*\s-[RLD]\s|ssh(\.exe)?\s.*\s-[RLD]\s)''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1090.002' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('a1840bc16ad0c12afc2b2093824b25e4', 'adabdb775bd9df99c16b185343091ea1');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessName, EventData.DestinationIp AS DestinationIp, EventData.DestinationPort AS DestinationPort, EventData.Protocol AS Protocol FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 3 AND EventData.Initiated AND EventData.Image =~ '''(?i)\\(rundll32|mshta|wscript|cscript|powershell|pwsh|regsvr32|plink|ssh|socat|ncat|nc|htran|chisel|ngrok|frpc|tor)\.exe$''' AND NOT EventData.DestinationPort IN (80, 443, 53) AND NOT EventData.DestinationIp =~ '''^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|0:0:0:0:0:0:0:1|::1|fe80:)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1090.002' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('146933eaa506c9579437aa73c34f5484', 'b3d7e89f9f7c234f1eb6030fe31d8714');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.Forensics.ScreenCaptureHunt
description: |
  Detect screen capture activity: screen capture tools and APIs in process
  command lines and PowerShell, Windows Recall policy removal, capture image
  files in user/temp folders, and prefetch of capture tools.
author: DFIR Team
type: CLIENT
sources:
- name: SysmonProcessCreation
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.Image AS ProcessPath, EventData.CommandLine AS CommandLine,
           EventData.ParentImage AS ParentImage, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)\x5c(screencap\w*|nircmd\w*|screenshot\w*|bmc-tools\w*)\.exe$'''
           OR EventData.CommandLine =~ '''(?i)CopyFromScreen|BitBlt|PrintWindow|Get-Screenshot|Invoke-Screenshot|\bpsr(\.exe)?\s+/start|nircmd(c)?(\.exe)?\s+savescreenshot|bmc-tools|DisableAIDataAnalysis''')
- name: SecurityProcessCreation
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.NewProcessName AS ProcessPath, EventData.CommandLine AS CommandLine,
           EventData.ParentProcessName AS ParentImage, EventData.SubjectUserName AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688
      AND (EventData.NewProcessName =~ '''(?i)\x5c(screencap\w*|nircmd\w*|screenshot\w*|bmc-tools\w*)\.exe$'''
           OR EventData.CommandLine =~ '''(?i)CopyFromScreen|BitBlt|PrintWindow|Get-Screenshot|Invoke-Screenshot|\bpsr(\.exe)?\s+/start|nircmd(c)?(\.exe)?\s+savescreenshot|bmc-tools|DisableAIDataAnalysis''')
- name: PowerShellScriptBlocks
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.ScriptBlockText AS ScriptBlock, EventData.Path AS ScriptPath
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
    WHERE System.EventID.Value = 4104
      AND EventData.ScriptBlockText =~ '''(?i)CopyFromScreen|Get-Screenshot|Invoke-Screenshot|PrintWindow\(|BitBlt\('''
- name: CaptureImageFiles
  query: |
    SELECT OSPath, Size, Mtime, Btime
    FROM glob(globs=['C:/Users/*/AppData/Local/Temp/**', 'C:/Users/*/AppData/Roaming/**', 'C:/Users/Public/**',
                     'C:/ProgramData/**', 'C:/Windows/Temp/**', 'C:/temp/**', 'C:/tmp/**'])
    WHERE NOT IsDir
      AND Name =~ '''(?i)(screen|capture|shot|desktop|snap)[^\x5c]*\.(bmp|png|jpe?g|tiff?|gif|zip|mht)$'''
      AND NOT OSPath =~ '''(?i)\x5cMicrosoft\x5cWindows\x5cSystemData\x5c|\x5cLockScreen|\x5cMicrosoft\x5c(Edge|Teams|OneDrive)\x5c|\x5cGoogle\x5cChrome\x5c'''
- name: PrefetchScreenCapture
  query: |
    SELECT Executable, RunCount, LastRunTimes, ExecutablePath
    FROM Artifact.Windows.Forensics.Prefetch()
    WHERE Executable =~ '''(?i)^(screencap|nircmd|screenshot|psr\.exe|bmc-tools)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1113' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('c565bf5e690574e2fdd086348e2f6cc4', '6f1254b704058f548be6d4d427d1296b');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessPath, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.User AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND (EventData.Image =~ '''(?i)\x5c(screencap\w*|nircmd\w*|screenshot\w*|bmc-tools\w*)\.exe$''' OR EventData.CommandLine =~ '''(?i)CopyFromScreen|BitBlt|PrintWindow|Get-Screenshot|Invoke-Screenshot|\bpsr(\.exe)?\s+/start|nircmd(c)?(\.exe)?\s+savescreenshot|bmc-tools|DisableAIDataAnalysis''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1113' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('3611691f2796447303057f650c26e151', 'dc5ace9ff92e55754b86ee0fecb0bc2f');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.AudioCapture
description: Detect T1123 Audio Capture across multiple data sources
sources:
- name: AudioAPIAccess
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.SourceImage AS ProcessImage, EventData.TargetImage AS TargetImage,
           EventData.GrantedAccess AS GrantedAccess, EventData.CallTrace AS CallTrace
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 10 AND EventData.TargetImage =~ '''(?i)\x5caudiodg\.exe$'''
      AND NOT EventData.SourceImage =~ '''(?i)\x5c(teams|ms-teams|zoom|discord|skype|svchost|audiodg|msmpeng|csrss|lsass|wmiprvse|taskmgr|procexp64|vmtoolsd)\.exe$'''
- name: AudioFileCreation
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessImage, EventData.TargetFilename AS TargetFilename
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 11 AND EventData.TargetFilename =~ '''(?i)\.(wav|mp3|m4a|aiff?|wma|ogg|opus|flac)$'''
      AND NOT EventData.TargetFilename =~ '''(?i)\x5cusers\x5c[^\x5c]+\x5c(music|onedrive[^\x5c]*\x5cmusic)\x5c|\x5cwindows\x5c(media|winsxs|systemapps)\x5c|\x5cprogram files'''
- name: AudioCaptureCommands
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.CommandLine AS CommandLine,
           EventData.ParentImage AS ParentImage, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.CommandLine =~ '''(?i)(soundrecorder(\.exe)?\s.*/file|ffmpeg.*-f\s+(dshow|wasapi)|sox(\.exe)?\s.*-d|get-audiodevice|audiodevicecmdlets|windowsaudiodevice-powershell-cmdlet|mciSendString|record\s+capture)'''
- name: MicrophoneConsentStore
  query: |
    SELECT Key.OSPath AS Key, timestamp(winfiletime=LastUsedTimeStart) AS LastUsedStart, timestamp(winfiletime=LastUsedTimeStop) AS LastUsedStop
    FROM read_reg_key(globs=['HKEY_USERS/*/Software/Microsoft/Windows/CurrentVersion/CapabilityAccessManager/ConsentStore/microphone/NonPackaged/*',
                             'HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/CapabilityAccessManager/ConsentStore/microphone/NonPackaged/*'])
    WHERE LastUsedTimeStop
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1123' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('c17d2087f2a089cb5d375dc09cb8a654', 'bafe02529e68eaf644d5ae6d528627cd');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.Image AS Image, EventData.SourceImage AS SourceImage, EventData.TargetImage AS TargetImage, EventData.CommandLine AS CommandLine FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE (System.EventID.Value = 1 AND EventData.CommandLine =~ '''(?i)(soundrecorder(\.exe)?\s.*/file|ffmpeg.*-f\s+(dshow|wasapi)|sox(\.exe)?\s.*-d|get-audiodevice|audiodevicecmdlets|windowsaudiodevice-powershell-cmdlet|mciSendString|record\s+capture)''') OR (System.EventID.Value = 10 AND EventData.TargetImage =~ '''(?i)\x5caudiodg\.exe$''' AND NOT EventData.SourceImage =~ '''(?i)\x5c(teams|ms-teams|zoom|discord|skype|svchost|audiodg|msmpeng|csrss|lsass|wmiprvse|taskmgr|procexp64|vmtoolsd)\.exe$''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1123' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('1fdacecd096827ab30c5dd943a96058d', '3c898fa3fa0da7cbcc8c3dcbe6ea2a21');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.Windows.DataEncoding.Detection
description: |
  T1132 Data Encoding: encoded command lines and payloads (base64 -EncodedCommand, FromBase64String,
  certutil -encode/-decode, long base64 blobs), script hosts talking to the network on non-standard ports,
  encoded commands in PowerShell script blocks and console history.
sources:
- name: EncodedCommandLines
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image,
           EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.CommandLine =~ '''(?i)(\s-e(nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{20,}|frombase64string|tobase64string|certutil(\.exe)?"?\s+.*-(en|de)code|\bbase64\s+(-d|--decode)|[A-Za-z0-9+/]{120,}={0,2})'''
      AND NOT EventData.Image =~ '''(?i)\\(msedgewebview2|msedge|chrome|firefox|brave|opera|teams|ms-teams|code|slack|discord|onedrive|searchprotocolhost)\.exe$'''
- name: ScriptHostNetwork
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image,
           EventData.DestinationIp AS DestinationIp, EventData.DestinationHostname AS DestinationHostname,
           EventData.DestinationPort AS DestinationPort, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 3
      AND EventData.Image =~ '''(?i)\\(powershell|pwsh|cmd|regsvr32|rundll32|mshta|wscript|cscript|certutil|bitsadmin)\.exe$'''
      AND NOT EventData.DestinationPort IN (80, 443, 53, 135, 445, 5985, 5986)
      AND NOT EventData.DestinationIp =~ '''^(127\.|::1$|0:0:0:0:0:0:0:1$)'''
- name: PowerShellScriptBlocks
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ScriptBlockText AS ScriptBlockText,
           EventData.Path AS Path
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
    WHERE System.EventID.Value = 4104
      AND EventData.ScriptBlockText =~ '''(?i)(frombase64string|tobase64string|\[convert\]::|system\.io\.compression\.(gzipstream|deflatestream)|[A-Za-z0-9+/]{200,}={0,2})'''
      AND NOT EventData.Path =~ '''(?i)^C:\\(Windows|Program Files|Program Files \(x86\))\\'''
- name: ConsoleHistory
  query: |
    SELECT * FROM foreach(
      row={SELECT OSPath, Mtime FROM glob(globs='C:/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt')},
      query={SELECT OSPath, Mtime, Line FROM parse_lines(filename=OSPath)
             WHERE Line =~ '''(?i)(\s-e(nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{20,}|frombase64string|tobase64string|certutil.*-(en|de)code|[A-Za-z0-9+/]{120,}={0,2})'''})
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1132' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('4d52ed237666f8a728c310b9a6db5407', '3123eac53fe9282ba644ce0f5aef7b28');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.User AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND EventData.CommandLine =~ '''(?i)(\s-e(nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{20,}|frombase64string|tobase64string|certutil(\.exe)?"?\s+.*-(en|de)code|\bbase64\s+(-d|--decode)|[A-Za-z0-9+/]{120,}={0,2})''' AND NOT EventData.Image =~ '''(?i)\\(msedgewebview2|msedge|chrome|firefox|brave|opera|teams|ms-teams|code|slack|discord|onedrive|searchprotocolhost)\.exe$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1132' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('77b78d5728a2573125cc113213855126', '2d58d3ed33f7a34db952db2e42f6618a');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Hunt.T1133.ExternalRemoteServices
description: |
  External remote services on a Windows host: network/RDP logons and failed logons from addresses outside
  the private ranges (Security 4624/4625), RDP authentications with their source address (RemoteConnectionManager
  1149), NTLM validations for remote workstations (4776), and VPN / remote-access browser extensions forced in
  through the registry (Sysmon 13).
sources:
  - name: ExternalLogons
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
             EventData.LogonType AS LogonType, EventData.IpAddress AS IpAddress, EventData.TargetUserName AS TargetUserName,
             EventData.WorkstationName AS WorkstationName, EventData.LogonProcessName AS LogonProcess
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value IN (4624, 4625)
        AND EventData.LogonType IN (3, 10)
        AND EventData.IpAddress =~ '''^[0-9a-fA-F:.]+$'''
        AND NOT EventData.IpAddress =~ '''^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|::1$|fe80:|0\.0\.0\.0|-$)'''
  - name: RDPAuthentications
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             UserData.EventXML.Param1 AS User, UserData.EventXML.Param2 AS Domain, UserData.EventXML.Param3 AS SourceAddress
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx')
      WHERE System.EventID.Value = 1149
  - name: NTLMValidationRemote
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.TargetUserName AS TargetUserName, EventData.Workstation AS Workstation,
             format(format='0x%x', args=EventData.Status) AS Status
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value = 4776
        AND EventData.Workstation AND lowcase(string=EventData.Workstation) != lowcase(string=System.Computer)
        AND NOT lowcase(string=System.Computer) =~ lowcase(string=EventData.Workstation)
  - name: VPNBrowserExtensionsForced
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.Image AS Image, EventData.TargetObject AS TargetObject, EventData.Details AS Details
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value IN (12, 13)
        AND EventData.TargetObject =~ '''(?i)\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser)\\(Extensions|ExtensionInstallForcelist)\\'''
  - name: ExternalBrowserExtensionsRegistry
    query: |
      SELECT OSPath.Path AS Key, Mtime AS LastWrite
      FROM glob(globs=['HKEY_LOCAL_MACHINE/SOFTWARE/Google/Chrome/Extensions/*',
                       'HKEY_LOCAL_MACHINE/SOFTWARE/Wow6432Node/Google/Chrome/Extensions/*',
                       'HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Edge/Extensions/*',
                       'HKEY_LOCAL_MACHINE/SOFTWARE/Wow6432Node/Microsoft/Edge/Extensions/*'], accessor='registry')
      WHERE IsDir
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1133' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('2f54914c3992fcc77b3501be73a06af9');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.LogonType AS LogonType, EventData.IpAddress AS IpAddress, EventData.TargetUserName AS TargetUserName, EventData.WorkstationName AS WorkstationName, EventData.LogonProcessName AS LogonProcess FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx') WHERE System.EventID.Value IN (4624, 4625) AND EventData.LogonType IN (3, 10) AND EventData.IpAddress =~ '''^[0-9a-fA-F:.]+$''' AND NOT EventData.IpAddress =~ '''^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|::1$|fe80:|0\.0\.0\.0|-$)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1133' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('cfe069fd8fe5888aef0d1889b7485379', '9f8ee44dd732c9acd00fc59f485411ec');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.TokenImpersonation
description: Token impersonation / theft - processes running as SYSTEM started by a normal user's process, known token-theft tools, and handles opened on SYSTEM processes with token-duplication rights
sources:
- name: SecurityLogAnalysis
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.NewProcessName AS ProcessName, EventData.CommandLine AS CommandLine,
           EventData.ParentProcessName AS ParentProcess, EventData.SubjectUserName AS CreatorUser,
           EventData.TargetUserName AS ProcessUser, EventData.TokenElevationType AS TokenElevationType
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688
      AND ((EventData.TargetUserSid = 'S-1-5-18' AND EventData.SubjectUserSid =~ '''^S-1-5-21-''')
           OR EventData.NewProcessName =~ '''(?i)\x5c(NSudo\w*|\w*Potato\w*|incognito|Tokenvator|PrintSpoofer\w*|RoguePotato|GodPotato)\.exe$'''
           OR EventData.CommandLine =~ '''(?i)Get-System|Invoke-TokenManipulation|Invoke-RunAs|-U:T\s|-U:S\s|steal_token|make_token''')
- name: SysmonProcessCreation
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.Image AS ProcessName, EventData.CommandLine AS CommandLine, EventData.User AS ProcessUser,
           EventData.ParentImage AS ParentProcess, EventData.ParentUser AS ParentUser, EventData.IntegrityLevel AS IntegrityLevel
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND ((EventData.User =~ '''(?i)^NT AUTHORITY\x5cSYSTEM$''' AND EventData.ParentUser =~ '''\x5c'''
            AND NOT EventData.ParentUser =~ '''(?i)^NT AUTHORITY\x5c|^Window Manager\x5c|^Font Driver Host\x5c''')
           OR EventData.Image =~ '''(?i)\x5c(NSudo\w*|\w*Potato\w*|incognito|Tokenvator|PrintSpoofer\w*)\.exe$'''
           OR EventData.CommandLine =~ '''(?i)Get-System|Invoke-TokenManipulation|-U:T\s|-U:S\s|steal_token|make_token''')
- name: SysmonProcessAccess
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.SourceImage AS SourceImage, EventData.SourceUser AS SourceUser,
           EventData.TargetImage AS TargetImage, EventData.TargetUser AS TargetUser,
           format(format='0x%x', args=EventData.GrantedAccess) AS GrantedAccess, EventData.CallTrace AS CallTrace
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 10
      AND EventData.TargetUser =~ '''(?i)^NT AUTHORITY\x5cSYSTEM$'''
      AND NOT EventData.SourceUser =~ '''(?i)^NT AUTHORITY\x5c'''
      AND int(int=EventData.GrantedAccess / 64) - 2 * int(int=EventData.GrantedAccess / 128) = 1
      AND EventData.TargetImage =~ '''(?i)\x5c(winlogon|lsass|services|spoolsv|svchost|TrustedInstaller)\.exe$'''
      AND EventData.SourceImage =~ '''(?i)\x5c(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript)\.exe$|\x5c(Users|ProgramData|Windows\x5cTemp|PerfLogs|AtomicRedTeam|ExternalPayloads)\x5c'''
- name: ElevatedLogons
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.SubjectUserName AS CallerUser, EventData.TargetUserName AS TargetUser, EventData.LogonType AS LogonType,
           EventData.LogonProcessName AS LogonProcess, EventData.ProcessName AS ProcessName, EventData.IpAddress AS IpAddress
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4624 AND EventData.LogonType = 9
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1134.001' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('9fde1b69ecb3cb9d6e66741f17c9cd76');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, EventData.NewProcessName AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentProcessName AS ParentProcess, EventData.SubjectUserName AS CreatorUser, EventData.TargetUserName AS ProcessUser, EventData.TokenElevationType AS TokenElevationType FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx') WHERE System.EventID.Value = 4688 AND ((EventData.TargetUserSid = 'S-1-5-18' AND EventData.SubjectUserSid =~ '''^S-1-5-21-''') OR EventData.NewProcessName =~ '''(?i)\x5c(NSudo\w*|\w*Potato\w*|incognito|Tokenvator|PrintSpoofer\w*|RoguePotato|GodPotato)\.exe$''' OR EventData.CommandLine =~ '''(?i)Get-System|Invoke-TokenManipulation|Invoke-RunAs|-U:T\s|-U:S\s|steal_token|make_token''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1134.001' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('5c1759ba25ef2d46e7ee60f7e953fd4b');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.TokenManipulation.CreateProcess
description: |
  T1134.002 Create Process with Token: a process started under another account's token than its parent's
  (above all SYSTEM children of user processes), handle opens on token-holding system processes by
  non-system programs, and token-creation privileges held by ordinary accounts.
sources:
  - name: SysmonTokenSwitch
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.User AS User,
             EventData.ParentImage AS ParentImage, EventData.ParentUser AS ParentUser, EventData.CommandLine AS CommandLine,
             EventData.IntegrityLevel AS IntegrityLevel
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 1
        AND EventData.ParentUser AND EventData.ParentUser != '-' AND EventData.User != EventData.ParentUser
        AND NOT EventData.ParentUser =~ '''(?i)^(NT AUTHORITY|AUTORITE NT|NT-AUTORIT)'''
        AND NOT EventData.ParentImage =~ '''(?i)^c:\x5cwindows\x5c(system32|syswow64)\x5c(svchost|services|wininit|winlogon|smss|csrss|consent|lsass|userinit|msiexec|wbem\x5cwmiprvse)\.exe$'''
  - name: SecurityTokenSwitch
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.NewProcessName AS ProcessName,
             EventData.ParentProcessName AS ParentProcess, EventData.CommandLine AS CommandLine,
             EventData.SubjectUserName AS CreatorUser, EventData.SubjectLogonId AS CreatorLogonId,
             EventData.TargetUserName AS NewProcessUser, EventData.TargetLogonId AS NewProcessLogonId
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value = 4688
        AND EventData.TargetUserSid AND NOT EventData.TargetUserSid IN ('S-1-0-0', '-')
        AND EventData.TargetUserSid != EventData.SubjectUserSid
        AND NOT EventData.SubjectUserSid IN ('S-1-5-18', 'S-1-5-19', 'S-1-5-20')
        AND NOT EventData.SubjectUserName =~ '''\$$'''
        AND NOT EventData.ParentProcessName =~ '''(?i)^c:\x5cwindows\x5c(system32|syswow64)\x5c(svchost|services|wininit|winlogon|smss|csrss|consent|lsass|userinit|msiexec)\.exe$'''
  - name: TokenProcessAccess
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.SourceImage AS SourceProcess,
             EventData.SourceUser AS SourceUser, EventData.TargetImage AS TargetProcess,
             format(format='0x%x', args=EventData.GrantedAccess) AS Access, EventData.CallTrace AS CallTrace
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 10
        AND EventData.TargetImage =~ '''(?i)\x5c(lsass|winlogon|services|wininit|smss|spoolsv)\.exe$'''
        AND EventData.GrantedAccess IN (1024, 1040, 4096, 4112, 5120, 5136, 5176, 5178, 2035711, 2043903, 2097151)
        AND NOT EventData.SourceImage =~ '''(?i)^c:\x5c(windows\x5c(system32|syswow64)\x5c(svchost|services|wininit|winlogon|smss|csrss|lsass|wbem\x5cwmiprvse|taskmgr|searchindexer|securityhealthservice|sppsvc|werfault|wermgr|taskhostw|vssvc|dllhost|msiexec)\.exe|programdata\x5cmicrosoft\x5cwindows defender\x5c|program files( \(x86\))?\x5c(windows defender|vmware\x5cvmware tools|microsoft\x5cedgeupdate|google\x5c))'''
  - name: ProcessFromSystemParent
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.User AS User,
             EventData.ParentImage AS ParentImage, EventData.CommandLine AS CommandLine, EventData.IntegrityLevel AS IntegrityLevel
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 1
        AND EventData.ParentImage =~ '''(?i)\x5c(lsass|winlogon|spoolsv|wininit|csrss)\.exe$'''
        AND EventData.Image =~ '''(?i)\x5c(cmd|powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript|whoami|net1?|notepad|conhost)\.exe$'''
        AND NOT (EventData.ParentImage =~ '''(?i)\x5cwinlogon\.exe$''' AND EventData.Image =~ '''(?i)\x5c(userinit|fontdrvhost|dwm|logonui)\.exe$''')
  - name: TokenPrivileges
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.SubjectUserName AS Username,
             EventData.SubjectDomainName AS Domain, EventData.SubjectLogonId AS LogonId, EventData.PrivilegeList AS Privileges
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value = 4672
        AND EventData.PrivilegeList =~ '''SeTcbPrivilege|SeAssignPrimaryTokenPrivilege|SeCreateTokenPrivilege'''
        AND NOT EventData.SubjectUserSid IN ('S-1-5-18', 'S-1-5-19', 'S-1-5-20')
        AND NOT EventData.SubjectUserName =~ '''\$$|^(DWM|UMFD)-\d+$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1134.002' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('661474e6226311c6e9dd64077ee698e2');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.User AS User, EventData.ParentImage AS ParentImage, EventData.ParentUser AS ParentUser, EventData.CommandLine AS CommandLine FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND EventData.ParentUser AND EventData.ParentUser != '-' AND EventData.User != EventData.ParentUser AND NOT EventData.ParentUser =~ '''(?i)^(NT AUTHORITY|AUTORITE NT|NT-AUTORIT)''' AND NOT EventData.ParentImage =~ '''(?i)^c:\x5cwindows\x5c(system32|syswow64)\x5c(svchost|services|wininit|winlogon|smss|csrss|consent|lsass|userinit|msiexec|wbem\x5cwmiprvse)\.exe$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1134.002' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('8bdc798cf93df64b985707ec17c94faf');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Hardware.SupplyChain.Compromise
description: Detect hardware supply chain compromise through code integrity failures, boot/system-start drivers and unsigned driver loads
sources:
- name: CodeIntegrityViolations
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
           EventData.FileNameBuffer AS File, EventData.ProcessNameBuffer AS Process, EventData.RequestedSigningLevel AS RequestedSigningLevel,
           EventData.Status AS Status
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-CodeIntegrity%4Operational.evtx')
    WHERE System.EventID.Value IN (3001, 3002, 3004, 3023, 3033)
      AND EventData.FileNameBuffer =~ '''(?i)(\.sys$|\\drivers\\|boot|firmware|efi)'''
- name: BootOrSystemStartServices
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ServiceName AS ServiceName,
           EventData.ImagePath AS ImagePath, EventData.ServiceType AS ServiceType, EventData.StartType AS StartType
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx')
    WHERE System.EventID.Value = 7045
      AND EventData.StartType =~ '''(?i)^(boot|system) start$'''
- name: UnsignedDriverLoads
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ImageLoaded AS ImageLoaded,
           EventData.Signed AS Signed, EventData.Signature AS Signature, EventData.SignatureStatus AS SignatureStatus, EventData.Hashes AS Hashes
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 6
      AND (NOT EventData.Signed =~ '''(?i)^true$''' OR NOT EventData.SignatureStatus =~ '''(?i)^valid$''' OR EventData.ImageLoaded =~ '''(?i)(firmware|\\efi\\)''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1195.003' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('eedb2cc8fa4d19ad181ab52b2fe3eb8b', '470bd199219b987f1af4b8f17b18a19d');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ServiceName AS ServiceName, EventData.ImagePath AS ImagePath, EventData.ServiceType AS ServiceType, EventData.StartType AS StartType FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx') WHERE System.EventID.Value = 7045 AND EventData.StartType =~ '''(?i)^(boot|system) start$''' AND NOT EventData.ImagePath =~ '''(?i)\\windows\\system32\\drivers\\'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1195.003' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('5fabb2fa1fae4dedb2d819bfd17d50c7', '352f5f5bb8efb9ca3711ff761f417397');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.BITSJobs
description: |
  BITS job abuse: bitsadmin / BITS cmdlets in process creation and PowerShell script blocks, BITS jobs
  created by programs other than the usual Windows/browser updaters (Bits-Client/Operational 3), and BITS
  files queued from / transferred from hosts other than Microsoft/Google update services (Bits-Client/Operational 16403, 59).
sources:
- name: BITSProcessExecution
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.SubjectUserName AS User,
           EventData.NewProcessName AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentProcessName AS ParentProcess
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688
      AND (EventData.NewProcessName =~ '''(?i)\\bitsadmin\.exe$''' OR
           EventData.CommandLine =~ '''(?i)(Start-BitsTransfer|Add-BitsFile|Set-BitsTransfer|bitsadmin.*/(transfer|addfile|SetNotifyCmdLine|create))''')
- name: BITSJobsCreatedByUnusualProcess
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.jobTitle AS JobTitle, EventData.jobOwner AS JobOwner, EventData.processPath AS ProcessPath, EventData.jobId AS JobId
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Bits-Client%4Operational.evtx')
    WHERE System.EventID.Value = 3
      AND NOT EventData.processPath =~ '''(?i)\\(svchost|Microsoft\.SharePoint|FileCoAuth|MoUsoCoreWorker|usoclient|wuauclt|OneDrive|OneDriveSetup|MicrosoftEdgeUpdate|msedge|GoogleUpdate|chrome|updater|DeliveryOptimization|MsMpEng|MpCmdRun|backgroundTaskHost|SIHClient|CompatTelRunner|devicecensus|TiWorker|setuphost)\.exe$'''
- name: BITSTransfersToUnusualHosts
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           System.EventID.Value AS EventID, EventData.jobTitle || EventData.name AS JobName,
           EventData.RemoteName || EventData.url AS Url, EventData.LocalName AS LocalFile
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Bits-Client%4Operational.evtx')
    WHERE System.EventID.Value IN (16403, 59)
      AND NOT (EventData.RemoteName || EventData.url) =~ '''(?i)^https?://([a-z0-9-]+\.)*(microsoft\.com|windowsupdate\.com|windows\.com|msedge\.net|office\.com|office\.net|live\.com|bing\.com|msn\.com|azureedge\.net|akamaized\.net|google\.com|gvt1\.com|googleapis\.com|delivery\.mp\.microsoft\.com)(:[0-9]+)?/'''
- name: PowerShellBITSCommands
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ScriptBlockText AS ScriptBlockText
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
    WHERE System.EventID.Value = 4104
      AND EventData.ScriptBlockText =~ '''(?i)(Start-BitsTransfer|Add-BitsFile|Set-BitsTransfer|New-BitsTransfer)'''
      AND NOT EventData.ScriptBlockText =~ '''(?i)^\s*#'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1197' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('ef5b7847930c615ebc6089971d627052', '56288e330d1740e3d11bbdb000431c71');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.T1210.RemoteServiceExploitation
description: |
  Detect exploitation of remote services by correlating crashes of network-facing services with suspicious child processes of service hosts and anomalous network logons
sources:
- name: ServiceCrashes
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           System.EventID.Value AS EventID, EventData.param1 AS ServiceName, Message
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx')
    WHERE System.EventID.Value IN (7031, 7034)
      AND EventData.param1 =~ '''(?i)^(Server|Print Spooler|Remote Desktop Services|Windows Remote Management|Remote Procedure Call|DNS Server|DHCP Server|SNMP|Netlogon|Distributed Transaction Coordinator|Remote Registry|IIS Admin|World Wide Web Publishing|Microsoft Exchange|SQL Server|Workstation)'''
- name: ApplicationCrashes
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           System.EventID.Value AS EventID, EventData.Data[0] AS FaultingApplication, EventData.Data[3] AS FaultingModule, Message
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Application.evtx')
    WHERE System.EventID.Value = 1000
      AND format(format='%v', args=EventData.Data[0]) =~ '''(?i)^(spoolsv|lsass|svchost|w3wp|sqlservr|dns|dhcpserver|msexchange\w*|httpd|nginx|tomcat\w*|java)\.exe$'''
- name: SuspiciousProcessCreation
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.Image AS ProcessName, EventData.ParentImage AS ParentProcess,
           EventData.CommandLine AS CommandLine, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.ParentImage =~ '''(?i)\x5c(lsass|spoolsv|winlogon|w3wp|sqlservr|dns|msdtc|wsmprovhost)\.exe$'''
      AND EventData.Image =~ '''(?i)\x5c(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|whoami|net1?)\.exe$'''
- name: NetworkAuthentication
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           System.EventID.Value AS EventID, EventData.LogonType AS LogonType, EventData.IpAddress AS SourceIP,
           EventData.TargetUserName AS TargetUser, EventData.Status AS Status, EventData.AuthenticationPackageName AS AuthPackage
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value IN (4624, 4625) AND EventData.LogonType = 3
      AND NOT EventData.IpAddress =~ '''^(-|::1|127\.0\.0\.1)?$'''
      AND (EventData.TargetUserName = 'ANONYMOUS LOGON' OR format(format='%v', args=EventData.Status) =~ '''(?i)c000006d''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1210' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('51776238dac9133025e776537d47cd60', 'd010066f6ce244a59dec2fe9aeb16af5');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.param1 AS ServiceName, Message FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx') WHERE System.EventID.Value IN (7031, 7034) AND EventData.param1 =~ '''(?i)^(Server|Print Spooler|Remote Desktop Services|Windows Remote Management|Remote Procedure Call|DNS Server|DHCP Server|SNMP|Netlogon|Distributed Transaction Coordinator|Remote Registry|IIS Admin|World Wide Web Publishing|Microsoft Exchange|SQL Server|Workstation)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1210' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('4d06502ccb0e08380736955160b2ea30', '22aec1285ecd6f81aef7fd43e9dc6f0c');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.RemoteAccessHardware
description: |
  IP-KVM remote access hardware (TinyPilot, PiKVM and other Linux USB-gadget KVMs) plugged into the host:
  they enumerate as a USB composite device with the Linux Foundation vendor ID 1D6B (keyboard + mouse + storage).
  Kernel-PnP device configuration, Security 6416 (external device recognized) and the USB enumeration registry.
sources:
- name: PnPDeviceConfiguration
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
           EventData.DeviceInstanceId AS DeviceInstanceId, EventData.DriverName AS DriverName, EventData.ClassGuid AS ClassGuid
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Kernel-PnP%4Configuration.evtx')
    WHERE System.EventID.Value IN (400, 410)
      AND EventData.DeviceInstanceId =~ '''(?i)VID_1D6B|tinypilot|pikvm|kvm'''
- name: ExternalDeviceRecognized
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.DeviceId AS DeviceId,
           EventData.DeviceDescription AS DeviceDescription, EventData.ClassName AS ClassName, EventData.VendorIds AS VendorIds
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 6416
      AND format(format='%v %v %v', args=[EventData.DeviceId, EventData.DeviceDescription, EventData.VendorIds]) =~ '''(?i)VID_1D6B|tinypilot|pikvm|kvm|composite gadget'''
- name: USBRegistryArtifacts
  query: |
    SELECT Key.OSPath AS Key, Key.Mtime AS LastWritten, FriendlyName, DeviceDesc, Mfg
    FROM read_reg_key(globs='HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Enum/USB/*/*')
    WHERE format(format='%v %v %v %v', args=[Key.OSPath, FriendlyName, DeviceDesc, Mfg]) =~ '''(?i)VID_1D6B|tinypilot|pikvm|kvm|composite gadget'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1219.003' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('20646fffa54939de5e3bb08d19a5377e', '8e937b2cf1da3b037ded0c168bff5eec');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.DeviceInstanceId AS DeviceInstanceId, EventData.DriverName AS DriverName FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Kernel-PnP%4Configuration.evtx') WHERE System.EventID.Value IN (400, 410) AND EventData.DeviceInstanceId =~ '''(?i)VID_1D6B|tinypilot|pikvm|kvm'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1219.003' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('9c89d6356a24c84f62a49585b277ddb9');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Custom.InhibitSystemRecovery
description: Detect T1490 Inhibit System Recovery (shadow copy / backup catalog deletion, recovery disabled) across process, backup and registry evidence
sources:
- name: SysmonProcesses
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessName,
           EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.CommandLine =~ '''(?i)(vssadmin(\.exe)?"?\s+(delete\s+shadows|resize\s+shadowstorage)|wmic(\.exe)?"?\s+.*shadowcopy.*delete|win32_shadowcopy.*(delete|remove-)|bcdedit(\.exe)?"?\s+.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|wbadmin(\.exe)?"?\s+delete\s+(catalog|systemstatebackup|backup)|diskshadow.*delete\s+shadows|reagentc(\.exe)?"?\s+/disable|disable-computerrestore)'''
- name: SecurityProcesses
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.NewProcessName AS ProcessName,
           EventData.CommandLine AS CommandLine, EventData.ParentProcessName AS ParentImage, EventData.SubjectUserName AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688
      AND EventData.CommandLine =~ '''(?i)(vssadmin(\.exe)?"?\s+(delete\s+shadows|resize\s+shadowstorage)|wmic(\.exe)?"?\s+.*shadowcopy.*delete|bcdedit(\.exe)?"?\s+.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|wbadmin(\.exe)?"?\s+delete\s+(catalog|systemstatebackup|backup)|reagentc(\.exe)?"?\s+/disable)'''
- name: BackupCatalogDeleted
  query: |
    SELECT * FROM chain(
      a={SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
                System.Provider.Name AS Provider, EventData AS Details
         FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Application.evtx')
         WHERE System.EventID.Value = 524 AND System.Provider.Name =~ '''(?i)backup'''},
      b={SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
                System.Provider.Name AS Provider, EventData AS Details
         FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Backup.evtx')
         WHERE System.EventID.Value = 524})
- name: RegistryChanges
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image,
           EventData.TargetObject AS TargetObject, EventData.Details AS Details
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value IN (12, 13, 14)
      AND EventData.TargetObject =~ '''(?i)(\\SystemRestore\\(DisableSR|DisableConfig)$|\\Policies\\Microsoft\\Windows NT\\SystemRestore|\\Services\\(VSS|wbengine|swprv)\\Start$|\\BootStatusPolicy|\\Control\\BackupRestore\\FilesNotToSnapshot)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1490' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('bc10dfd50d625510c6f53c1887261338', 'dd93e8d885098062ea0ce27fb65521f7');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.ParentCommandLine AS ParentCommandLine FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND EventData.CommandLine =~ '''(?i)(vssadmin(\.exe)?"?\s+(delete\s+shadows|resize\s+shadowstorage)|wmic(\.exe)?"?\s+.*shadowcopy.*delete|win32_shadowcopy.*(delete|remove-)|bcdedit(\.exe)?"?\s+.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|wbadmin(\.exe)?"?\s+delete\s+(catalog|systemstatebackup|backup)|diskshadow.*delete\s+shadows|reagentc(\.exe)?"?\s+/disable|disable-computerrestore)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1490' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('e9ed9dd434ca78c41536216c99b9d63b', '620ed32089c7ec7d15ffd515d9f57e69');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.ComputeHijacking
description: |
  Detects cryptocurrency mining / compute hijacking (ATT&CK T1496.001): miner binaries and command lines,
  connections to mining pools / stratum ports, scheduled tasks that start miners. parse_evtx() takes
  filename=, not file= (verify failed, so this never ran); Sysmon DestinationPort is a number.
sources:
- name: SuspiciousProcessCreation
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.Image AS ProcessPath, EventData.CommandLine AS CommandLine,
           EventData.ParentImage AS ParentProcess, EventData.Hashes AS Hashes
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1 AND (
        EventData.Image =~ '''(?i)\\(xmrig|cpuminer|cgminer|bfgminer|sgminer|ccminer|nbminer|t-rex|phoenixminer|lolminer|nanominer)[^\\]*\.exe$'''
        OR EventData.OriginalFileName =~ '''(?i)xmrig'''
        OR EventData.CommandLine =~ '''(?i)(stratum\+(tcp|ssl)://|--donate-level|--coin[ =]|--algo[ =]|-o [a-z0-9.-]*pool|cryptonight|randomx|monero)'''
        OR (EventData.Image =~ '''(?i)\\(svchost|csrss|winlogon|lsass|services)\.exe$'''
            AND NOT EventData.Image =~ '''(?i)^C:\\Windows\\(System32|SysWOW64)\\''')
      )
- name: SecurityProcessCreation
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.NewProcessName AS ProcessPath, EventData.CommandLine AS CommandLine,
           EventData.ParentProcessName AS ParentProcess
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688 AND (
        EventData.NewProcessName =~ '''(?i)\\(xmrig|cpuminer|cgminer|bfgminer|sgminer|ccminer|nbminer|t-rex|phoenixminer|lolminer|nanominer)[^\\]*\.exe$'''
        OR EventData.CommandLine =~ '''(?i)(stratum\+(tcp|ssl)://|--donate-level|--coin[ =]|--algo[ =]|cryptonight|randomx)'''
      )
- name: MiningPoolConnections
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.Image AS ProcessPath, EventData.DestinationIp AS DestIP,
           EventData.DestinationHostname AS DestHost, EventData.DestinationPort AS DestPort
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 3 AND (
        EventData.DestinationPort IN (3333, 3334, 5555, 7777, 8333, 9999, 14433, 14444, 45560)
        OR EventData.DestinationHostname =~ '''(?i)(pool\.|mining|minexmr|nanopool|2miners|f2pool|ethermine|nicehash|supportxmr|moneroocean|hashvault|herominers)'''
      )
- name: MiningPoolDns
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.Image AS ProcessPath, EventData.QueryName AS Query
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 22
      AND EventData.QueryName =~ '''(?i)(minexmr|nanopool|2miners|f2pool|ethermine|nicehash|supportxmr|moneroocean|hashvault|herominers|xmrpool|c3pool)'''
- name: SuspiciousScheduledTasks
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.TaskName AS TaskName, EventData.TaskContent AS TaskContent
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4698
      AND EventData.TaskContent =~ '''(?i)(xmrig|cpuminer|stratum|--donate-level|cryptonight|randomx)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1496.001' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('3a8ad23c7743e3d2a04963f83249cd6f', '76c385e0ec9925e866a242ad1ddf9cd1');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Custom.T1499001.OSExhaustionFlood
description: |
  OS exhaustion flood: TCP/IP resource exhaustion warnings in the System log (Tcpip 4226/4227/4231),
  flooding tools started on the host (Sysmon 1), and bursts of more than 100 inbound TCP connections per
  minute from one address in Windows Filtering Platform auditing (Security 5156, if that auditing is on).
sources:
- name: TCPIPEvents
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           System.EventID.Value AS EventID, System.Provider.Name AS Provider, Message
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx')
    WHERE System.EventID.Value IN (4226, 4227, 4231)
      AND System.Provider.Name =~ '''(?i)tcpip'''
- name: SysmonProcesses
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)\\(hping\d?|nping|scapy|loic|hoic|slowloris|thc-ssl-dos|synflood)[^\\]*\.exe$'''
           OR EventData.CommandLine =~ '''(?i)(syn[-_ ]?flood|ack[-_ ]?flood|tcp[-_ ]?flood|udp[-_ ]?flood|--flood|slowloris)''')
- name: FirewallConnectionBursts
  query: |
    LET conns = SELECT EventData.SourceAddress AS SourceAddress, EventData.DestPort AS DestPort,
                       int(int=System.TimeCreated.SystemTime / 60) * 60 AS Minute, System.Computer AS Computer
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value = 5156 AND str(str=EventData.Protocol) = '6' AND str(str=EventData.Direction) =~ '14592|Inbound'
    SELECT * FROM foreach(row={
      SELECT SourceAddress, DestPort, Computer, timestamp(epoch=Minute) AS EventTime, count() AS ConnectionCount
      FROM conns GROUP BY SourceAddress, DestPort, Minute
    }) WHERE ConnectionCount > 100
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1499.001' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('5038d35787659f94b8c25effeddf94d1', '5a499fe74689c98f447014d397ec8a2f');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, System.Provider.Name AS Provider, Message FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx') WHERE System.EventID.Value IN (4226, 4227, 4231) AND System.Provider.Name =~ '''(?i)tcpip'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1499.001' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('c489540c9c1a210628087c20c07cd9b5');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Custom.ServiceExhaustionFlood
description: Detect endpoint denial of service via service exhaustion floods - many inbound connections to web/remote service ports from one source, web server / service crashes, and web server logs
sources:
- name: SysmonInboundFlood
  query: |
    SELECT * FROM foreach(row={
      SELECT SourceIP, Port, Process, min(item=EventTime) AS FirstSeen, max(item=EventTime) AS LastSeen,
             count() AS Connections, Computer
      FROM foreach(row={
          SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
                 EventData.SourceIp AS SourceIP, EventData.DestinationPort AS Port, EventData.Image AS Process,
                 format(format='%v|%v', args=[EventData.SourceIp, EventData.DestinationPort]) AS Key
          FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
          WHERE System.EventID.Value = 3 AND NOT EventData.Initiated
            AND EventData.DestinationPort IN (80, 443, 8080, 8443, 3389, 445, 5985, 5986, 21, 25)})
      GROUP BY Key})
    WHERE Connections > 500
- name: ServiceCrashes
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           System.EventID.Value AS EventID, EventData.Data[0] AS FaultingApplication, Message
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Application.evtx')
    WHERE System.EventID.Value IN (1000, 1002)
      AND format(format='%v', args=EventData.Data[0]) =~ '''(?i)^(w3wp|httpd|nginx|tomcat\w*|java|sqlservr|svchost|lsass|spoolsv)\.exe$'''
- name: HttpServiceErrors
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           System.EventID.Value AS EventID, Message
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx')
    WHERE System.EventID.Value IN (5010, 5011, 5013, 5117, 5186, 7031, 7034)
      AND Message =~ '''(?i)(application pool|w3svc|world wide web|http|iis|web)'''
- name: WebServerLogs
  query: |
    SELECT OSPath, Mtime, Size
    FROM glob(globs=['C:/inetpub/logs/LogFiles/**/*.log', 'C:/Windows/System32/LogFiles/HTTPERR/*.log'])
    WHERE NOT IsDir
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1499.002' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('676b19a2ee96a0af7a1c553f7dbe8035', 'ff151307cb10511e5b47247666e05f0b');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT * FROM foreach(row={SELECT SourceIP, Port, Process, min(item=EventTime) AS FirstSeen, max(item=EventTime) AS LastSeen, count() AS Connections, Computer FROM foreach(row={SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, EventData.SourceIp AS SourceIP, EventData.DestinationPort AS Port, EventData.Image AS Process, format(format='%v|%v', args=[EventData.SourceIp, EventData.DestinationPort]) AS Key FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 3 AND NOT EventData.Initiated AND EventData.DestinationPort IN (80, 443, 8080, 8443, 3389, 445, 5985, 5986, 21, 25)}) GROUP BY Key}) WHERE Connections > 500
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1499.002' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('349197fe3f6df3bd5116311cb503b2a3', 'b95508e01b7ed1c146cda5550d4d5591');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Custom.ApplicationExhaustionFlood
description: |
  Application exhaustion flood against a service on this host: crashes/hangs of server applications,
  resource-exhaustion and unexpected-shutdown events, and flood tools run from the host.
sources:
- name: ServerApplicationCrashes
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
           System.Provider.Name AS Provider, EventData.Data AS Details
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Application.evtx')
    WHERE System.EventID.Value IN (1000, 1002, 1026)
      AND System.Provider.Name =~ '''(?i)^(Application Error|Application Hang|\.NET Runtime)$'''
      AND format(format='%v', args=EventData.Data) =~ '''(?i)(w3wp|httpd|nginx|apache|sqlservr|java|javaw|tomcat\d*|node|iisexpress|php-cgi|MSExchange\w*|inetinfo|dns|dhcp|lsass|smss|termsrv|svchost)\.exe'''
- name: ResourceExhaustion
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
           System.Provider.Name AS Provider, EventData AS Details
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx')
    WHERE (System.EventID.Value = 2004 AND System.Provider.Name =~ '''(?i)Resource-Exhaustion''')
       OR (System.EventID.Value = 6008 AND System.Provider.Name =~ '''(?i)^EventLog$''')
       OR (System.EventID.Value IN (2019, 2020) AND System.Provider.Name =~ '''(?i)^srv$''')
- name: FloodTools
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.CommandLine AS CommandLine,
           EventData.ParentImage AS ParentImage, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)\x5c(loic|hoic|hping3?|slowloris|goldeneye|siege|wrk|bombardier|vegeta|torshammer|xerxes|slowhttptest|ab)\.exe$'''
        OR EventData.CommandLine =~ '''(?i)(slowloris|slowhttptest|goldeneye|torshammer|bombardier|\bab(\.exe)?"?\s+-n\s+\d{4,}|hping3?\s.*--flood|while\s*\(\$?true\).*invoke-webrequest)''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1499.003' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('a78809aae6cc6224fdb7da8727fa885f', '3ae39a33061ba02aec34dfc049153a16');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, System.Provider.Name AS Provider, EventData.Data AS Details FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Application.evtx') WHERE System.EventID.Value IN (1000, 1002, 1026) AND System.Provider.Name =~ '''(?i)^(Application Error|Application Hang|\.NET Runtime)$''' AND format(format='%v', args=EventData.Data) =~ '''(?i)(w3wp|httpd|nginx|apache|sqlservr|java|javaw|tomcat\d*|node|iisexpress|php-cgi|MSExchange\w*|inetinfo|dns|dhcp|lsass|smss|termsrv|svchost)\.exe'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1499.003' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('c6a83a702afd27b88b53da7ac2bd9c6b');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.ComponentFirmware
description: Detect component firmware manipulation via unsigned/invalid storage, controller or firmware drivers and driver load failures
sources:
- name: SuspiciousFirmwareDrivers
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ImageLoaded AS ImageLoaded,
           EventData.Hashes AS Hashes, EventData.Signed AS Signed, EventData.Signature AS Signature, EventData.SignatureStatus AS SignatureStatus
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 6
      AND EventData.ImageLoaded =~ '''(?i)(firmware|flash|nvme|stor|disk|controller|bios|uefi|efi|spi|smm)'''
      AND (NOT EventData.Signed =~ '''(?i)^true$''' OR NOT EventData.SignatureStatus =~ '''(?i)^valid$''')
- name: DriverLoadFailures
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.DriverName AS DriverName,
           EventData.FailureName AS FailureName, EventData.Status AS Status
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx')
    WHERE System.EventID.Value = 219
      AND EventData.FailureName =~ '''(?i)(nvme|stor|sata|scsi|disk|firmware|uefi|bios|spi|smm)'''
      AND NOT EventData.FailureName =~ '''(?i)wudfrd'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1542.002' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('abdbbf8c2e51c8e021cfb318bf2a6160', '7158f95ac5629ebdfaf4b7e54f7a5199');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ImageLoaded AS ImageLoaded, EventData.Hashes AS Hashes, EventData.Signed AS Signed, EventData.Signature AS Signature, EventData.SignatureStatus AS SignatureStatus FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 6 AND EventData.ImageLoaded =~ '''(?i)(firmware|flash|nvme|stor|disk|controller|bios|uefi|efi|spi|smm)''' AND (NOT EventData.Signed =~ '''(?i)^true$''' OR NOT EventData.SignatureStatus =~ '''(?i)^valid$''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1542.002' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('222dee09dae454ec897fbafd6f235e63', 'f835099b28a96c92f60c263e0cdff136');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.PortMonitorPersistence
description: |
  Detects Port Monitor persistence technique by monitoring registry modifications,
  DLL loads by spoolsv.exe, and file creation in system directories.
sources:
- name: PortMonitorRegistry
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
           EventData.TargetObject AS TargetObject, EventData.Details AS Details, EventData.Image AS Image
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value IN (12, 13)
      AND EventData.TargetObject =~ '''(?i)\\Control\\Print\\Monitors\\'''
- name: PortMonitorRegistryKeys
  query: |
    SELECT OSPath.Path AS Key, Mtime AS LastWrite, Data.value AS Driver
    FROM glob(globs='HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/Print/Monitors/*/Driver', accessor='registry')
    WHERE NOT Data.value =~ '''(?i)^(localspl|tcpmon|usbmon|wsdmon|APMon|AppMon|FXSMON|NetMon|PrintConfig|PDFMon|winprint)\.dll$'''
- name: SpoolsvDLLLoads
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.Image AS Image, EventData.ImageLoaded AS ImageLoaded, EventData.Signed AS Signed, EventData.Signature AS Signature
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 7
      AND EventData.Image =~ '''(?i)\\spoolsv\.exe$'''
      AND (EventData.Signed = 'false' OR
           NOT EventData.ImageLoaded =~ '''(?i)^C:\\Windows\\(System32|SysWOW64|WinSxS)\\''')
- name: SystemDLLCreation
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.TargetFilename AS TargetFilename, EventData.Image AS Image
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 11
      AND EventData.TargetFilename =~ '''(?i)^C:\\Windows\\System32\\[^\\]+\.dll$'''
      AND NOT EventData.Image =~ '''(?i)^C:\\Windows\\(System32|WinSxS|servicing)\\.*(TiWorker|TrustedInstaller|msiexec|poqexec|svchost|wuauclt|MoUsoCoreWorker|DismHost)\.exe$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1547.010' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('e21d46c60d8a2787d3bafaceee5b7b23', '1ccbda50f07143af7490e177599510ec');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.Image AS Image, EventData.TargetObject AS TargetObject, EventData.Details AS Details, EventData.ImageLoaded AS ImageLoaded, EventData.Signed AS Signed FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE (System.EventID.Value IN (12, 13) AND EventData.TargetObject =~ '''(?i)\\Control\\Print\\Monitors\\''') OR (System.EventID.Value = 7 AND EventData.Image =~ '''(?i)\\spoolsv\.exe$''' AND (EventData.Signed = 'false' OR NOT EventData.ImageLoaded =~ '''(?i)^C:\\Windows\\(System32|SysWOW64|WinSxS)\\'''))
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1547.010' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('a860acb808954a81d8f4d1535bcab434', '0a7ce27955b0938f539aa67221217fc9');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.Collect.AlternateAuth
description: Evidence of alternate authentication material (pass-the-hash / pass-the-ticket / overpass-the-hash) - NewCredentials (type 9 seclogo) logons, NTLM network logons without a session key, explicit-credential logons, and the tools/commands that use stolen hashes or tickets
sources:
  - name: WindowsAuthEvents
    query: |
      SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
             System.EventID.Value AS EventID, EventData.SubjectUserName AS CallerUser, EventData.TargetUserName AS TargetUser,
             EventData.TargetDomainName AS TargetDomain, EventData.LogonType AS LogonType, EventData.LogonProcessName AS LogonProcess,
             EventData.AuthenticationPackageName AS AuthPackage, EventData.KeyLength AS KeyLength,
             EventData.IpAddress AS IpAddress, EventData.ProcessName AS ProcessName, EventData.TargetServerName AS TargetServer
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE (System.EventID.Value = 4624 AND EventData.LogonType = 9 AND EventData.LogonProcessName =~ '''(?i)^seclogo''')
         OR (System.EventID.Value = 4624 AND EventData.LogonType = 3 AND EventData.AuthenticationPackageName = 'NTLM'
             AND EventData.KeyLength = 0 AND NOT EventData.TargetUserName =~ '''(?i)^ANONYMOUS LOGON$|\$$''')
         OR (System.EventID.Value = 4648 AND NOT EventData.TargetServerName =~ '''(?i)^(localhost|127\.0\.0\.1)$'''
             AND NOT EventData.ProcessName =~ '''(?i)\x5c(svchost|lsass|winlogon|consent|taskhostw)\.exe$''')
  - name: SysmonProcessCreation
    query: |
      SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
             EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.User AS User,
             EventData.ParentImage AS ParentImage, EventData.ParentUser AS ParentUser, EventData.LogonId AS LogonId
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 1
        AND EventData.CommandLine =~ '''(?i)sekurlsa::(pth|tickets)|kerberos::(ptt|ptc|golden)|\b(asktgt|asktgs|ptt|s4u|createnetonly)\b|/netonly|/rc4:[0-9a-f]{32}|/ntlm:[0-9a-f]{32}|-hashes\s+[0-9a-f]*:[0-9a-f]{32}|Invoke-(Mimikatz|Rubeus|SMBExec|WMIExec|TheHash)'''
  - name: SecurityProcessCreation
    query: |
      SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
             EventData.NewProcessName AS Image, EventData.CommandLine AS CommandLine, EventData.SubjectUserName AS User,
             EventData.ParentProcessName AS ParentImage
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value = 4688
        AND EventData.CommandLine =~ '''(?i)sekurlsa::(pth|tickets)|kerberos::(ptt|ptc|golden)|\b(asktgt|asktgs|ptt|s4u|createnetonly)\b|/netonly|/rc4:[0-9a-f]{32}|/ntlm:[0-9a-f]{32}|-hashes\s+[0-9a-f]*:[0-9a-f]{32}|Invoke-(Mimikatz|Rubeus|SMBExec|WMIExec|TheHash)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1550' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('e965687b899f2f5fc3d872e02c80b64c');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.SubjectUserName AS CallerUser, EventData.TargetUserName AS TargetUser, EventData.LogonType AS LogonType, EventData.LogonProcessName AS LogonProcess, EventData.AuthenticationPackageName AS AuthPackage, EventData.KeyLength AS KeyLength, EventData.IpAddress AS IpAddress, EventData.ProcessName AS ProcessName FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx') WHERE System.EventID.Value = 4624 AND ((EventData.LogonType = 9 AND EventData.LogonProcessName =~ '''(?i)^seclogo''') OR (EventData.LogonType = 3 AND EventData.AuthenticationPackageName = 'NTLM' AND EventData.KeyLength = 0 AND NOT EventData.TargetUserName =~ '''(?i)^ANONYMOUS LOGON$|\$$'''))
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1550' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('d0ec1dbe2b7809a25aba7f3d6bdaeea1', '8c7c4a83583960547da1ebb68d2cc861');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.TrustControlSubversion
description: |
  Subverting trust controls: root/trusted-publisher certificate store and SIP / trust-provider registry
  changes (Security 4657, Sysmon 12/13), certificate files dropped (Sysmon 11), and the commands that install
  certificates, disable signature checks or strip Mark-of-the-Web (Sysmon 1).
sources:
- name: CertificateRegistryModifications
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
           EventData.ObjectName AS RegistryPath, EventData.ProcessName AS ProcessName, EventData.SubjectUserName AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4657
      AND EventData.ObjectName =~ '''(?i)(SystemCertificates\\(Root|AuthRoot|TrustedPublisher)|Cryptography\\OID\\.*CryptSIPDll|Cryptography\\Providers\\Trust)'''
- name: SysmonTrustRegistry
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
           EventData.Image AS Image, EventData.TargetObject AS TargetObject, EventData.Details AS Details
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value IN (12, 13)
      AND EventData.TargetObject =~ '''(?i)(SystemCertificates\\(Root|AuthRoot|TrustedPublisher)\\Certificates\\|Cryptography\\OID\\EncodingType 0\\CryptSIPDll|Cryptography\\Providers\\Trust\\FinalPolicy)'''
      AND NOT EventData.Image =~ '''(?i)^C:\\Windows\\System32\\(svchost|lsass|CompatTelRunner)\.exe$'''
- name: SuspiciousFileCreation
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.TargetFilename AS TargetFilename, EventData.ProcessId AS ProcessId, EventData.Image AS Image
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 11 AND EventData.TargetFilename =~ '''(?i)\.(cer|crt|p7b|pfx)$'''
- name: TrustSubversionCommands
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.CommandLine =~ '''(?i)(certutil.*-addstore.*(root|trustedpublisher)|Import-Certificate.*Cert:\\.*\\(Root|TrustedPublisher)|Unblock-File|Zone\.Identifier|bcdedit.*(testsigning|nointegritychecks)|CryptSIPDll)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1553' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('c73ad0a91e8742fad73a6f3ce1abf9ac', '245d7e886ad6e697d838e2d2d2f2c4b9');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.CodeSigningAbuse
description: |
  Code signing abuse: modules that carry a signature that doesn't verify (tampered, revoked, expired, self-signed),
  and signing tools / self-made code-signing certificates used on the host.
sources:
  - name: InvalidSignatureImageLoads
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.ImageLoaded AS ImageLoaded,
             EventData.Signed AS Signed, EventData.SignatureStatus AS SignatureStatus, EventData.Signature AS Signature, EventData.Hashes AS Hashes
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 7
        AND EventData.Signed =~ '''(?i)^true$'''
        AND NOT EventData.SignatureStatus =~ '''(?i)^valid$'''
  - name: SigningActivity
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.CommandLine AS CommandLine,
             EventData.ParentImage AS ParentImage, EventData.User AS User
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 1
        AND (EventData.Image =~ '''(?i)\x5c(signtool|osslsigncode|sigthief|carbonCopy|limelighter)\.exe$'''
          OR EventData.CommandLine =~ '''(?i)(signtool(\.exe)?"?\s+sign\s|osslsigncode|set-authenticodesignature|new-selfsignedcertificate.*codesigning|sigthief|carboncopy)''')
  - name: SigningActivitySecurity
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.NewProcessName AS Image, EventData.CommandLine AS CommandLine,
             EventData.ParentProcessName AS ParentImage, EventData.SubjectUserName AS User
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value = 4688
        AND (EventData.NewProcessName =~ '''(?i)\x5c(signtool|osslsigncode|sigthief|carbonCopy|limelighter)\.exe$'''
          OR EventData.CommandLine =~ '''(?i)(signtool(\.exe)?"?\s+sign\s|osslsigncode|set-authenticodesignature|new-selfsignedcertificate.*codesigning|sigthief|carboncopy)''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1553.002' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('c9b4058bf439f844f4241381a36c93d2');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.Image AS Image, EventData.ImageLoaded AS ImageLoaded, EventData.SignatureStatus AS SignatureStatus, EventData.Signature AS Signature, EventData.CommandLine AS CommandLine FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE (System.EventID.Value = 7 AND EventData.Signed =~ '''(?i)^true$''' AND NOT EventData.SignatureStatus =~ '''(?i)^valid$''') OR (System.EventID.Value = 1 AND EventData.CommandLine =~ '''(?i)(signtool(\.exe)?"?\s+sign\s|osslsigncode|set-authenticodesignature|new-selfsignedcertificate.*codesigning|sigthief|carboncopy)''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1553.002' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('1ae911961f2a1c68c10f9e0387dd5a77');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.Windows.MOTW.Bypass
description: |
  Mark-of-the-Web bypass via container files (ISO/IMG/VHD/archives): containers downloaded or created,
  their Zone.Identifier stream, and programs run from a mounted container or an archive-extraction folder
  (files inside a container don't inherit the mark).
sources:
- name: ContainerFileCreation
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.TargetFilename AS FilePath,
           EventData.Image AS ProcessName, 'Container File' AS ArtifactType
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 11
      AND EventData.TargetFilename =~ '''(?i)\.(iso|img|vhdx?|zip|rar|7z|cab)$'''
      AND NOT EventData.TargetFilename =~ '''(?i)(\\Windows\\|\\ProgramData\\Microsoft\\|\\Windows Defender\\|\\Package Cache\\|\\WinSxS\\)'''
- name: ContainerWithMarkOfTheWeb
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.TargetFilename AS FilePath,
           EventData.Image AS ProcessName, EventData.Contents AS ZoneIdentifier, 'Zone.Identifier stream' AS ArtifactType
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 15
      AND EventData.TargetFilename =~ '''(?i)\.(iso|img|vhdx?|zip|rar|7z|cab):Zone\.Identifier$'''
- name: ExecutionFromContainer
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessPath,
           EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, 'Process Execution' AS ArtifactType
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)^[D-Z]:\\[^\\]+\.(exe|com|scr|bat|cmd|lnk)$'''
           OR EventData.Image =~ '''(?i)\\AppData\\Local\\Temp\\(7z[A-Z0-9]+|Rar\$[A-Z0-9.]+|Temp\d+_[^\\]+\.zip)\\'''
           OR EventData.CommandLine =~ '''(?i)mount-diskimage|\.(iso|img|vhdx?)"?\s*$''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1553.005' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('4a3876bfed4cc435cb211f07885cc8a2', 'f12566ece1e5a7252923ab90f09232a8');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.TargetFilename AS FilePath, EventData.ProcessId AS PID, EventData.Image AS ProcessName FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value IN (11, 15) AND EventData.TargetFilename =~ '''(?i)\.(iso|img|vhdx?|zip|rar|7z|cab)(:Zone\.Identifier)?$''' AND NOT EventData.TargetFilename =~ '''(?i)(\\Windows\\|\\ProgramData\\Microsoft\\|\\Windows Defender\\|\\Package Cache\\|\\WinSxS\\)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1553.005' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('a784d1eedfd325ca86ba180d98a40a3c');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.CredentialManager.Detection
description: Detect access to Windows Credential Manager - vault/credential listing tools and cmdlets, credential-dumping scripts, and access to the Credentials / Vault folders
sources:
- name: ProcessCreation
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.NewProcessName AS ProcessPath, EventData.CommandLine AS CommandLine,
           EventData.ParentProcessName AS ParentProcess, EventData.SubjectUserName AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688
      AND (EventData.NewProcessName =~ '''(?i)\x5c(vaultcmd|credentialfileview|vaultpasswordview|lazagne)\.exe$'''
           OR EventData.CommandLine =~ '''(?i)keymgr\.dll\s*,\s*KRShowKeyMgr|cmdkey(\.exe)?\s+/list|Get-VaultCredential|Invoke-WCMDump|Get-CredManCreds|Enum-CredMan|\[Windows\.Security\.Credentials\.PasswordVault''')
- name: SysmonProcessCreation
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.Image AS ProcessPath, EventData.CommandLine AS CommandLine,
           EventData.ParentImage AS ParentProcess, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)\x5c(vaultcmd|credentialfileview|vaultpasswordview|lazagne)\.exe$'''
           OR EventData.CommandLine =~ '''(?i)keymgr\.dll\s*,\s*KRShowKeyMgr|cmdkey(\.exe)?\s+/list|Get-VaultCredential|Invoke-WCMDump|Get-CredManCreds|Enum-CredMan|\[Windows\.Security\.Credentials\.PasswordVault''')
- name: PowerShellScriptBlocks
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.ScriptBlockText AS ScriptBlock, EventData.Path AS ScriptPath
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
    WHERE System.EventID.Value = 4104
      AND EventData.ScriptBlockText =~ '''(?i)CredEnumerate|Get-VaultCredential|Invoke-WCMDump|Windows\.Security\.Credentials\.PasswordVault|vaultcli\.dll'''
- name: FileAccess
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.ProcessName AS ProcessPath, EventData.ObjectName AS FilePath, EventData.AccessMask AS AccessMask,
           EventData.SubjectUserName AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value IN (4656, 4663)
      AND EventData.ObjectName =~ '''(?i)\x5cMicrosoft\x5c(Credentials|Vault)\x5c'''
      AND NOT EventData.ProcessName =~ '''(?i)\x5c(lsass|svchost|MsMpEng|SearchIndexer|SearchProtocolHost)\.exe$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1555.004' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('eb8ae85e389ad62ee46c94e4b4cdca24', '9f492bc623961b55483e5e5ace515b68');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$LET sysmon = SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentProcess, EventData.User AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND (EventData.Image =~ '''(?i)\x5c(vaultcmd|credentialfileview|vaultpasswordview|lazagne)\.exe$''' OR EventData.CommandLine =~ '''(?i)keymgr\.dll\s*,\s*KRShowKeyMgr|cmdkey(\.exe)?\s+/list|Get-VaultCredential|Invoke-WCMDump|Get-CredManCreds|Enum-CredMan|\[Windows\.Security\.Credentials\.PasswordVault''') LET security = SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, EventData.NewProcessName AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentProcessName AS ParentProcess, EventData.SubjectUserName AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx') WHERE System.EventID.Value = 4688 AND (EventData.NewProcessName =~ '''(?i)\x5c(vaultcmd|credentialfileview|vaultpasswordview|lazagne)\.exe$''' OR EventData.CommandLine =~ '''(?i)keymgr\.dll\s*,\s*KRShowKeyMgr|cmdkey(\.exe)?\s+/list|Get-VaultCredential|Invoke-WCMDump|Get-CredManCreds|Enum-CredMan|\[Windows\.Security\.Credentials\.PasswordVault''') SELECT * FROM chain(a={SELECT * FROM sysmon}, b={SELECT * FROM if(condition=len(list=sysmon)=0, then={SELECT * FROM security})})
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1555.004' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('7adc7b8d53a1bf6437d68500497963a1', '893686f098bb36b2fcfc3086c6315d04');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Custom.NetworkProviderDLL
description: |
  Network provider DLL credential capture (NPPSpy-style): a new provider added to NetworkProvider\Order,
  a service with a NetworkProvider\ProviderPath that isn't one of Windows' own, and mpnotify.exe loading a non-Microsoft DLL.
sources:
- name: SysmonRegistryChanges
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
           EventData.TargetObject AS RegistryKey, EventData.Details AS NewValue, EventData.Image AS Process
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value IN (12, 13, 14)
      AND EventData.TargetObject =~ '''(?i)(\x5cControl\x5cNetworkProvider\x5c(Hw)?Order\x5cProviderOrder$|\x5cServices\x5c[^\x5c]+\x5cNetworkProvider\x5c(ProviderPath|Name|Class)?$|\x5cServices\x5c[^\x5c]+\x5cNetworkProvider$)'''
      AND NOT EventData.Image =~ '''(?i)^c:\x5cwindows\x5c(system32\x5c(services|svchost|msiexec|drvinst)\.exe|servicing\x5c|winsxs\x5c)'''
- name: SecurityRegistryAudit
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ObjectName AS ObjectName,
           EventData.ObjectValueName AS ValueName, EventData.NewValue AS NewValue, EventData.ProcessName AS ProcessName, EventData.SubjectUserName AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4657 AND EventData.ObjectName =~ '''(?i)\x5cNetworkProvider(\x5c|$)'''
- name: ProviderDLLLoads
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.ImageLoaded AS ImageLoaded,
           EventData.Signed AS Signed, EventData.Signature AS Signature, EventData.SignatureStatus AS SignatureStatus, EventData.Hashes AS Hashes
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 7 AND EventData.Image =~ '''(?i)\x5cmpnotify\.exe$'''
      AND NOT (EventData.Signature =~ '''(?i)^Microsoft Windows''' AND EventData.SignatureStatus =~ '''(?i)^valid$''')
- name: ProviderRegistry
  query: |
    LET order = SELECT ProviderOrder FROM read_reg_key(globs='HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/NetworkProvider/Order')
    SELECT Key.OSPath AS Key, Key.Mtime AS LastWritten, Name, ProviderPath, Class, order[0].ProviderOrder AS ProviderOrder
    FROM read_reg_key(globs='HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/*/NetworkProvider')
    WHERE NOT ProviderPath =~ '''(?i)^%systemroot%\x5csystem32\x5c(ntlanman|drprov|davclnt|p9np|vmhgfs|vmhgfs64)\.dll$|^%systemroot%\x5csystem32\x5c(vmhgfs|rdpnp)\.dll$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1556.008' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('baddef5d725c17a43791c1c253ac4c40', '19f1f5446c74e874f4d99eddaaeef028');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.Image AS Image, EventData.ImageLoaded AS ImageLoaded, EventData.TargetObject AS RegistryKey, EventData.Details AS NewValue, EventData.Signature AS Signature FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE (System.EventID.Value = 7 AND EventData.Image =~ '''(?i)\x5cmpnotify\.exe$''' AND NOT (EventData.Signature =~ '''(?i)^Microsoft Windows''' AND EventData.SignatureStatus =~ '''(?i)^valid$''')) OR (System.EventID.Value IN (12, 13, 14) AND EventData.TargetObject =~ '''(?i)(\x5cControl\x5cNetworkProvider\x5c(Hw)?Order\x5cProviderOrder$|\x5cServices\x5c[^\x5c]+\x5cNetworkProvider\x5cProviderPath$)''' AND NOT EventData.Image =~ '''(?i)^c:\x5cwindows\x5c(system32\x5c(services|svchost|msiexec|drvinst)\.exe|servicing\x5c|winsxs\x5c)''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1556.008' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('4d26484833fb07b5b643f3413d9ae990', 'a14835d1eb855a8027999f9c0c410f16');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.Evil.Twin.Detection
description: Detects potential Evil Twin Wi-Fi attacks through WLAN connection events (open/WEP networks, failures), saved wireless profiles and known network profiles
sources:
- name: WirelessConnectionEvents
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
           EventData.SSID AS SSID, EventData.ProfileName AS ProfileName, EventData.AuthenticationAlgorithm AS Authentication,
           EventData.CipherAlgorithm AS Cipher, EventData.Reason AS Reason, EventData AS Details
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx')
    WHERE System.EventID.Value IN (8001, 8002, 8003, 11000, 11001, 11004, 11005, 11010)
      AND (EventData.AuthenticationAlgorithm =~ '''(?i)(open|wep|shared)''' OR System.EventID.Value IN (8002, 11001, 11010))
- name: WirelessProfiles
  query: |
    SELECT OSPath, Mtime, Btime,
           parse_xml(file=OSPath).WLANProfile.SSIDConfig.SSID.name AS ProfileSSID,
           parse_xml(file=OSPath).WLANProfile.connectionMode AS ConnectionMode,
           parse_xml(file=OSPath).WLANProfile.MSM.security.authEncryption.authentication AS Authentication
    FROM glob(globs='C:/ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/*/*.xml')
- name: NetworkProfileRegistry
  query: |
    SELECT Key.OSPath.Basename AS ProfileGuid, Key.Mtime AS KeyModified, ProfileName, Description, Category, NameType
    FROM read_reg_key(globs='HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/NetworkList/Profiles/*')
    WHERE NameType = 71
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1557.004' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('e40e4b9674908d2af33ad618044a244e', '36bf5a12874143beb0c0b864af1f7ce4');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.SSID AS SSID, EventData.ProfileName AS ProfileName, EventData.AuthenticationAlgorithm AS Authentication, EventData.CipherAlgorithm AS Cipher, EventData.Reason AS Reason FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx') WHERE System.EventID.Value IN (8001, 8002, 8003, 11000, 11001, 11004, 11005, 11010) AND (EventData.AuthenticationAlgorithm =~ '''(?i)(open|wep|shared)''' OR System.EventID.Value IN (8002, 11001, 11010))
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1557.004' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('ed4e4688351ca5e06a86885bb48a396b', '9544a04f52dc3bfc77fee19cd49ccfd2');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.KerberosTicketAnomaly
description: |
  Kerberos ticket theft and forgery: RC4 service tickets for user service accounts (Kerberoasting, 4769 on
  domain controllers), TGT requests without pre-authentication or with RC4 (AS-REP roasting, 4768 on DCs),
  ticket tooling on the host (Sysmon 1) and non-system processes reading LSASS memory (Sysmon 10).
sources:
- name: KerberosTGSRequests
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.TargetUserName AS Username, EventData.ServiceName AS Service,
           EventData.TicketEncryptionType AS EncryptionType, EventData.TicketOptions AS TicketOptions, EventData.IpAddress AS ClientIP
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4769
      AND format(format='%v', args=EventData.TicketEncryptionType) =~ '''^(0x17|23|0x18|24)$'''
      AND NOT EventData.ServiceName =~ '''(?i)(\$$|^krbtgt)'''
- name: TGTRequests
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.TargetUserName AS Username, EventData.TicketEncryptionType AS EncryptionType,
           EventData.PreAuthType AS PreAuthType, EventData.Status AS Status, EventData.IpAddress AS ClientIP
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4768
      AND (format(format='%v', args=EventData.PreAuthType) = '0'
           OR format(format='%v', args=EventData.TicketEncryptionType) =~ '''^(0x17|23|0x18|24)$''')
- name: KerberosToolExecution
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)\\(rubeus|kekeo|mimikatz|ticketer|getuserspns|getnpusers)[^\\]*\.exe$'''
           OR EventData.CommandLine =~ '''(?i)(kerberoast|asreproast|asktgt|asktgs|s4u|golden|silver|kerberos::(ptt|golden|list)|Invoke-Kerberoast|Request-SPNTicket|ptt\s+/ticket|klist\s+purge)''')
- name: LSASSMemoryAccess
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.SourceImage AS ProcessPath, EventData.TargetImage AS TargetProcess,
           format(format='0x%x', args=EventData.GrantedAccess) AS AccessRights, EventData.CallTrace AS CallTrace
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 10 AND EventData.TargetImage =~ '''(?i)\\lsass\.exe$'''
      AND format(format='0x%x', args=EventData.GrantedAccess) =~ '''(?i)^0x(10|1010|1410|1438|143a|1fffff|1f3fff|1f0fff|40|1418)$'''
      AND NOT EventData.SourceImage =~ '''(?i)^C:\\(Windows\\System32\\(csrss|wininit|winlogon|services|svchost|lsm|LogonUI|MRT|wbem\\WmiPrvSE)\.exe|ProgramData\\Microsoft\\Windows Defender\\Platform\\.*\\MsMpEng\.exe|Program Files\\Windows Defender\\MsMpEng\.exe)$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1558' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('3f9a55a5391fa70903b96fe6d4e5d5c5', '0acec87722fe602826a90c5119d58ac2');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.TargetUserName AS Username, EventData.ServiceName AS Service, EventData.TicketEncryptionType AS EncryptionType, EventData.PreAuthType AS PreAuthType, EventData.IpAddress AS ClientIP FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx') WHERE (System.EventID.Value = 4769 AND format(format='%v', args=EventData.TicketEncryptionType) =~ '''^(0x17|23|0x18|24)$''' AND NOT EventData.ServiceName =~ '''(?i)(\$$|^krbtgt)''') OR (System.EventID.Value = 4768 AND (format(format='%v', args=EventData.PreAuthType) = '0' OR format(format='%v', args=EventData.TicketEncryptionType) =~ '''^(0x17|23|0x18|24)$'''))
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1558' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('62ecf89c374bde25f897ec201d088d2a', '59878ee579efd953e3d0df650a3ef2fe');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.IPC.Abuse
description: Detect Inter-Process Communication abuse - named pipes known from offensive tooling or created by script hosts / user-writable binaries, pipe object access by non-system processes, and Office applications spawning shells (DDE / COM)
sources:
- name: SysmonNamedPipes
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           System.EventID.Value AS EventID, EventData.PipeName AS PipeName, EventData.Image AS ProcessImage,
           EventData.ProcessId AS ProcessId, EventData.User AS User, 'NamedPipe' AS IPCType
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value IN (17, 18)
      AND (EventData.PipeName =~ '''(?i)^\x5c(MSSE-\d+-server|msagent_\w+|postex_\w+|postex_ssh_\w+|status_\w+|interprocess_\w+|lsadump|cachedump|wceservicepipe|jaccdpqnvbrrxlaf|psexec\w*|remcom\w*|csexec\w*|paexec\w*|winsession|rpchlp_\d|isapi_http|isapi_dg|demoagent_\w+|DserNamePipe\w*|ntsvcs\w*|scerpc\w*)$'''
           OR (EventData.Image =~ '''(?i)\x5c(powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript|msbuild|installutil)\.exe$|\x5c(Users\x5cPublic|ProgramData|Windows\x5cTemp|PerfLogs|AppData\x5cLocal\x5cTemp)\x5c'''
               AND NOT EventData.PipeName =~ '''(?i)^\x5c(PSHost\.\d+\.\d+\.DefaultAppDomain\.(powershell|pwsh)|dotnet-diagnostic-\d+$|mojo\.|chrome\.|crashpad_|LOCAL\x5c|Winsock2\x5c|ProtectedPrefix\x5c|Anonymous Pipe|<Anonymous Pipe>)'''))
- name: SecurityObjectAccess
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.ProcessName AS ProcessName, EventData.ObjectName AS ObjectName, EventData.AccessMask AS AccessMask,
           EventData.SubjectUserName AS User, 'ObjectAccess' AS IPCType
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value IN (4656, 4663) AND EventData.ObjectName =~ '''(?i)\x5cpipe\x5c'''
      AND NOT EventData.ProcessName =~ '''(?i)^C:\x5cWindows\x5c(System32|SysWOW64)\x5c|\x5cMsMpEng\.exe$|^System$'''
- name: SuspiciousProcessLineage
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.ParentImage AS ParentImage, EventData.Image AS Image, EventData.CommandLine AS CommandLine,
           EventData.User AS User, 'ProcessCreation' AS IPCType
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.ParentImage =~ '''(?i)\x5c(winword|excel|powerpnt|outlook|msaccess|mspub|onenote)\.exe$'''
      AND EventData.Image =~ '''(?i)\x5c(cmd|powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin)\.exe$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1559' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('d226c8e6b157c5c0dacb28c6f1e35c8a');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.PipeName AS PipeName, EventData.Image AS ProcessImage, EventData.ProcessId AS ProcessId, EventData.User AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value IN (17, 18) AND (EventData.PipeName =~ '''(?i)^\x5c(MSSE-\d+-server|msagent_\w+|postex_\w+|postex_ssh_\w+|status_\w+|interprocess_\w+|lsadump|cachedump|wceservicepipe|jaccdpqnvbrrxlaf|psexec\w*|remcom\w*|csexec\w*|paexec\w*|winsession|rpchlp_\d|isapi_http|isapi_dg|demoagent_\w+|DserNamePipe\w*|ntsvcs\w*|scerpc\w*)$''' OR (EventData.Image =~ '''(?i)\x5c(powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript|msbuild|installutil)\.exe$|\x5c(Users\x5cPublic|ProgramData|Windows\x5cTemp|PerfLogs|AppData\x5cLocal\x5cTemp)\x5c''' AND NOT EventData.PipeName =~ '''(?i)^\x5c(PSHost\.\d+\.\d+\.DefaultAppDomain\.(powershell|pwsh)|dotnet-diagnostic-\d+$|mojo\.|chrome\.|crashpad_|LOCAL\x5c|Winsock2\x5c|ProtectedPrefix\x5c|Anonymous Pipe|<Anonymous Pipe>)'''))
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1559' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('93c5d6c2e30fee81f82aab76a7aa2aed');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.T1561.DiskWipeDetection
description: |
  Detects disk wipe activity: wiper tools and destructive disk commands, raw disk reads/writes through
  \\.\PhysicalDrive / volume devices (Sysmon 9), and unsigned or known raw-disk drivers being loaded.
sources:
- name: WipeCommands
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image,
           EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)\\(sdelete64?|dd)\.exe$'''
           OR EventData.CommandLine =~ '''(?i)(\bcipher(\.exe)?"?\s+/w:|\bformat(\.com)?"?\s+[a-z]:.*(/p:|/y)|\\\\\.\\PhysicalDrive\d|\bclean\s+all\b|\bsdelete6?4?\b|\bdd\b.*\bof=|clear-disk|initialize-disk|format-volume)''')
- name: RawDiskAccess
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image,
           EventData.Device AS Device, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 9
      AND NOT EventData.Image =~ '''(?i)^(System|C:\\Windows\\System32\\(svchost|wininit|smss|autochk|chkdsk|defrag|vds|vssvc|dllhost|lsass)\.exe|C:\\ProgramData\\Microsoft\\Windows Defender\\.*|C:\\Program Files\\Windows Defender\\.*)$'''
- name: SuspiciousDriverLoads
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ImageLoaded AS ImageLoaded,
           EventData.Signed AS Signed, EventData.Signature AS Signature, EventData.SignatureStatus AS SignatureStatus, EventData.Hashes AS Hashes
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 6
      AND (NOT EventData.Signed =~ '''(?i)^true$''' OR NOT EventData.SignatureStatus =~ '''(?i)^valid$'''
           OR EventData.ImageLoaded =~ '''(?i)\\(rawdisk\d*|elrawdsk|epmntdrv|eldos\w*|wiper\w*|eraser\w*|hermetic\w*)\.sys$''')
- name: BackupPrivilegeUse
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.SubjectUserName AS User,
           EventData.ProcessName AS ProcessName, EventData.PrivilegeList AS PrivilegeList
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4673
      AND EventData.PrivilegeList =~ '''(?i)(SeBackupPrivilege|SeManageVolumePrivilege)'''
      AND NOT EventData.ProcessName =~ '''(?i)^C:\\(Windows|Program Files|Program Files \(x86\))\\'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1561' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('69b0415ed6b085c0752ddb318175c171', '10cf618b4d8a2abeb5a8d05bf881f33b');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.Device AS Device FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE (System.EventID.Value = 1 AND (EventData.Image =~ '''(?i)\\(sdelete64?|dd)\.exe$''' OR EventData.CommandLine =~ '''(?i)(\bcipher(\.exe)?"?\s+/w:|\bformat(\.com)?"?\s+[a-z]:.*(/p:|/y)|\\\\\.\\PhysicalDrive\d|\bclean\s+all\b|\bsdelete6?4?\b|\bdd\b.*\bof=|clear-disk|initialize-disk|format-volume)''')) OR (System.EventID.Value = 9 AND NOT EventData.Image =~ '''(?i)^(System|C:\\Windows\\System32\\(svchost|wininit|smss|autochk|chkdsk|defrag|vds|vssvc|dllhost|lsass)\.exe|C:\\ProgramData\\Microsoft\\Windows Defender\\.*|C:\\Program Files\\Windows Defender\\.*)$''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1561' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('9efb6b57301b744a5aa38f0989cff545', '284b01830355f96bcee152d4584f528f');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.DiskContentWipe
description: |
  Disk content wipe: raw-disk drivers loaded (RawDisk/EldoS as used by Shamoon, WinIO etc.), raw volume access by
  non-system programs, and wiping commands (sdelete, cipher /w, format, diskpart clean, Clear-Disk, dd to PhysicalDrive).
sources:
  - name: RawDiskDriverLoads
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ImageLoaded AS ImageLoaded,
             EventData.Signature AS Signature, EventData.SignatureStatus AS SignatureStatus, EventData.Hashes AS Hashes
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 6
        AND (EventData.ImageLoaded =~ '''(?i)\x5c(rawdisk|elrawdsk|drdisk|winio(64)?|directio(64)?|epmntdrv|eldos|physmem|mapmem|zamguard\d*|amsdk)\.sys$'''
          OR EventData.Signature =~ '''(?i)eldos|easeus|paragon software''')
  - name: RawVolumeAccess
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.Device AS Device, EventData.User AS User
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 9
        AND NOT EventData.Image =~ '''(?i)^(system$|c:\x5cwindows\x5c(system32|syswow64)\x5c(svchost|vssvc|defrag|chkdsk|wbengine|vds|lsass|smartscreen|searchindexer|wininit|csrss|services|dfsrs|sdiagnhost|wbem\x5cwmiprvse|mrt|taskhostw)\.exe$|c:\x5cprogramdata\x5cmicrosoft\x5cwindows defender\x5c|c:\x5cprogram files\x5cwindows defender\x5c)'''
  - name: WipeCommands
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.CommandLine AS CommandLine,
             EventData.ParentImage AS ParentImage, EventData.User AS User
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 1
        AND (EventData.Image =~ '''(?i)\x5c(sdelete(64)?|wipe|killdisk|eraser)\.exe$'''
          OR EventData.CommandLine =~ '''(?i)(sdelete(64)?(\.exe)?"?\s.*-[zcp]|cipher(\.exe)?"?\s+/w:|format(\.com)?"?\s+[a-z]:.*(/p:|/y)|diskpart.*clean|clean\s+all|clear-disk|format-volume|\x5c\x5c\.\x5cphysicaldrive\d|dd(\.exe)?\s.*of=.*physicaldrive)''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1561.001' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('e08d535660630548e4f63f9190fb192d');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.Image AS Image, EventData.ImageLoaded AS ImageLoaded, EventData.CommandLine AS CommandLine, EventData.Signature AS Signature FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE (System.EventID.Value = 6 AND (EventData.ImageLoaded =~ '''(?i)\x5c(rawdisk|elrawdsk|drdisk|winio(64)?|directio(64)?|epmntdrv|eldos|physmem|mapmem|zamguard\d*|amsdk)\.sys$''' OR EventData.Signature =~ '''(?i)eldos|easeus|paragon software''')) OR (System.EventID.Value = 1 AND EventData.CommandLine =~ '''(?i)(sdelete(64)?(\.exe)?"?\s.*-[zcp]|cipher(\.exe)?"?\s+/w:|format(\.com)?"?\s+[a-z]:.*(/p:|/y)|diskpart.*clean|clean\s+all|clear-disk|format-volume|\x5c\x5c\.\x5cphysicaldrive\d|dd(\.exe)?\s.*of=.*physicaldrive)''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1561.001' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('d5d143bbc5e14582db29de95ed1aba09');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.SessionHijacking
description: Detect RDP and remote service session hijacking - tscon run to attach another user's session (typically as SYSTEM), session reconnects, RDP logons and RDP connection events
sources:
- name: SecurityLogs
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           System.EventID.Value AS EventID, EventData.TargetUserName AS User, EventData.IpAddress AS SourceIP,
           EventData.ClientAddress AS ClientAddress, EventData.AccountName AS AccountName, EventData.SessionName AS SessionName,
           EventData.LogonType AS LogonType, EventData.TargetLogonId AS LogonID
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE (System.EventID.Value IN (4624, 4648) AND EventData.LogonType = 10)
       OR System.EventID.Value IN (4778, 4779)
- name: TerminalServicesLogs
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           System.Channel AS Channel, System.EventID.Value AS EventID,
           UserData.EventXML.User AS User, UserData.EventXML.Address AS Address, UserData.EventXML.SessionID AS SessionID,
           UserData.EventXML.TargetSession AS TargetSession, UserData.EventXML.Source AS SourceSession,
           UserData.EventXML.Param1 AS Param1, UserData.EventXML.Param3 AS Param3, Message
    FROM chain(
      a={SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx') WHERE System.EventID.Value IN (1149, 261)},
      b={SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx') WHERE System.EventID.Value IN (24, 25, 39, 40)})
- name: ProcessExecution
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.Image AS ProcessName, EventData.CommandLine AS CommandLine, EventData.User AS User,
           EventData.ParentImage AS ParentImage, EventData.ParentCommandLine AS ParentCommandLine
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)\x5ctscon\.exe$''' OR EventData.CommandLine =~ '''(?i)tscon(\.exe)?\s+\d+''')
- name: SecurityProcessCreation
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.NewProcessName AS ProcessName, EventData.CommandLine AS CommandLine,
           EventData.TargetUserName AS User, EventData.ParentProcessName AS ParentImage
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688
      AND (EventData.NewProcessName =~ '''(?i)\x5ctscon\.exe$''' OR EventData.CommandLine =~ '''(?i)tscon(\.exe)?\s+\d+''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1563' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('c0fad505e9fdf1d1cc9790494d7ca051', '8d8f138b82cdeb8d7c422176d0b46c71');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessName, EventData.CommandLine AS CommandLine, EventData.User AS User, EventData.ParentImage AS ParentImage, EventData.ParentCommandLine AS ParentCommandLine FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND (EventData.Image =~ '''(?i)\x5ctscon\.exe$''' OR EventData.CommandLine =~ '''(?i)tscon(\.exe)?\s+\d+''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1563' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('495dfc926dc1e83c0517c511228a19c3', 'f95acfe6308499bfe9ff75c16d2eedec');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.RDPHijacking
description: |
  RDP session hijacking: tscon.exe switching sessions (especially run as SYSTEM or from a service),
  services created to run tscon (System 7045), session reconnects in the LocalSessionManager log (25),
  RDP authentications with their source address (RemoteConnectionManager 1149) and RDP logons (4624 type 10).
sources:
- name: TsconExecution
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.User AS User,
           EventData.ParentImage AS ParentImage, EventData.IntegrityLevel AS IntegrityLevel
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1 AND EventData.Image =~ '''(?i)\\tscon\.exe$'''
- name: TsconServiceCreated
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.ServiceName AS ServiceName, EventData.ImagePath AS ImagePath, EventData.AccountName AS Account
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx')
    WHERE System.EventID.Value = 7045 AND EventData.ImagePath =~ '''(?i)tscon'''
- name: SessionReconnects
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
           UserData.EventXML.User AS User, UserData.EventXML.SessionID AS SessionID, UserData.EventXML.Address AS Source
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx')
    WHERE System.EventID.Value = 25
- name: RDPAuthentications
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           UserData.EventXML.Param1 AS User, UserData.EventXML.Param2 AS Domain, UserData.EventXML.Param3 AS SourceAddress
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx')
    WHERE System.EventID.Value = 1149
- name: RDPLogons
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.LogonType AS LogonType, EventData.TargetUserName AS TargetUserName, EventData.IpAddress AS IpAddress,
           EventData.LogonProcessName AS LogonProcess
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4624 AND EventData.LogonType = 10
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1563.002' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('5b1050888139e4ddf5a1dcb2f1cd9e7b', 'd292ac71fdae273a3567652dca400b97');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.User AS User, EventData.ParentImage AS ParentImage FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND (EventData.Image =~ '''(?i)\\tscon\.exe$''' OR EventData.CommandLine =~ '''(?i)(sc(\.exe)?\s+create.*tscon|tscon(\.exe)?\s+\d+\s+/dest)''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1563.002' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('668c303109689fec41606ab6e9bc9c0d', '3a36388a53a1d057d49d45bcfab2394d');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Exchange.EmailHidingRules
description: |
  Email hiding rules created from this host: New-InboxRule / Set-InboxRule (Exchange / Exchange Online PowerShell)
  with delete / move / mark-as-read actions, in PowerShell script-block (4104) and module (4103) logging,
  plus Outlook client rule files (.rwz) changed.
sources:
  - name: PowerShellInboxRules
    query: |
      LET ops = SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
                       EventData.ScriptBlockText AS ScriptBlockText, EventData.Payload AS Payload, EventData.Path AS Path
        FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
        WHERE System.EventID.Value IN (4103, 4104)
          AND format(format='%v %v', args=[EventData.ScriptBlockText, EventData.Payload]) =~ '''(?i)(new|set)-inboxrule'''
      LET classic = SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
                           NULL AS ScriptBlockText, format(format='%v', args=EventData.Data) AS Payload, NULL AS Path
        FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Windows PowerShell.evtx')
        WHERE System.EventID.Value IN (400, 800)
          AND format(format='%v', args=EventData.Data) =~ '''(?i)(new|set)-inboxrule'''
      SELECT *, format(format='%v %v', args=[ScriptBlockText, Payload]) =~ '''(?i)(DeleteMessage|SoftDeleteMessage|MoveToFolder|MarkAsRead|RedirectTo|ForwardTo|StopProcessingRules)''' AS HidingAction
      FROM chain(a=ops, b=classic)
  - name: OutlookRuleFiles
    query: |
      SELECT OSPath, Size, Mtime, Btime
      FROM glob(globs=['C:/Users/*/AppData/Roaming/Microsoft/Outlook/*.rwz', 'C:/Users/*/AppData/Local/Microsoft/Outlook/*.rwz'])
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1564.008' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('94243070c7996c3034cd5d73e694f64b');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, EventData.ScriptBlockText AS ScriptBlockText, EventData.Payload AS Payload FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx') WHERE System.EventID.Value IN (4103, 4104) AND format(format='%v %v', args=[EventData.ScriptBlockText, EventData.Payload]) =~ '''(?i)(new|set)-inboxrule'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1564.008' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('6034f6372d5a0521704dc9012b189b99', '1943db01a01c168c2b42f70b0420369d');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.LateralToolTransfer
description: Detect lateral tool transfer via SMB admin shares (files written over SMB, then executed)
sources:
- name: SMBShareFileWrites
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.SubjectUserName AS User,
           EventData.ShareName AS Share, EventData.RelativeTargetName AS TargetFile, EventData.IpAddress AS SourceIP,
           EventData.AccessList AS AccessList
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 5145
      AND EventData.ShareName =~ '''(?i)\\(C|ADMIN|[D-Z])\$$'''
      AND EventData.RelativeTargetName =~ '''(?i)\.(exe|dll|bat|cmd|ps1|vbs|js|hta|scr|msi)$'''
- name: AdminShareAccess
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.SubjectUserName AS User,
           EventData.ShareName AS Share, EventData.IpAddress AS SourceIP
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 5140
      AND EventData.ShareName =~ '''(?i)\\(C|ADMIN|[D-Z])\$$'''
      AND NOT EventData.IpAddress =~ '''^(127\.0\.0\.1|::1|-)$'''
- name: FilesWrittenOverSMB
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Process,
           EventData.TargetFilename AS CreatedFile, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 11
      AND EventData.Image =~ '''(?i)^System$'''
      AND EventData.TargetFilename =~ '''(?i)\.(exe|dll|bat|cmd|ps1|vbs|js|hta|scr|msi)$'''
- name: ExecutionOfTransferredTools
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ExecutedProcess,
           EventData.CommandLine AS CommandLine, EventData.User AS User, EventData.ParentImage AS Parent
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)^C:\\(Windows\\Temp|Users\\Public|PerfLogs)\\[^\\]+\.(exe|bat|cmd)$'''
           OR EventData.Image =~ '''(?i)^C:\\Windows\\[^\\]+\.exe$''' AND EventData.ParentImage =~ '''(?i)\\services\.exe$''' AND NOT EventData.Image =~ '''(?i)\\(explorer|regedit|hh|notepad|bfsvc|splwow64|winhlp32|write|helppane|twunk_32)\.exe$''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1570' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('6b15129e45f5dbb5bf56aa9a9e35ddd4', '6180edb7b8b37d30e05da8cedf2160b9');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.SubjectUserName AS User, EventData.ShareName AS Share, EventData.RelativeTargetName AS TargetFile, EventData.IpAddress AS SourceIP, EventData.AccessList AS AccessList FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx') WHERE System.EventID.Value = 5145 AND EventData.ShareName =~ '''(?i)\\(C|ADMIN|[D-Z])\$$''' AND EventData.RelativeTargetName =~ '''(?i)\.(exe|dll|bat|cmd|ps1|vbs|js|hta|scr|msi)$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1570' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('999d8542190d59f78cf1df112d32ed37', '4c8517e669956cdfe1fe5f874f43e168');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.DLLHijacking
description: |
  DLL search-order hijacking: unsigned DLLs loaded from user-writable folders or from next to a program
  outside Windows' folders while carrying the name of a Windows system DLL, DLLs written into user-writable
  folders by script hosts / LOLBins, and App Paths / IFEO registry redirection (Security 4657).
sources:
  - name: SuspiciousDLLLoads
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.Image AS ProcessPath, EventData.ImageLoaded AS DLLPath,
             EventData.Signed AS IsSigned, EventData.Signature AS Signature, EventData.Hashes AS Hashes
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 7
        AND EventData.Signed = 'false'
        AND NOT EventData.ImageLoaded =~ '''(?i)^C:\\Windows\\(System32|SysWOW64|WinSxS|assembly|Microsoft\.NET)\\'''
        AND (EventData.ImageLoaded =~ '''(?i)\\(Users|ProgramData|Temp|PerfLogs|Windows\\Temp)\\'''
             OR EventData.ImageLoaded =~ '''(?i)\\(version|dbghelp|dbgcore|wininet|winhttp|cryptsp|cryptbase|userenv|uxtheme|dwmapi|propsys|profapi|wtsapi32|winmm|iphlpapi|netapi32|samcli|secur32|sspicli|dpapi|amsi|ntmarta|wbemcomn|edgegdi|mswsock|dxgi|d3d11|xmllite|srvcli|mpr|wow64log)\.dll$''')
  - name: DLLFileCreation
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.Image AS ProcessPath, EventData.TargetFilename AS CreatedFile
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 11
        AND EventData.TargetFilename =~ '''(?i)\.dll$'''
        AND NOT EventData.TargetFilename =~ '''(?i)^C:\\Windows\\(System32|SysWOW64|WinSxS|assembly|Microsoft\.NET|SoftwareDistribution|Installer|servicing)\\'''
        AND EventData.Image =~ '''(?i)\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|xcopy|robocopy|expand|extrac32|esentutl)\.exe$'''
  - name: RegistryRedirection
    query: |
      SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
             EventData.ObjectName AS RegistryKey, EventData.ObjectValueName AS ValueName, EventData.NewValue AS NewValue,
             EventData.ProcessName AS ProcessName
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value = 4657
        AND EventData.ObjectName =~ '''(?i)(App Paths|Image File Execution Options|KnownDlls|SafeDllSearchMode)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1574.001' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('967aec30d11792024382962ead3a610d');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessPath, EventData.ImageLoaded AS DLLPath, EventData.Signed AS IsSigned, EventData.Company AS Company, EventData.Product AS Product, EventData.Hashes AS Hashes FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 7 AND EventData.Signed = 'false' AND NOT EventData.ImageLoaded =~ '''(?i)^C:\\Windows\\(System32|SysWOW64|WinSxS|assembly|Microsoft\.NET)\\''' AND (EventData.ImageLoaded =~ '''(?i)\\(Users|ProgramData|Temp|PerfLogs|Windows\\Temp)\\''' OR EventData.ImageLoaded =~ '''(?i)\\(version|dbghelp|dbgcore|wininet|winhttp|cryptsp|cryptbase|userenv|uxtheme|dwmapi|propsys|profapi|wtsapi32|winmm|iphlpapi|netapi32|samcli|secur32|sspicli|dpapi|amsi|ntmarta|wbemcomn|edgegdi|mswsock|dxgi|d3d11|xmllite|srvcli|mpr|wow64log)\.dll$''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1574.001' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('259c50254df75df291063311d28020c3', '442d60b1499d94e23951e0d24008821f');

UPDATE ref_artifact_library SET analysis_steps = $orcafix2$NOT OBSERVABLE ON THE HOST: ATT&CK lists no host data source for this technique (it happens on attacker infrastructure or in public sources). An empty collection result is expected and is not evidence that it didn't happen.$orcafix2$ || chr(10) || chr(10) || COALESCE(analysis_steps, '')
WHERE t_code = 'T1583' AND COALESCE(analysis_steps, '') NOT LIKE 'NOT OBSERVABLE ON THE HOST%';

UPDATE ref_artifact_library SET analysis_steps = $orcafix2$NOT OBSERVABLE ON THE HOST: ATT&CK lists no host data source for this technique (it happens on attacker infrastructure or in public sources). An empty collection result is expected and is not evidence that it didn't happen.$orcafix2$ || chr(10) || chr(10) || COALESCE(analysis_steps, '')
WHERE t_code = 'T1583.004' AND COALESCE(analysis_steps, '') NOT LIKE 'NOT OBSERVABLE ON THE HOST%';

UPDATE ref_artifact_library SET analysis_steps = $orcafix2$NOT OBSERVABLE ON THE HOST: ATT&CK lists no host data source for this technique (it happens on attacker infrastructure or in public sources). An empty collection result is expected and is not evidence that it didn't happen.$orcafix2$ || chr(10) || chr(10) || COALESCE(analysis_steps, '')
WHERE t_code = 'T1584.002' AND COALESCE(analysis_steps, '') NOT LIKE 'NOT OBSERVABLE ON THE HOST%';

UPDATE ref_artifact_library SET analysis_steps = $orcafix2$NOT OBSERVABLE ON THE HOST: ATT&CK lists no host data source for this technique (it happens on attacker infrastructure or in public sources). An empty collection result is expected and is not evidence that it didn't happen.$orcafix2$ || chr(10) || chr(10) || COALESCE(analysis_steps, '')
WHERE t_code = 'T1584.003' AND COALESCE(analysis_steps, '') NOT LIKE 'NOT OBSERVABLE ON THE HOST%';

UPDATE ref_artifact_library SET analysis_steps = $orcafix2$NOT OBSERVABLE ON THE HOST: ATT&CK lists no host data source for this technique (it happens on attacker infrastructure or in public sources). An empty collection result is expected and is not evidence that it didn't happen.$orcafix2$ || chr(10) || chr(10) || COALESCE(analysis_steps, '')
WHERE t_code = 'T1587' AND COALESCE(analysis_steps, '') NOT LIKE 'NOT OBSERVABLE ON THE HOST%';

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Custom.T1587002.CodeSigningCertificates
description: Host-side traces of self-made code signing certificates - certificate creation / signing tools run on the host, certificates in the machine stores, and certificate / key files in user-writable folders
sources:
- name: CertificateStores
  query: |
    SELECT Key, Name, Data.value as CertData, Data.type as DataType
    FROM read_reg_key(globs='HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/SystemCertificates/*/Certificates/*')
    WHERE Name = 'Blob'
- name: CertificateToolExecution
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.Image AS ProcessName, EventData.CommandLine AS CommandLine,
           EventData.ParentImage AS ParentProcess, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND (EventData.Image =~ '''(?i)\x5c(makecert|signtool|pvk2pfx|cert2spc|osslsigncode)\.exe$'''
           OR EventData.CommandLine =~ '''(?i)New-SelfSignedCertificate[^\n]*CodeSigning|Set-AuthenticodeSignature|openssl[^\n]*(req|x509)[^\n]*codeSigning'''
           OR (EventData.Image =~ '''(?i)\x5ccertutil\.exe$''' AND EventData.CommandLine =~ '''(?i)-(addstore|importpfx)'''))
- name: PowerShellCertificateCreation
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.ScriptBlockText AS ScriptBlock, EventData.Path AS ScriptPath
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
    WHERE System.EventID.Value = 4104
      AND EventData.ScriptBlockText =~ '''(?i)New-SelfSignedCertificate[^\n]*CodeSigning|Set-AuthenticodeSignature\s+[^\n]*-Certificate'''
- name: CertificateFiles
  query: |
    SELECT OSPath, Size, Btime, Mtime
    FROM glob(globs=['C:/Users/**/*.{cer,crt,p12,pfx,pvk,spc}', 'C:/ProgramData/**/*.{p12,pfx,pvk,spc}',
                     'C:/Windows/Temp/**/*.{cer,crt,p12,pfx,pvk,spc}', 'C:/temp/**/*.{cer,crt,p12,pfx,pvk,spc}'])
    WHERE NOT IsDir AND Size > 0
      AND NOT OSPath =~ '''(?i)\x5cAppData\x5c(Local|Roaming)\x5c(Microsoft\x5c(Edge|Teams|OneDrive)|Google\x5cChrome|Mozilla)\x5c|\x5cnode_modules\x5c|\x5csite-packages\x5c|\x5c(certifi|pip)\x5c'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1587.002' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('884adc5d15368eba16b6efb54be7a9f3', '15eec3858777b14384c3c1d87d7aedd6');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, EventData.Image AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentProcess, EventData.User AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND (EventData.Image =~ '''(?i)\x5c(makecert|signtool|pvk2pfx|cert2spc|osslsigncode)\.exe$''' OR EventData.CommandLine =~ '''(?i)New-SelfSignedCertificate[^\n]*CodeSigning|Set-AuthenticodeSignature|openssl[^\n]*(req|x509)[^\n]*codeSigning''' OR (EventData.Image =~ '''(?i)\x5ccertutil\.exe$''' AND EventData.CommandLine =~ '''(?i)-(addstore|importpfx)'''))
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1587.002' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('401e62ff7c7f504bf85166783abedf9c', 'a4018471f00710b184224a48e0d24c0b');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: T1588_ObtainCapabilities_Detection
description: |
  Obtaining capabilities happens on the adversary's side; on a host only its residue is visible: offensive
  tools that reached the disk and were caught by Defender (1116/1117, HackTool / exploit families), PowerShell
  download cradles (4104), and browser downloads of tools / archives from code-hosting and paste sites.
sources:
- name: WindowsDefenderToolDetections
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID,
           get(item=EventData, field='Threat Name') AS ThreatName, get(item=EventData, field='Category Name') AS Category,
           get(item=EventData, field='Path') AS FilePath, get(item=EventData, field='Process Name') AS Process,
           get(item=EventData, field='Action Name') AS Action
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx')
    WHERE System.EventID.Value IN (1116, 1117)
      AND (get(item=EventData, field='Threat Name') =~ '''(?i)(HackTool|Exploit|Mimikatz|CobaltStrike|Meterpreter|Rubeus|Lazagne|PowerSploit|Sliver|Impacket|PsExec|Keylogger|Backdoor|Trojan:.*/(Meterpreter|Cobalt))'''
           OR get(item=EventData, field='Category Name') =~ '''(?i)(Tool|Exploit)''')
- name: PowerShellDownloadActivity
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.ScriptBlockText AS Command, EventData.Path AS ScriptPath, System.Security.UserID AS UserSID
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
    WHERE System.EventID.Value = 4104
      AND EventData.ScriptBlockText =~ '''(?i)(DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|Start-BitsTransfer)\s*[ (].{0,200}https?://'''
      AND NOT EventData.ScriptBlockText =~ '''(?i)^\s*#'''
- name: BrowserToolDownloads
  query: |
    SELECT * FROM foreach(
      row={ SELECT OSPath FROM glob(globs=['C:/Users/*/AppData/Local/Google/Chrome/User Data/*/History',
                                           'C:/Users/*/AppData/Local/Microsoft/Edge/User Data/*/History']) },
      query={
        SELECT OSPath AS HistoryFile, target_path AS SavedTo, tab_url AS Url,
               timestamp(winfiletime=start_time * 10) AS EventTime, total_bytes AS Bytes
        FROM sqlite(file=OSPath, query="SELECT target_path, tab_url, start_time, total_bytes FROM downloads")
        WHERE Url =~ '''(?i)(github\.com|githubusercontent\.com|gitlab\.com|pastebin\.com|transfer\.sh|mega\.nz|anonfiles|gofile\.io)'''
          AND SavedTo =~ '''(?i)\.(exe|dll|zip|rar|7z|ps1|bat|vbs|hta|py|msi|iso)$'''
      })
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1588' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('8a57ea393b9384322fc313ca7dc75b9c', 'fe274241992fca67092cfc6b3cc4a190');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, System.EventID.Value AS EventID, get(item=EventData, field='Threat Name') AS ThreatName, get(item=EventData, field='Category Name') AS Category, get(item=EventData, field='Path') AS FilePath, get(item=EventData, field='Process Name') AS Process FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx') WHERE System.EventID.Value IN (1116, 1117) AND (get(item=EventData, field='Threat Name') =~ '''(?i)(HackTool|Exploit|Mimikatz|CobaltStrike|Meterpreter|Rubeus|Lazagne|PowerSploit|Sliver|Impacket|PsExec|Keylogger|Backdoor)''' OR get(item=EventData, field='Category Name') =~ '''(?i)(Tool|Exploit)''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1588' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('482d3e5a254688b987fb1c193851fc6c', '7fec132112f7982f7b535ed106395fd8');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.T1588001.MalwareAcquisition
description: |
  Host-side residue of obtaining malware/attack tools (the acquisition itself happens on attacker infrastructure):
  browser visits to malware/exploit sharing sites and offensive-tool repositories, and executables/scripts staged
  directly in Downloads, Public or Windows\Temp.
sources:
- name: MalwareSiteHistoryChromium
  query: |
    SELECT * FROM foreach(
      row={SELECT OSPath FROM glob(globs=['C:/Users/*/AppData/Local/Google/Chrome/User Data/*/History',
                                         'C:/Users/*/AppData/Local/Microsoft/Edge/User Data/*/History'])},
      query={SELECT OSPath AS HistoryFile, url AS URL, title AS Title, visit_count AS VisitCount,
                    timestamp(winfiletime=last_visit_time * 10) AS LastVisit
             FROM sqlite(file=OSPath, query="SELECT url, title, visit_count, last_visit_time FROM urls")
             WHERE url =~ '''(?i)(vx-underground\.org|malshare\.com|bazaar\.abuse\.ch|virusshare\.com|das-malwerk\.de|virussign\.com|github\.com/ytisf/thezoo|exploit-db\.com/(download|exploits)|packetstormsecurity\.com/files|github\.com/[^/]+/(mimikatz|lazagne|rubeus|sharphound|bloodhound|sliver|empire|covenant|nishang|powersploit|impacket|seatbelt|certify|safetykatz)|raw\.githubusercontent\.com/\S*(mimikatz|lazagne|rubeus|sharphound|powersploit|nishang|invoke-mimikatz))'''})
- name: MalwareSiteHistoryFirefox
  query: |
    SELECT * FROM foreach(
      row={SELECT OSPath FROM glob(globs='C:/Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite')},
      query={SELECT OSPath AS HistoryFile, url AS URL, title AS Title, visit_count AS VisitCount,
                    timestamp(epoch=last_visit_date / 1000000) AS LastVisit
             FROM sqlite(file=OSPath, query="SELECT url, title, visit_count, last_visit_date FROM moz_places")
             WHERE url =~ '''(?i)(vx-underground\.org|malshare\.com|bazaar\.abuse\.ch|virusshare\.com|das-malwerk\.de|virussign\.com|github\.com/ytisf/thezoo|exploit-db\.com/(download|exploits)|packetstormsecurity\.com/files|github\.com/[^/]+/(mimikatz|lazagne|rubeus|sharphound|bloodhound|sliver|empire|covenant|nishang|powersploit|impacket|seatbelt|certify|safetykatz))'''})
- name: StagedExecutables
  query: |
    SELECT OSPath, Size, Mtime, Btime, hash(path=OSPath).SHA256 AS SHA256
    FROM glob(globs=['C:/Users/*/Downloads/*.{exe,dll,scr,hta,ps1,vbs,js,bat,cmd,msi,iso,img}',
                     'C:/Users/Public/**/*.{exe,dll,scr,hta,ps1,vbs,js,bat,cmd}',
                     'C:/Windows/Temp/*.{exe,dll,scr,hta,ps1,vbs,js,bat,cmd}'])
    WHERE NOT IsDir AND Size > 0
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1588.001' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('c1f957eb4dd1a635ad9fff0e159b0777');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT OSPath, Size, Mtime, Btime FROM glob(globs=['C:/Users/*/Downloads/*.{exe,dll,scr,hta,ps1,vbs,js,bat,cmd,msi,iso,img}', 'C:/Users/Public/**/*.{exe,dll,scr,hta,ps1,vbs,js,bat,cmd}', 'C:/Windows/Temp/*.{exe,dll,scr,hta,ps1,vbs,js,bat,cmd}']) WHERE NOT IsDir AND Size > 0
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1588.001' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('145c2846dfd0b55026d4dec1ccabab3e');

UPDATE ref_artifact_library SET analysis_steps = $orcafix2$NOT OBSERVABLE ON THE HOST: ATT&CK lists no host data source for this technique (it happens on attacker infrastructure or in public sources). An empty collection result is expected and is not evidence that it didn't happen.$orcafix2$ || chr(10) || chr(10) || COALESCE(analysis_steps, '')
WHERE t_code = 'T1590.002' AND COALESCE(analysis_steps, '') NOT LIKE 'NOT OBSERVABLE ON THE HOST%';

UPDATE ref_artifact_library SET analysis_steps = $orcafix2$NOT OBSERVABLE ON THE HOST: ATT&CK lists no host data source for this technique (it happens on attacker infrastructure or in public sources). An empty collection result is expected and is not evidence that it didn't happen.$orcafix2$ || chr(10) || chr(10) || COALESCE(analysis_steps, '')
WHERE t_code = 'T1590.006' AND COALESCE(analysis_steps, '') NOT LIKE 'NOT OBSERVABLE ON THE HOST%';

UPDATE ref_artifact_library SET analysis_steps = $orcafix2$NOT OBSERVABLE ON THE HOST: ATT&CK lists no host data source for this technique (it happens on attacker infrastructure or in public sources). An empty collection result is expected and is not evidence that it didn't happen.$orcafix2$ || chr(10) || chr(10) || COALESCE(analysis_steps, '')
WHERE t_code = 'T1591.001' AND COALESCE(analysis_steps, '') NOT LIKE 'NOT OBSERVABLE ON THE HOST%';

UPDATE ref_artifact_library SET analysis_steps = $orcafix2$NOT OBSERVABLE ON THE HOST: ATT&CK lists no host data source for this technique (it happens on attacker infrastructure or in public sources). An empty collection result is expected and is not evidence that it didn't happen.$orcafix2$ || chr(10) || chr(10) || COALESCE(analysis_steps, '')
WHERE t_code = 'T1592.003' AND COALESCE(analysis_steps, '') NOT LIKE 'NOT OBSERVABLE ON THE HOST%';

UPDATE ref_artifact_library SET analysis_steps = $orcafix2$NOT OBSERVABLE ON THE HOST: ATT&CK lists no host data source for this technique (it happens on attacker infrastructure or in public sources). An empty collection result is expected and is not evidence that it didn't happen.$orcafix2$ || chr(10) || chr(10) || COALESCE(analysis_steps, '')
WHERE t_code = 'T1595.002' AND COALESCE(analysis_steps, '') NOT LIKE 'NOT OBSERVABLE ON THE HOST%';

UPDATE ref_artifact_library SET analysis_steps = $orcafix2$NOT OBSERVABLE ON THE HOST: ATT&CK lists no host data source for this technique (it happens on attacker infrastructure or in public sources). An empty collection result is expected and is not evidence that it didn't happen.$orcafix2$ || chr(10) || chr(10) || COALESCE(analysis_steps, '')
WHERE t_code = 'T1596.001' AND COALESCE(analysis_steps, '') NOT LIKE 'NOT OBSERVABLE ON THE HOST%';

UPDATE ref_artifact_library SET analysis_steps = $orcafix2$NOT OBSERVABLE ON THE HOST: ATT&CK lists no host data source for this technique (it happens on attacker infrastructure or in public sources). An empty collection result is expected and is not evidence that it didn't happen.$orcafix2$ || chr(10) || chr(10) || COALESCE(analysis_steps, '')
WHERE t_code = 'T1596.005' AND COALESCE(analysis_steps, '') NOT LIKE 'NOT OBSERVABLE ON THE HOST%';

UPDATE ref_artifact_library SET analysis_steps = $orcafix2$NOT OBSERVABLE ON THE HOST: ATT&CK lists no host data source for this technique (it happens on attacker infrastructure or in public sources). An empty collection result is expected and is not evidence that it didn't happen.$orcafix2$ || chr(10) || chr(10) || COALESCE(analysis_steps, '')
WHERE t_code = 'T1597.001' AND COALESCE(analysis_steps, '') NOT LIKE 'NOT OBSERVABLE ON THE HOST%';

UPDATE ref_artifact_library SET analysis_steps = $orcafix2$NOT OBSERVABLE ON THE HOST: ATT&CK lists no host data source for this technique (it happens on attacker infrastructure or in public sources). An empty collection result is expected and is not evidence that it didn't happen.$orcafix2$ || chr(10) || chr(10) || COALESCE(analysis_steps, '')
WHERE t_code = 'T1608.001' AND COALESCE(analysis_steps, '') NOT LIKE 'NOT OBSERVABLE ON THE HOST%';

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Custom.LinkTargetAnalysis
description: |
  Host-side traces of staged link targets (ATT&CK T1608.005): lookups and visits of URL shorteners /
  redirectors and random-looking hosts. The staging itself happens on attacker infrastructure; what a host
  keeps is the victim following the link. len(list=) on a string failed verify (never ran); the SRUM part
  used an artifact that isn't available offline.
sources:
- name: SuspiciousDNSQueries
  query: |
    SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
           EventData.Image AS Process, EventData.QueryName AS Domain, EventData.QueryResults AS Results
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 22
      AND EventData.QueryName =~ '''(?i)(^|\.)(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|ow\.ly|rebrand\.ly|tiny\.cc|s\.id|v\.gd)$'''
- name: BrowserHistory
  query: |
    SELECT OSPath, url, title, visit_count, typed_count,
           timestamp(winfiletime=last_visit_time * 10) AS LastVisit
    FROM foreach(row={
        SELECT OSPath FROM glob(globs=['C:/Users/*/AppData/Local/Google/Chrome/User Data/*/History',
                                       'C:/Users/*/AppData/Local/Microsoft/Edge/User Data/*/History'])
      }, query={
        SELECT OSPath, * FROM sqlite(file=OSPath,
          query="SELECT url, title, visit_count, typed_count, last_visit_time FROM urls")
      })
    WHERE url =~ '''(?i)^https?://(www\.)?(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|ow\.ly|rebrand\.ly|tiny\.cc|s\.id|v\.gd)/'''
       OR url =~ '''(?i)^https?://[^/]*(ngrok|trycloudflare\.com|workers\.dev|pages\.dev|web\.app|firebaseapp\.com|glitch\.me|r2\.dev)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1608.005' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('47fd31a6a6501aebacba7b4254f4c5f2', '6edb3e1df14a4eb5249e286aa6ff6671');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, EventData.Image AS Process, EventData.QueryName AS Domain, EventData.QueryResults AS Results FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 22 AND EventData.QueryName =~ '''(?i)(^|\.)(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|ow\.ly|rebrand\.ly|tiny\.cc|s\.id|v\.gd)$'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1608.005' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('229f5a58ef3fd1be122e0ebd47960594', '432e3c8b8727a434457f8d2784fc3850');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.Containers.DeployContainer
description: |
  Deploy Container from this host: docker / podman / nerdctl / ctr / kubectl starting containers or pods,
  above all with host access (privileged, host PID/network, host filesystem mounts, docker socket).
sources:
- name: SysmonContainerCommands
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.CommandLine AS CommandLine,
           EventData.ParentImage AS ParentImage, EventData.User AS User,
           EventData.CommandLine =~ '''(?i)(--privileged|--pid[= ]host|--net(work)?[= ]host|--cap-add[= ](sys_admin|all)|-v\s+/:/|--volume[= ]/:/|docker\.sock|hostPID|hostNetwork|privileged:\s*true)''' AS HostAccess
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.CommandLine =~ '''(?i)((docker|podman|nerdctl)(\.exe)?"?\s+(container\s+)?(run|create|start|compose\s+up|service\s+create)\s|ctr(\.exe)?"?\s+(run|c\s+create|containers\s+create)\s|kubectl(\.exe)?"?\s+(run|create\s+deployment|apply|debug)\s)'''
- name: SecurityContainerCommands
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.NewProcessName AS Image, EventData.CommandLine AS CommandLine,
           EventData.ParentProcessName AS ParentImage, EventData.SubjectUserName AS User,
           EventData.CommandLine =~ '''(?i)(--privileged|--pid[= ]host|--net(work)?[= ]host|--cap-add[= ](sys_admin|all)|-v\s+/:/|--volume[= ]/:/|docker\.sock|hostPID|hostNetwork|privileged:\s*true)''' AS HostAccess
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value = 4688
      AND EventData.CommandLine =~ '''(?i)((docker|podman|nerdctl)(\.exe)?"?\s+(container\s+)?(run|create|start|compose\s+up|service\s+create)\s|ctr(\.exe)?"?\s+(run|c\s+create|containers\s+create)\s|kubectl(\.exe)?"?\s+(run|create\s+deployment|apply|debug)\s)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1610' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('809667ebf21170559fff93a1cf3b120c', '13294e854924bad0ed7003598a520bb1');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.User AS User FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND EventData.CommandLine =~ '''(?i)((docker|podman|nerdctl)(\.exe)?"?\s+(container\s+)?(run|create|start|compose\s+up|service\s+create)\s|ctr(\.exe)?"?\s+(run|c\s+create|containers\s+create)\s|kubectl(\.exe)?"?\s+(run|create\s+deployment|apply|debug)\s)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1610' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('79a6826902efd42be901f527982c2f5b', '73ec1166fc6745767149f3f59be64ebf');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.ReflectiveCodeLoading
description: |
  Reflective code loading: in-memory .NET assembly loading from command lines and PowerShell script blocks,
  and the .NET runtime loaded into processes that never host .NET normally (rundll32, regsvr32, notepad, ...).
sources:
- name: SysmonProcessCreation
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ProcessId AS ProcessId,
           EventData.Image AS ProcessImage, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.CommandLine =~ '''(?i)(\[(system\.)?reflection\.assembly\]::(load|loadfile|loadfrom)\b|assembly\]::load\(|\.load\(\s*\[convert\]::frombase64string|getdelegateforfunctionpointer|invoke-reflectivepeinjection)'''
- name: ClrLoadedIntoUnusualProcess
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ProcessId AS ProcessId,
           EventData.Image AS ProcessImage, EventData.ImageLoaded AS ImageLoaded, EventData.User AS User
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 7
      AND EventData.ImageLoaded =~ '''(?i)\\(clr|mscoreei|clrjit|coreclr)\.dll$'''
      AND EventData.Image =~ '''(?i)\\(rundll32|regsvr32|notepad|werfault|svchost|wmiprvse|mshta|wscript|cscript|msiexec|calc|explorer|dllhost|spoolsv|lsass|winword|excel|powerpnt|outlook)\.exe$'''
- name: PowerShellScriptBlocks
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ScriptBlockId AS ScriptBlockId,
           EventData.ScriptBlockText AS ScriptBlockText, EventData.Path AS Path
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
    WHERE System.EventID.Value = 4104
      AND EventData.ScriptBlockText =~ '''(?i)(\[(system\.)?reflection\.assembly\]::(load|loadfile|loadfrom)\s*\(|assembly\]::load\(|\.load\(\s*\[convert\]::frombase64string|getdelegateforfunctionpointer|invoke-reflectivepeinjection|virtualalloc.*createthread)'''
      AND NOT EventData.Path =~ '''(?i)^C:\\(Windows|Program Files|Program Files \(x86\))\\'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1620' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('6319124a7e646101a2a5b077da789213');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer, EventData.ProcessId AS ProcessId, EventData.Image AS ProcessImage, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 1 AND EventData.CommandLine =~ '''(?i)(\[(system\.)?reflection\.assembly\]::(load|loadfile|loadfrom)\b|assembly\]::load\(|\.load\(\s*\[convert\]::frombase64string|getdelegateforfunctionpointer|invoke-reflectivepeinjection)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1620' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('2f489aa0f1bcd25d3d8472bad3e631b0');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Windows.Detection.FinancialTheft
description: |
  Financial theft residue on a host: logons by finance/payroll accounts or to finance applications
  (Security 4624/4648), Outlook rules that forward or hide mail (business e-mail compromise), and processes
  whose command line carries a cryptocurrency wallet address (clipboard hijackers, ransom notes).
sources:
- name: SuspiciousFinanceLogins
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.EventID.Value AS EventID, System.Computer AS Computer,
           EventData.TargetUserName AS AccountName, EventData.LogonType AS LogonType, EventData.IpAddress AS IpAddress,
           EventData.ProcessName AS ProcessName, EventData.TargetServerName AS TargetServer
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE System.EventID.Value IN (4624, 4648)
      AND (EventData.ProcessName =~ '''(?i)(QuickBooks|SAP|Workday|Oracle|Peachtree|Sage)'''
           OR EventData.TargetUserName =~ '''(?i)(finance|treasury|accounting|payroll|ap_|ar_)''')
- name: OutlookRuleChanges
  query: |
    SELECT OSPath.Path AS Key, Mtime AS LastWrite
    FROM glob(globs='HKEY_USERS/*/Software/Microsoft/Office/*/Outlook/Profiles/*/*', accessor='registry')
    WHERE OSPath.Path =~ '''(?i)0a0d020000000000c000000000000046'''
- name: CryptoWalletInCommandLine
  query: |
    SELECT System.TimeCreated.SystemTime AS EventTime, System.Computer AS Computer,
           EventData.Image AS ProcessName, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage
    FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
    WHERE System.EventID.Value = 1
      AND EventData.CommandLine =~ '''(\bbc1q[02-9ac-hj-np-z]{38,58}\b|\b0x[a-fA-F0-9]{40}\b|\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b)'''
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1657' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('60ffac05c6d48e58a463de7757314e56', '8ef0feeb054284bec71ad7c2366fc16d');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT System.TimeCreated.SystemTime AS EventTime, System.EventID.Value AS EventID, System.Computer AS Computer, EventData.TargetUserName AS AccountName, EventData.LogonType AS LogonType, EventData.IpAddress AS IpAddress, EventData.ProcessName AS ProcessName FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx') WHERE System.EventID.Value IN (4624, 4648) AND (EventData.ProcessName =~ '''(?i)(QuickBooks|SAP|Workday|Oracle|Peachtree|Sage)''' OR EventData.TargetUserName =~ '''(?i)(finance|treasury|accounting|payroll)''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1657' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('b5b92e058043acfc5cd3866059de47cc', '57fb9819a4a05708ff4a53918bd1a2d6');

UPDATE ref_artifact_library SET surgical_yaml = $orcafix2$name: Custom.T1665.HideInfrastructure
description: Host-side traces of hidden C2 infrastructure - lookups of tunnelling / dynamic-DNS / free-TLD domains, tunnelling clients, and outbound connections to public addresses from script hosts or binaries in user-writable folders (Windows Filtering Platform)
sources:
  - name: WindowsFilteringPlatform
    query: |
      SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
             System.EventID.Value AS EventID, EventData.Application AS Application, EventData.DestAddress AS DestIP,
             EventData.DestPort AS DestPort, EventData.Protocol AS Protocol, EventData.ProcessID AS ProcessId
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
      WHERE System.EventID.Value IN (5156, 5157) AND EventData.Direction = '%%14593'
        AND NOT EventData.DestAddress =~ '''^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|0\.|22[4-9]\.|2[3-5]\d\.|::1$|fe80:|ff0)'''
        AND EventData.Application =~ '''(?i)\x5c(powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript|msbuild|installutil|certutil|bitsadmin)\.exe$|\x5c(users\x5cpublic|programdata|windows\x5ctemp|perflogs|appdata\x5clocal\x5ctemp)\x5c|\x5c(ngrok|cloudflared|frpc|chisel|plink)\.exe$'''
  - name: DNSQueries
    query: |
      SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
             EventData.Image AS Image, EventData.QueryName AS Domain, EventData.QueryResults AS QueryResults
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 22
        AND (EventData.QueryName =~ '''(?i)\.(ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|loca\.lt|serveo\.net|duckdns\.org|no-ip\.(com|org|biz)|ddns\.net|hopto\.org|zapto\.org|servehttp\.com|dynu\.(com|net)|portmap\.(io|host)|pagekite\.me|tk|ml|ga|cf|gq)$'''
             OR EventData.QueryName =~ '''^[a-z0-9-]{40,}\.''')
  - name: TunnelClientExecution
    query: |
      SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer,
             EventData.Image AS Image, EventData.CommandLine AS CommandLine, EventData.ParentImage AS ParentImage, EventData.User AS User
      FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
      WHERE System.EventID.Value = 1
        AND (EventData.Image =~ '''(?i)\x5c(ngrok|cloudflared|frpc|chisel|gost|iox)\.exe$'''
             OR EventData.CommandLine =~ '''(?i)\b(ngrok\s+(tcp|http|tls)|cloudflared\s+tunnel|chisel\s+client|frpc\s+-c)''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1665' AND md5(replace(COALESCE(surgical_yaml, ''), chr(13), '')) IN ('c2bffd421d28ef02c108399fbc4923eb');

UPDATE ref_artifact_library SET custom_vql = $orcafix2$SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime, System.Computer AS Computer, EventData.Image AS Image, EventData.QueryName AS Domain, EventData.QueryResults AS QueryResults FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx') WHERE System.EventID.Value = 22 AND (EventData.QueryName =~ '''(?i)\.(ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|loca\.lt|serveo\.net|duckdns\.org|no-ip\.(com|org|biz)|ddns\.net|hopto\.org|zapto\.org|servehttp\.com|dynu\.(com|net)|portmap\.(io|host)|pagekite\.me|tk|ml|ga|cf|gq)$''' OR EventData.QueryName =~ '''^[a-z0-9-]{40,}\.''')
$orcafix2$, updated_at = NOW()
WHERE t_code = 'T1665' AND md5(replace(COALESCE(custom_vql, ''), chr(13), '')) IN ('b45a0f5b3f99d5366f15203e4409bb04', '04e5d8b32acf2d0ee4f023d0a4deb1e5');
