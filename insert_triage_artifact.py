import sys
sys.path.insert(0, 'backend')
from core.database_manager import db
from sqlalchemy import text

triage_vqls = {
    'TRIAGE_EVTX': "SELECT EventTime, Computer, Channel, Provider, EventID, EventRecordID, UserID, Message FROM Artifact.Windows.EventLogs.Evtx(EvtxGlob='%SystemRoot%/System32/winevt/Logs/*.evtx') LIMIT 100000",
    'TRIAGE_PREFETCH': "SELECT Name, LastRunTimes, RunCount, Filename, Hash, Loaded FROM Artifact.Windows.Forensics.Prefetch()",
    'TRIAGE_MFT': "SELECT EntryNumber, FullPath, FileName, FileSize, InUse, IsDir, Created0x10, Modified0x10, Accessed0x10 FROM parse_mft(filename='C:/$MFT', accessor='ntfs') WHERE NOT IsDir LIMIT 500000",
    'TRIAGE_REG': "SELECT ModTime, FullPath, Name, Type, Data FROM Artifact.Windows.Registry.NTUser() LIMIT 100000",
    'TRIAGE_BROWSER': "SELECT Url, Title, VisitCount, LastVisitTime, TypedCount FROM Artifact.Windows.Applications.Chrome.History() LIMIT 50000",
    'TRIAGE_LNK': "SELECT SourceFile, TargetPath, WorkingDir, Arguments, FileSize, CreationTime, AccessTime, WriteTime FROM Artifact.Windows.Forensics.Lnk()",
    'TRIAGE_TASKS': "SELECT EventTime, TaskName, Command, Arguments, UserId FROM Artifact.Windows.EventLogs.ScheduledTasks()",
    'TRIAGE_WMI': "SELECT Name, Namespace, Query, Filter, Consumer, Binding FROM Artifact.Windows.Persistence.PermanentWMIEvents()",
    'TRIAGE_SRUM': "SELECT AutoIncId, TimeStamp, AppId, UserId, BytesSent, BytesRecvd, NetworkInterface FROM Artifact.Windows.Forensics.SRUM() LIMIT 100000",
    'TRIAGE_RECYCLE': "SELECT SourcePath, FileSize, DeletedTime, FileName FROM Artifact.Windows.Forensics.RecycleBin()",
    'TRIAGE_USB': "SELECT EventTime, DeviceDescription, DeviceID, SerialNumber, Manufacturer, HardwareID FROM Artifact.Windows.Forensics.USBDevices()",
}

with db.engine.begin() as conn:
    for t_code, vql in triage_vqls.items():
        conn.execute(text('''
            INSERT INTO ref_artifact_library (t_code, custom_vql)
            VALUES (:t, :v)
            ON CONFLICT (t_code) DO UPDATE SET custom_vql = EXCLUDED.custom_vql, surgical_yaml = NULL
        '''), {'t': t_code, 'v': vql})
        print(f'Updated {t_code}')

print('All triage VQLs updated successfully')