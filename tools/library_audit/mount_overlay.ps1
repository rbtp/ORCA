# Mounts a disk image read-only-for-real: a throwaway write overlay takes every write (the image file is never
# written) and a fake disk signature lets two clones of one disk (same signature) be online at the same time.
# Gives the largest partition the requested drive letter. Run as administrator.
#   .\mount_overlay.ps1 -AimCli <agent>\bin\arsenal\aim_cli.exe -Image D:\vm\attacked.vmdk -Letter Q
# Dismount: aim_cli --dismount=<device number shown in aim_<name>.txt> (the overlay is deleted automatically).
param([Parameter(Mandatory)][string]$AimCli, [Parameter(Mandatory)][string]$Image, [Parameter(Mandatory)][string]$Letter)
$ErrorActionPreference = 'Stop'
$dir = Split-Path $Image
$name = [IO.Path]::GetFileNameWithoutExtension($Image)
$before = @(Get-Disk | % Number)
$ov = Join-Path $dir "$name.overlay.vhdx"
$log = Join-Path $dir "aim_$name.txt"
if (Test-Path $ov) { Remove-Item $ov -Force }
if (Test-Path $log) { Remove-Item $log -Force }
Start-Process -FilePath $AimCli -ArgumentList "--mount", "--fakesig", "--online", "--filename=`"$Image`"", "--writeoverlay=`"$ov`"", "--autodelete", "--background" `
  -RedirectStandardOutput $log -NoNewWindow
# aim_cli --background leaves a child running: wait for its "mounted" line, not for the process
for ($i = 0; $i -lt 300; $i++) {
    if ((Test-Path $log) -and (Select-String -Path $log -Pattern 'Virtual disk mounted' -Quiet)) { break }
    Start-Sleep 2
}
Start-Sleep 5
$new = Get-Disk | ? { $before -notcontains $_.Number }
if (-not $new) { Get-Content $log; throw "no new disk" }
$new | ? IsOffline | Set-Disk -IsOffline $false
$new | ? IsReadOnly | Set-Disk -IsReadOnly $false
$part = Get-Partition -DiskNumber $new.Number | Sort-Object Size -Descending | Select-Object -First 1
if ($part.DriveLetter -and $part.DriveLetter -ne $Letter) { Remove-PartitionAccessPath -DiskNumber $new.Number -PartitionNumber $part.PartitionNumber -AccessPath "$($part.DriveLetter):\" }
if ($part.DriveLetter -ne $Letter) { Set-Partition -DiskNumber $new.Number -PartitionNumber $part.PartitionNumber -NewDriveLetter $Letter }
"disk $($new.Number) -> ${Letter}: " + (Test-Path "${Letter}:\Windows\System32\config\SYSTEM")
