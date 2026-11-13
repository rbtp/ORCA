$paths = @('C:\AtomicRedTeam', 'C:\Lab', "$env:TEMP", 'C:\Windows\Temp', 'C:\Users\Public')
foreach ($p in $paths) { try { Add-MpPreference -ExclusionPath $p -ErrorAction Stop; "excluded $p" } catch { "failed $p : $_" } }
(Get-MpPreference).ExclusionPath
