-- Migration: add_suspicious_locations_hash_technique
-- Run: docker exec -i orca-postgres psql -U postgres -d orca_db < add_suspicious_locations_hash_technique.sql
--
-- Seeds a utility technique (like MFT/AMCACHE, not a real MITRE T-code) that
-- hashes executable/script-capable files sitting directly in common
-- malware-drop locations, alongside MFT (full file listing) and AMCACHE
-- (hashes for anything that's ever executed) -- gives an analyst hash-based
-- situational awareness up front instead of a live pull once something looks
-- suspicious mid-review.
--
-- Deliberately NON-recursive (Downloads/*.exe, not Downloads/**/*.exe) and
-- extension-filtered -- confirmed live against a real, moderately-used dev
-- workstation that a recursive, unfiltered version of this same idea matched
-- 54,574 files and took 5.5 minutes (dominated by legitimate installer/
-- updater self-extraction subfolders, e.g. Visual Studio Installer staging
-- dozens of its own .exe/.dll files under a randomly-named Temp subfolder).
-- This non-recursive, extension-filtered version matched 16 files in ~1.1s
-- on the same machine -- malware sitting loose in Downloads/Temp is the
-- common real pattern this targets; nested installer-staging noise is what
-- going non-recursive specifically excludes. Startup folders are the
-- exception (kept recursive with **) since they're small and rarely nested.

INSERT INTO public.ref_artifact_library (t_code, name, custom_vql, updated_at)
VALUES (
    'SUSPICIOUS_LOCATIONS_HASH',
    'Common Malware Location File Hashes',
    $vql$SELECT FullPath, Size, Mtime, hash(path=FullPath).SHA256 AS SHA256
FROM glob(globs=[
  'C:/Users/*/Downloads/*.exe', 'C:/Users/*/Downloads/*.dll', 'C:/Users/*/Downloads/*.scr',
  'C:/Users/*/Downloads/*.ps1', 'C:/Users/*/Downloads/*.bat', 'C:/Users/*/Downloads/*.cmd',
  'C:/Users/*/Downloads/*.vbs', 'C:/Users/*/Downloads/*.js', 'C:/Users/*/Downloads/*.hta',
  'C:/Users/*/Downloads/*.msi', 'C:/Users/*/Downloads/*.jar', 'C:/Users/*/Downloads/*.lnk',
  'C:/Users/*/AppData/Local/Temp/*.exe', 'C:/Users/*/AppData/Local/Temp/*.dll', 'C:/Users/*/AppData/Local/Temp/*.scr',
  'C:/Users/*/AppData/Local/Temp/*.ps1', 'C:/Users/*/AppData/Local/Temp/*.bat', 'C:/Users/*/AppData/Local/Temp/*.cmd',
  'C:/Users/*/AppData/Local/Temp/*.vbs', 'C:/Users/*/AppData/Local/Temp/*.js', 'C:/Users/*/AppData/Local/Temp/*.hta',
  'C:/Windows/Temp/*.exe', 'C:/Windows/Temp/*.dll', 'C:/Windows/Temp/*.scr',
  'C:/Windows/Temp/*.ps1', 'C:/Windows/Temp/*.bat', 'C:/Windows/Temp/*.vbs',
  'C:/Users/*/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/**',
  'C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/**'
])
WHERE NOT IsDir AND Size < 52428800 AND Size > 0$vql$,
    NOW()
)
ON CONFLICT (t_code) DO UPDATE SET
    name = EXCLUDED.name,
    custom_vql = EXCLUDED.custom_vql,
    updated_at = NOW();
