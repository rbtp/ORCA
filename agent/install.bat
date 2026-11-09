@echo off
echo [ORCA Agent Installer]
echo.

REM Locate python.exe explicitly instead of trusting a bare `python` to
REM resolve on PATH -- on a box where it doesn't (no PATH entry, stale PATH
REM from before Python was installed, etc.) "python ..." fails with no
REM useful error here and surfaces later as a confusing ModuleNotFoundError
REM once something ELSE does happen to find a different interpreter.
REM Checks, in order: PATH, the per-user python.org install location, the
REM all-users install location.
set "PYEXE="
for /f "delims=" %%P in ('where python 2^>nul') do if not defined PYEXE set "PYEXE=%%P"
if not defined PYEXE if exist "%LocalAppData%\Programs\Python\Python313\python.exe" set "PYEXE=%LocalAppData%\Programs\Python\Python313\python.exe"
if not defined PYEXE if exist "C:\Program Files\Python313\python.exe" set "PYEXE=C:\Program Files\Python313\python.exe"
if not defined PYEXE goto :nopython
echo Using Python at: %PYEXE%
goto :havepython

:nopython
echo ERROR: could not find python.exe.
echo Checked: PATH, %LocalAppData%\Programs\Python\Python313\python.exe, C:\Program Files\Python313\python.exe
echo Find your python.exe yourself -- e.g. run "where python" from a brand new
echo terminal window, or check wherever you ran the installer from. Then either
echo add its folder to PATH and open a new terminal, or edit the PYEXE line near
echo the top of this script to point directly at it.
pause
exit /b 1

:havepython

set /p SERVER_URL="Enter ORCA server URL (e.g. https://10.11.110.60 -- no port; 8000 is backend-internal only, not reachable from outside the container): "
set /p TOKEN="Enter your JWT token: "

REM Written next to this script explicitly (%~dp0), not a bare relative
REM path -- orca_agent.py always loads config.json from its own directory
REM (os.path.dirname(__file__)), regardless of the caller's current
REM working directory. A bare `> config.json` instead lands wherever this
REM batch file happened to be run FROM, which silently isn't the same
REM folder unless you launched it with that as your cwd already.
echo { "server_url": "%SERVER_URL%", "token": "%TOKEN%", "bin_dir": "./bin", "poll_interval": 5 } > "%~dp0config.json"

REM Installed from the bundled vendor/ wheels, not PyPI -- on an
REM internet-isolated box, a plain `pip install requests` silently fails
REM (its errors were being swallowed by 2>nul too, which is how this went
REM unnoticed until orca_agent.py actually ran and hit ModuleNotFoundError).
REM Invoked as `"%PYEXE%" -m pip`, not a bare `pip`, so this always installs
REM into the exact interpreter resolved above, not whatever a separate
REM `pip` command happens to resolve to on PATH.
"%PYEXE%" -m pip install --no-index --find-links="%~dp0vendor" requests

REM orca_agent.py's config.json has bin_dir="./bin" -- a RELATIVE path.
REM orca_agent.py resolves it against whatever the current working
REM directory happens to be at runtime, not against its own script folder
REM (unlike config.json's own load path, which IS anchored to __file__).
REM Launching it directly (bare `start ... orca_agent.py`, or a scheduled
REM task with no working directory set) leaves that cwd undefined --
REM Task Scheduler in particular runs SYSTEM tasks with a working directory
REM that is NOT C:\ORCA\agent by default, which would silently relocate
REM every downloaded binary (arsenal/aim_cli.exe included) to the wrong
REM place on next boot. A tiny wrapper .bat that cd's first, with both
REM paths already fully resolved to absolutes, removes the ambiguity for
REM both the immediate launch below and the scheduled task.
(
echo @echo off
echo cd /d "%~dp0"
echo "%PYEXE%" "%~dp0orca_agent.py"
) > "%~dp0run_agent.bat"

REM orca_agent.py is a plain script with no Service Control Manager
REM handshake (no win32serviceutil/SetServiceStatus), so registering it as
REM a native service via `sc create` fails with error 1053 ("did not
REM respond to the start or control request in a timely fashion") -- SCM
REM waits for a start-response that the script can never send.
REM
REM A Task Scheduler task was tried here first (AtLogOn trigger,
REM LogonType Interactive, RunLevel Highest -- the standard documented way
REM to get UAC-free elevation at logon) and rejected after live testing:
REM Task Manager's Elevated column showed the resulting python.exe as NOT
REM elevated despite RunLevel Highest, and Arsenal's aim_cli.exe (the
REM DevIoDrv/deviosvc component the DiscUtils provider uses for every
REM .vhd/.vhdx mount) needs real elevation -- it fails with "cannot access
REM driver" under that silently-unelevated token, while the identical
REM command run via a manual "Run as administrator" window completes in
REM seconds. (An earlier attempt at this same AtLogOn task additionally
REM had its own bug: a single-quoted PowerShell string doesn't expand
REM $env:USERDOMAIN/$env:USERNAME at all, silently registering the task
REM for a user literally named "$env:USERDOMAIN\$env:USERNAME" -- fixing
REM that bug didn't fix the deeper elevation problem, which is why this
REM moved off Task Scheduler entirely rather than patching it further.)
REM
REM A Startup-folder shortcut with its own "Run as administrator"
REM compatibility flag triggers the SAME real UAC elevation flow a manual
REM run uses -- confirmed to actually produce an elevated process, unlike
REM Task Scheduler's RunLevel Highest here. Tradeoff: a UAC prompt once
REM per logon that needs approving (not fully silent) -- but given the
REM agent already only comes up after an interactive logon anyway (same
REM dependency Docker Desktop itself has on this box), one click at that
REM same moment is a small ask for something that actually works.
schtasks /delete /tn "ORCA_Agent" /f >nul 2>nul
for /f "delims=" %%S in ('powershell -NoProfile -Command "[Environment]::GetFolderPath('Startup')"') do set "STARTUP_DIR=%%S"
powershell -NoProfile -Command ^
  "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('%STARTUP_DIR%\ORCA_Agent.lnk');" ^
  "$s.TargetPath = '%~dp0run_agent.bat'; $s.WorkingDirectory = '%~dp0'; $s.Save();" ^
  "$b = [IO.File]::ReadAllBytes('%STARTUP_DIR%\ORCA_Agent.lnk');" ^
  "$b[0x15] = $b[0x15] -bor 0x20;" ^
  "[IO.File]::WriteAllBytes('%STARTUP_DIR%\ORCA_Agent.lnk', $b)"

echo Starting agent now via the same shortcut (approve the UAC prompt)...
start "" "%STARTUP_DIR%\ORCA_Agent.lnk"

echo.
echo [ORCA Agent installed and started]
echo Agent will connect to %SERVER_URL%
pause
