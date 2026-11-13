# FORENSIC_AUTORUNS — Forensic.Persistence.Autoruns

- Captures: autostart registry entries (hive, key, value name, command): Run / RunOnce / RunOnceEx / RunServices / policy Run for HKLM (incl. Wow6432Node) and every user hive under HKEY_USERS, plus Winlogon Shell / Userinit / Taskman / VmApplet / GinaDLL.
- Mode: file/registry (registry accessor under the remap; HKEY_USERS/* enumerates all mounted NTUSER hives).
- Built-in used: none (hand-written glob over the autostart keys; Windows.Sysinternals.Autoruns needs the autoruns.exe binary and a live host).
- Rows on P: 7 (HKLM Run x2, Winlogon Shell/Userinit/VMApplet, HKU\Default Run, HKU\orcatest Run).
