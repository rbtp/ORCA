Please read "Arsenal Recon - End User License Agreement.txt" carefully before using this software.

Arsenal Image Mounter Remote Agent (a/k/a AIM Remote Agent) is a CLI application which runs on Windows, Linux, and BSD that makes disks available to Arsenal Image Mounter over a network. Arsenal strongly recommends that AIM Remote Agent be run from a forensically-sound boot environment that is compatible with Secure Boot and ensures disks are kept offline and read only at all times. Once one or more disks are made available to AIM via AIM Remote Agent, any of AIM's mount modes can be selected. For example, if write temporary mode is selected, AIM's write filter will be applied on the forensic workstation running AIM to facilitate interaction with the remote disks as if they were locally attached, writable, and complete (a/k/a “physical” or “real”) disks - allowing AIM to do things with remote disks which include interacting with their BitLocker-protected volumes, mounting their Volume Shadow Copies using multiple methods, and launching them into virtual machines.

Assuming that one or more disks have been made available with AIM Remote Agent, and AIM is running on the same network as AIM Remote Agent, AIM will automatically alert the user that remote disks are available (unless network filtering is interfering). A manual connection between AIM and the AIM Remote Agent can be accomplished via the "Advanced/Manually connect to AIM Remote Agent..." option.

AIM can be connected to multiple AIM Remote Agents in the same session. If additional drive letters are no longer available on AIM's end, remote disks will still be mounted by AIM but mount points will need to be created manually.

AIM Remote Agent uses UDP broadcasts and TCP connections on ports 9000 and 9001. You may be asked by your host firewall (e.g. Windows Firewall) when starting AIM whether AIM should be allowed to use various networks (e.g. domain, private, and public) to communicate with AIM Remote Agents. 

Please note:
•   Using AIM Remote Agent to connect remote disks to AIM over a network introduces unique variables when compared to locally connecting disk images or actual physical disks to AIM - for example, a network switch or hub, network cables, and network drivers on both the AIM Remote Agent and AIM ends. It is important to have confidence in the hardware and drivers being used to establish connections between AIM Remote Agent and AIM.
•   It is technically possible for AIM to write to the original disk made available by AIM Remote Agent, but this would require that the bootable environment allow write access to the disk, that AIM Remote Agent is run with the --writable switch, and that a write original mount mode is selected in AIM after a connection to AIM Remote Agent has been established
•   AIM Remote Agent compiled for various operating systems and architectures can be found in the "remote" subfolder 
•   AIM Remote Agent is designed to be used on secure local area networks. If encrypted communications are desired, tools like stunnel can be used.
•   If you are using a specially-configured WinPE as a forensically-sound boot environment, you will need to run the "wpeutil disablefirewall" command once WinPE is booted so that AIM Remote Agent can be used successfully.
•   AIM Remote Agent will use IPv6 if no network adapters are found with an IPv4 address

Use and License
We chose a dual-license for Arsenal Image Mounter (more specifically, Arsenal Image Mounter’s source code, APIs, and executables) to allow for royalty-free use in open source projects, but require financial support from commercial projects.

Arsenal Consulting, Inc. (d/b/a Arsenal Recon) retains the copyright to Arsenal Image Mounter, including the Arsenal Image Mounter source code, APIs, and executables, being made available under terms of the Affero General Public License v3. Arsenal Image Mounter source code, APIs, and executables may be used in projects that are licensed so as to be compatible with AGPL v3. If your project is not licensed under an AGPL v3 compatible license and you would like to use Arsenal Image Mounter source code, APIs, and/or executables, contact us (sales@ArsenalRecon.com) to obtain alternative licensing.

Contributors to Arsenal Image Mounter must sign the Arsenal Contributor Agreement (“ACA”). The ACA gives Arsenal and the contributor joint copyright interests in the source code.

