Please read "Arsenal Recon - End User License Agreement.txt" carefully before using this software.

Arsenal Image Mounter offers three command-line interface executables on Windows on x64 and Arm:

Arsenal Image Mounter CLI (a/k/a AIM CLI, aim_cli.exe) is a .NET tool that provides an integrated command line interface to Arsenal Image Mounter's virtual SCSI miniport driver and "Free Mode" functionality. The command “aim_cli --help” displays basic syntax for using AIM CLI. AIM CLI mounts disk images in read-only mode by default. AIM CLI is provided within the Arsenal Image Mounter download.

Arsenal Image Mounter Pro CLI (a/k/a AIM Pro CLI, aim_pro.exe) is a .NET tool that provides an integrated command line interface to Arsenal Image Mounter's virtual SCSI miniport driver and "Professional Mode" functionality. The command “aim_pro --help” displays basic syntax for using AIM Pro CLI. AIM Pro CLI mounts disk images in read-only mode by default. AIM Pro CLI is provided within the Arsenal Image Mounter download.

Arsenal Image Mounter Low Level (a/k/a AIM LL, aim_ll.exe) is a tool that does not use .NET and provides more “low level” access to the Arsenal Image Mounter driver. The command “aim_ll --help” displays basic syntax for using AIM LL. AIM LL mounts disk images in write-original mode by default, to maintain compatibility with existing scripts. AIM LL is largely deprecated and is only available directly from Arsenal.

Please note regarding the AIM CLI executables on Windows: 
•   All the AIM CLI executables on Windows offer varying degrees of functionality compared to the AIM GUI, so Arsenal recommends carefully reviewing the help (--help) from each executable to understand its capabilities.
•   AIM CLI, AIM Pro CLI, and AIM LL should normally be run with administrative privileges, but converting disk images from one format to another without mounting (and without using physical disks as targets), calculating checksums, and the Professional Mode features of creating Recon Reports and mounting partitions or Volume Shadow Copies in Windows file system driver bypass mode can be done without administrative privileges.
•   The AIM GUI actively onlines partitions within mounted/attached disks, but AIM CLI does not (unless the --online switch is used). Mounting/attaching a disk with AIM CLI is similar to simply attaching a physical disk to Windows without any extra logic, so (for example) Windows policy on the forensic workstation or file system errors within the mounted/attached disk may result (at least initially) in offline partitions and a lack of drive letter assignments.
•   While options and variables are passed to AIM with equals "=" signs in this readme, colon ":" signs are acceptable as well

Particular examples of syntax for the AIM CLI executables on Windows:

(Free Mode)

#display Free Mode help
aim_cli.exe --help

#mount an E01 forensic disk image write-temporary and with a fake disk signature, then bring disk/partitions online with automatic drive letter assignment, and finally delete differencing file automatically
aim_cli.exe --mount --fakesig --online --filename=C:\path\Win10Disk.E01 --provider=libewf --writeoverlay=C:\path\Win10Disk.E01.diff --autodelete

#mount a dd raw disk image write-original
aim_cli.exe --mount --writable --filename=C:\path\Win10Disk.dd

#mount a VMDK virtual machine disk image read-only
aim_cli.exe --mount --readonly --filename=C:\path\Win10Disk.vmdk --provider=DiscUtils

#convert an E01 forensic disk image to a new dd raw disk image, without mounting
aim_cli.exe --filename=Win10Disk.E01 --provider=LibEWF --convert=rawconversion.dd

#save an already mounted E01 forensic disk image (using disk id from AIM) to a dd raw disk image
aim_cli.exe --device=000200 --saveas=rawoutput.dd

#save an already mounted E01 forensic disk image (using disk device name from AIM) to a dd raw disk image
aim_cli.exe --device=\\?\PhysicalDrive4  --saveas=rawoutput.dd

#restore an E01 forensic disk image to an actual physical disk
aim_cli.exe --filename=Win10Disk.E01 --provider=LibEwf --convert=\\?\PhysicalDrive4

(Professional Mode)

#display Professional Mode help
aim_pro.exe --help

#mount all partitions within VHD virtual machine disk image in Windows file system driver bypass mode
aim_pro.exe --mountfs --filename=image.vhd --background

mount partition 3 within VHD virtual machine disk image in Windows file system driver bypass mode
aim_pro.exe --mountfs --filename=image.vhd --part=3 --background 

#mount a particular Volume Shadow Copy within VHD virtual machine disk image in Windows file system driver bypass mode
aim_pro.exe --mountfs --filename=image.vhd --vsc={4fc85291-ebac-4113-aeb5-590de0ae9b66} --background

#mount all partitions and Volume Shadow Copies within VHD virtual machine disk image in Windows file system driver bypass mode
aim_pro.exe --mountfs --filename=image.vhd --vscdir=C:\VSCs --background

#create a Recon Report from a VHD virtual machine disk image (including database-driven password attack and its VSCs) in HTML format
aim_pro.exe --analyze --filename=image.vhd --table=C:\PasswordAttackDBs\Password_Sledgehammer --vscs --html

#save a mounted disk with an unlocked BitLocker volume as a new image file with the BitLocker volume decrypted
aim_pro.exe --device=000200 --saveas=Win11Disk_Decrypted.dd --decrypt

Detailed syntax for the AIM CLI executables on Windows:

(Free Mode)

#mount a raw/forensic/virtual machine disk image as a "real" disk
aim_cli.exe --mount[=removable|cdrom] [--buffersize=size] [--readonly|--writable] [--fakesig] [--fakembr] [--online] --filename=imagefilename [--provider=MultiPartRaw|None|LibAFF4|DiscUtils|LibEwF|LibQcow] [--writeoverlay=differencingimagefile] [--autodelete]] [--background]

#start shared memory service mode, for mounting from other applications
aim_cli.exe --name=objectname [--buffersize=size] [--readonly|--writable] [--fakembr] --filename=imagefilename [--provider=MultiPartRaw|None|LibAFF4|DiscUtils|LibEwF|LibQcow] [--background]

#start TCP/IP service mode, for mounting from other computers
aim_cli.exe [--ipaddress=listenaddress] --port=tcpport [--readonly|--writable] [--fakembr] --filename=imagefilename [--provider=MultiPartRaw|None|LibAFF4|DiscUtils|LibEwF|LibQcow] [--background]

#convert a disk image without mounting
aim_cli.exe --filename=imagefilename [--fakembr] [--provider=MultiPartRaw|None|LibAFF4|DiscUtils|LibEwF|LibQcow] --convert=outputimagefilename [--variant=fixed|dynamic] [--background]

#convert a disk image without mounting the original and mounting the conversion as a physical disk
aim_cli.exe --filename=imagefilename [--fakembr] [--provider=MultiPartRaw|None|LibAFF4|DiscUtils|LibEwF|LibQcow] --convert=\\?\PhysicalDriveN [--background]

#calculate MD5, SHA1, or SHA256 checksum over disk image contents without mounting (all three calculated if a specific checksum is not specified)
aim_cli.exe --filename=imagefilename [--provider=MultiPartRaw|None|LibAFF4|DiscUtils|LibEwF|LibQcow] --checksum[=MD5|SHA1|SHA256]

#save a new disk image after mounting
aim_cli.exe --device=sixdigitdevicenumber|\\?\PhysicalDriveN --saveas=outputimagefilename [--variant=fixed|dynamic] [--background]

#dismount a mounted device
aim_cli.exe --dismount=[sixdigitdevicenumber|\\?\PhysicalDriveN] [--force]

#restore a disk image to an actual physical disk
aim_cli.exe --filename=imagefilename [--fakembr] [--provider=MultiPartRaw|None|LibAFF4|DiscUtils|LibEwF|LibQcow] --convert=\\?\PhysicalDriveN [--background]

#mount a new RAM disk
aim_cli.exe --ramdisk --disksize=size

#mount a new RAM disk from a VHD virtual machine disk image template
aim_cli.exe --ramdisk --filename=imagefilename

#create a new disk image file
aim_cli.exe --create --filename=imagefilename --disksize=size [--variant=fixed|dynamic] [--mount]

#display a list of mounted devices
aim_cli.exe --list

#rescan SCSI bus (corresponds to aim_ll.exe --rescan and "Rescan SCSI bus" in AIM GUI)
aim_cli.exe --rescan

#mount a disk at remote machine
aim_cli.exe --mount [--buffersize=size] [--readonly|--writable] [--fakesig] [--fakembr] [--online] --connect=ipaddress[:port] [--writeoverlay=differencingimagefile [--autodelete]]

(Professional Mode)

#display Professional Mode help
aim_pro.exe --help

#mount a Volume Shadow Copy as a disk image with a faked MBR partition table
aim_pro.exe --mount --fakembr --filename=imagefilename --vsc=VSCID [--background]

#start service mode, for mounting Volume Shadow Copy from other applications
aim_pro.exe --name=objectname [--readonly|writable] [--fakembr] --filename=imagefilename --vsc=VSCID [--background]

#mount a partition or Volume Shadow Copy in Windows file system driver bypass mode
aim_pro.exe --mountfs [--readonly|--writable] --filename=imagefilename [--part=n|--vsc=VSCID] [--background]
(Use --part to specify a partition, 1-based. O to mount a file system covering entire image. Omit to mount all partitions in image.)

#mount a partition and all Volume Shadow Copies of that partition in Windows file system driver bypass mode
aim_pro.exe --mountfs [--readonly|--writable] --filename=imagefilename [--part=n|--vscdir=directory [--background]
(Use --part to specify a partition, 1-based. O to mount a file system covering entire image. Omit to mount all partitions in image. directory specifies a directory where mount points for mounted VSCs will be created.)

#create a Recon Report
aim_pro.exe --analyze --filename=imagefilename [--table=passwordtable] [--checkdrv] [--vscs] [--html]

#save a mounted disk with an unlocked BitLocker volume as a new and fully decrypted disk image image
aim_pro.exe --device=sixdigitdevicenumber|\\?\PhysicalDriveN --saveas=imagefilename --decrypt

#convert a disk image containing a BitLocker-protected volume to a new and fully decrypted disk image
aim_pro.exe --filename=originalfilename --convert=newimagefilename --decrypt

#dismount a file system mounted in Windows file system driver bypass mode (a/k/a --mountfs)
aim_pro.exe --dismountfs=driveletter

Additional information regarding switches for the AIM CLI executables on Windows:

Sizes are in bytes by default but can be suffixed with for example M or G for MB or GB.

The --background switch will re-launch AIM CLI in a new process, detach from the current console window, and continue running in the background.

When the --force switch is used in combination with --dismount, the specified device is dismounted even if it may be in use.

The --autodelete switch will automatically delete the differencing file after the disk image is dismounted.

If --writeoverlay is used without specifying a differencing file, differencing data will be stored in RAM.

Recon Reports can include a database-driven password attack (--table), a check for present and valid drivers as well as details about non-standard drivers (--checkdrv), incorporation of information from VSCs (--vscs), and optional output to HTML (--html). Please note that Recon Reports are produced by the AIM CLI by opening (not mounting) the specified image file read only, so if a Recon Report is desired from a BitLocker-protected volume the AIM GUI should be used which has the ability to mount an image file and unlock its BitLocker-protected volume(s) before creation of a Recon Report.

The AIM Pro CLI commands --mountfs, --analyze, and --decrypt can be combined with options for decrypting BitLocker volumes:
--password=phrase
--recoverypassword=XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
--recoverykeyfile=path/to/XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX.BEK

When converting or saving "physical" objects (whether mounted or not), output type for disk images can be raw (.raw, .dd, .img, .ima, .bin), forensic (.e01), virtual machine (.vhd, .vhdx, .vdi, .vmdk), or dmg (.dmg). AIM CLI selects output type based on the outputimagefilename file extension. For virtual machine disk image formats, the optional --variant switch can be used to specify either fixed or dynamically expanding formats - the default is dynamic. This function can also be used to save virtually mounted objects (such as archives or directories mounted as CD/DVD-ROMs) to raw CD/DVD images, using the extensions .iso and .bin.

Use and License
We chose a dual-license for Arsenal Image Mounter (more specifically, Arsenal Image Mounter’s source code, APIs, and executables) to allow for royalty-free use in open source projects, but require financial support from commercial projects.

Arsenal Consulting, Inc. (d/b/a Arsenal Recon) retains the copyright to Arsenal Image Mounter, including the Arsenal Image Mounter source code, APIs, and executables, being made available under terms of the Affero General Public License v3. Arsenal Image Mounter source code, APIs, and executables may be used in projects that are licensed so as to be compatible with AGPL v3. If your project is not licensed under an AGPL v3 compatible license and you would like to use Arsenal Image Mounter source code, APIs, and/or executables, contact us (sales@ArsenalRecon.com) to obtain alternative licensing.

Contributors to Arsenal Image Mounter must sign the Arsenal Contributor Agreement (“ACA”). The ACA gives Arsenal and the contributor joint copyright interests in the source code.

