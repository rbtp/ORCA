Please read "Arsenal Recon - End User License Agreement.txt" carefully before using this software.

Arsenal Image Mounter offers two command-line interface executables on Linux:

Arsenal Image Mounter Linux CLI (a/k/a AIM Linux CLI, aim_cli) is a .NET tool that provides an integrated command line interface primarily to Arsenal Image Mounter's image conversion features. The command “aim_cli --help” displays basic syntax for using AIM Linux CLI. AIM Linux CLI mounts disk images in read-only mode by default. AIM Linux CLI is provided within the Arsenal Image Mounter download.

Arsenal Image Mounter Linux Pro CLI (a/k/a AIM Linux Pro CLI, aim_pro) is a .NET tool that provides an integrated command line interface to Arsenal Image Mounter's image and file system analysis features, including mounting file systems without using file system drivers provided by Linux - resulting in the exposure of metafiles, unallocated space, etc. The command “aim_pro --help” displays basic syntax for using AIM Linux Pro CLI. AIM Linux Pro CLI mounts disk images in read-only mode by default. AIM Linux Pro CLI is provided within the Arsenal Image Mounter download.

Please note regarding the AIM CLI executables on Linux:
•   The AIM Linux CLI and AIM Linux Pro CLI executables offer varying degrees of functionality compared to the AIM GUI on Windows, so Arsenal recommends carefully reviewing the help (--help) from each executable to understand its capabilities.
•   The AIM CLI executables on Linux do not mount disk images as complete disks as AIM on Windows, rather they provide functionality which does not require mounting or they mount the contents of disk images in file system driver bypass mode (FSDBM).
•   The following packages are required to enable the full functionality of the AIM CLI executables (organized by package name, library, and purpose):
libevtx-dev; libevtx; Supports passkey usage identification
libewf-dev; libewf; Supports E01, L01, AFF image file formats
libqcow-dev; libqcow; Supports QCow image file format
libbde-dev; libbde; Supports BitLocker encrypted volumes
libfuse3-dev; libfuse3; Supports mounting images in file system driver bypass mode (FSDBM)
•   Regarding packages, AIM currently provides our own libbde in runtimes\linux-x64\native\libbde.so and runtimes\linux-arm64\native\libbde.so because we have made some modifications that have not been merged into the main project yet. So, obtaining libbde separately is not currently necessary.
•   VSCID in the AIM CLI executables on Linux syntax refers to the VSC GUID
•   Sizes are in bytes by default but can be suffixed with for example M or G for MB or GB
•   Make sure to add the execute permission to AIM Linux CLI (chmod +x aim_cli) and AIM Linux Pro CLI (chmod +x aim_pro) before attempting to use them

Particular examples of syntax for the AIM CLI executables on Linux:

(Free Mode)

#display Free Mode help
aim_cli --help

#convert an E01 forensic disk image to a new dd raw disk image, without mounting
aim_cli --filename=Win10Disk.E01 --convert=Win10Disk.dd

#save physical disk sda as a new E01 forensic disk image
aim_cli --device=/dev/sda --saveas=sda.E01

(Professional Mode)

#display Professional Mode help
aim_pro --help

#mount an E01 forensic disk image and unlock its BitLocker-protected volume in file system driver bypass mode (FSDBM)
aim_pro –mountfs --readonly --filename=Romeo.E01 —password='Romeo&Juliet' --background

#save an E01 forensic disk image containing a BitLocker-protected volume as a new and fully-decrypted E01 forensic disk image
aim_pro --filename=Romeo.E01 --convert=Romeo_Decrypted.E01 --decrypt --password='Romeo&Juliet' 

#save an attached physical disk containing a BitLocker-protected volume as a new and fully decrypted E01 forensic disk image
aim_pro --device=/dev/sdc --saveas=RomeoPhysical_Decrypted.E01 --decrypt --password='Romeo&Juliet' 

Detailed syntax for the AIM CLI executables on Linux:

(Free Mode)

#create a new disk image
aim_cli --create --filename=imagefilename --disksize=size [--variant=fixed|dynamic]

#calculate MD5, SHA1, or SHA256 checksum over disk image contents without mounting (all three calculated if a specific checksum is not specified)
aim_cli --filename=imagefilename [--provider=MultiPartRaw|None|LibAFF4|DiscUtils|LibEwF|LibQcow] --checksum[=MD5|SHA1|SHA256]

#start TCP/IP service mode, for mounting from other computers:
aim_cli [--ipaddress=listenaddress] --port=tcpport [--readonly|--writable] [--fakembr] --filename=imagefilename [--provider=MultiPartRaw|None|LibAFF4|DiscUtils|LibEwF|LibQcow] [--background]

#convert a disk image from one format to another, without mounting
aim_cli --filename=imagefilename [--fakembr] [--provider=MultiPartRaw|None|LibAFF4|DiscUtils|LibEwF|LibQcow] --convert=outputimagefilename [--variant=fixed|dynamic] [--background]

#convert a disk image from one format to another, without mounting the original and mounting the conversion as a physical disk
aim_cli --filename=imagefilename [--fakembr] [--provider=MultiPartRaw|None|LibAFF4|DiscUtils|LibEwF|LibQcow] --convert=/dev/sdX [--background]

#save a physical disk as a disk image
aim_cli --device=/dev/sdX --saveas=outputimagefilename [--variant=fixed|dynamic] [--background]

(Professional Mode)

#start service mode, for mounting from other applications
aim_pro --name=objectname [--readonly | --writable] [--fakembr] --filename=imagefilename [--vsc=VSCID] [--background]

#mount a partition or Volume Shadow Copy in file system driver bypass mode (FSDBM)
aim_pro --mountfs[=mntdir] [--readonly|--writable] --filename=imagefilename [--part=n|--vsc=VSCID] [--background]
(Use --part to specify a partition, 1-based. O to mount a file system covering entire image. Omit to mount all partitions in image. mntdir specifies directory where mount points for each mounted partition is created. Default is /mnt.)

#mount a partition and all Volume Shadow Copies of that partition in file system driver bypass mode (FSDBM)
aim_pro --mountfs[=mntdir] [--readonly|--writable] --filename=imagefilename [--part=n] --vscdir=directory [--background]
(Use --part to specify a partition, 1-based. O to mount a file system covering entire image. Omit to mount all partitions in image. mntdir specifies directory where mount points for each mounted partition is created. Default is /mnt. directory specifies a directory where mount points for mounted VSCs will be created.)

#dismount a file system mounted with --mountfs
aim_pro --dismountfs=mntdir

#save a physical disk as a disk image
aim_pro --device=/dev/sdX --saveas=imagefilename [--decrypt]
(--decrypt saves BitLocker volumes in their decrypted form. Requires unlocked BitLocker volumes.)

#convert an existing disk image to another disk image format
aim_pro --filename=originalfilename --convert=newfilename [--decrypt]
(--decrypt saves BitLocker volumes in their decrypted form. See 'BitLocker support' below.)

Syntax to create a Recon Report from a disk image
aim_pro --analyze --filename=imagefilename [--table=passwordtable] [--checkdrv] [--vscs] [--html]
(--table opens a password attack database and uses it to attempt to find account passwords, --checkdrv checks and verifies that all drivers have present and valid driver files and also prints information about non-standard drivers found, --vscs includes VSCs in the analysis, --html outputs analysis report in HTML format)

BitLocker support
Commands --mountfs, --analyze and --decrypt can be combined with options for decrypting BitLocker volumes
--password=phrase
--recoverypassword=XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
--recoverykeyfile=path/to/XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX.BEK

Use and License
We chose a dual-license for Arsenal Image Mounter (more specifically, Arsenal Image Mounter’s source code, APIs, and executables) to allow for royalty-free use in open source projects, but require financial support from commercial projects.

Arsenal Consulting, Inc. (d/b/a Arsenal Recon) retains the copyright to Arsenal Image Mounter, including the Arsenal Image Mounter source code, APIs, and executables, being made available under terms of the Affero General Public License v3. Arsenal Image Mounter source code, APIs, and executables may be used in projects that are licensed so as to be compatible with AGPL v3. If your project is not licensed under an AGPL v3 compatible license and you would like to use Arsenal Image Mounter source code, APIs, and/or executables, contact us (sales@ArsenalRecon.com) to obtain alternative licensing.

Contributors to Arsenal Image Mounter must sign the Arsenal Contributor Agreement (“ACA”). The ACA gives Arsenal and the contributor joint copyright interests in the source code.

