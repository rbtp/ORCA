Please read "Arsenal Recon - End User License Agreement.txt" carefully before using this software.

Arsenal Image Mounter PowerShell Module (a/k/a AIM PowerShell Module) offers more reliable command line functionality when using PowerShell versus the standard AIM CLI that was designed for use with Windows Command Prompt.

Multiple versions of the AIM PowerShell Module can be found in the following "PowerShell" subfolders:

net48: PowerShell 5.x / .NET 4.8
net8.0: PowerShell Core 7.4.x / .NET 8.0
net9.0 PowerShell Core 7.5.x / .NET 9.0
net10.0 PowerShell Core 7.6.x / .NET 10.0

Example of AIM PowerShell Module (net10.0) commands which will import the module, mount a disk image, list the disk's volumes, list the mount points, and finally dismount the disk image:

PS C:\> Import-Module 'C:\Arsenal-Image-Mounter-v3.12.344\PowerShell\net10.0\Arsenal.ImageMounter.PowerShell.dll'

PS C:\> $vdisk = New-AimVirtualDisk -FileName "(Path to Disk Image)" -WriteOverlayMem -Online

PS C:\> Get-AimDiskVolumes $vdisk
\\?\Volume{152a6400-e077-4c27-ae79-41f916c4f629}\
\\?\Volume{0c06df19-1a83-42a6-927c-3531a1db8093}\
\\?\Volume{3a0b61ea-4c9a-4e9e-9f98-4dd10f88d9ed}\
\\?\Volume{141b9de2-eb4d-4fa0-8495-ea51a4c969e6}\
\\?\Volume{54fe5a08-508c-48d6-879c-d46f1a08ed6e}\

PS C:\> Get-AimDiskVolumes $vdisk | Get-AimVolumeMountPoints
K:\
L:\
O:\
D:\
J:\

PS C:\> Remove-AimVirtualDisk $vdisk

Use and License
We chose a dual-license for Arsenal Image Mounter (more specifically, Arsenal Image Mounter’s source code, APIs, and executables) to allow for royalty-free use in open source projects, but require financial support from commercial projects.

Arsenal Consulting, Inc. (d/b/a Arsenal Recon) retains the copyright to Arsenal Image Mounter, including the Arsenal Image Mounter source code, APIs, and executables, being made available under terms of the Affero General Public License v3. Arsenal Image Mounter source code, APIs, and executables may be used in projects that are licensed so as to be compatible with AGPL v3. If your project is not licensed under an AGPL v3 compatible license and you would like to use Arsenal Image Mounter source code, APIs, and/or executables, contact us (sales@ArsenalRecon.com) to obtain alternative licensing.

Contributors to Arsenal Image Mounter must sign the Arsenal Contributor Agreement (“ACA”). The ACA gives Arsenal and the contributor joint copyright interests in the source code.

