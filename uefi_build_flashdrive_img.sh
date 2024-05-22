#!/bin/bash

cd ${DSTDIR}

# Define bash script
build_uefi () {
	mkdir -p grub
	if ! dd if=/dev/zero of=grub/fat.img conv=sparse bs=1M count=512; then
		echo ERROR 1; return 1
	fi
	if ! mformat -i grub/fat.img ::; then echo ERROR 2; return 1; fi
	if ! mmd -i grub/fat.img ::/EFI; then echo ERROR 3; return 1; fi
	if ! mmd -i grub/fat.img ::/EFI/BOOT; then echo ERROR 4; return 1; fi
	if ! cat > grub/startup.nsh << FOE
# Run XMHF
FS1:
load \EFI\BOOT\init-x86-amd64.efi
# Sleep 1
stall 1000000
# Load Debian
FS2:
for %i in \EFI\ubuntu\grubx64.efi \EFI\debian\grubx64.efi \EFI\BOOT\BOOTX64.EFI
	if exists %i then
		%i
		exit
	endif
endfor
# \EFI\BOOT\BOOTX64.EFI
FOE
	then
		echo ERROR 5; return 1
	fi
	if ! cat > grub/init-x86-amd64.efi.conf << FOE
argv0 serial=115200,8n1,0x3f8 boot_drive=0x80
\EFI\BOOT\hypervisor-x86-amd64.bin
\EFI\BOOT\SINIT.bin
FOE
	then
		echo ERROR 6; return 1
	fi
	for i in ../init-x86-amd64.efi ../hypervisor-x86-amd64.bin grub/startup.nsh \
			 grub/init-x86-amd64.efi.conf; do
		if ! mcopy -i grub/fat.img "$i" ::/EFI/BOOT; then
			echo ERROR 7 "$i"; return 1
		fi
	done
	if ! fallocate -d grub/fat.img; then echo ERROR 8; return 1; fi
	# If BOOTX64.EFI is present and startup.nsh is not, will run automatically.
}

# Run bash script above, generate UEFI FAT image to "grub/fat.img"
build_uefi