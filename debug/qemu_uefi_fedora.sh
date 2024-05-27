#!/bin/bash

# Run the TPM emulator in the background.
./qemu_tpm_emulator.sh &

# Run QEMU (download debian11efi.qcow2 from Google Drive, put it to /PATH/TO/)
# /usr/share/OVMF/OVMF_CODE.fd is UEFI firmware image
# /usr/share/OVMF/UefiShell.iso contains UEFI shell
# You will see a line like "Image base: 0x7F9FE000" in UEFI console. This line
#  will be used for GDB
qemu-system-x86_64 \
	-m 2G \
	-gdb tcp::1234 \
	-smp 4 \
	-cpu Haswell,vmx=yes \
	-machine q35 -device intel-iommu \
	-enable-kvm \
	-bios /usr/share/OVMF/OVMF_CODE.fd \
	-net none \
	-serial stdio \
	-chardev socket,id=chrtpm,path=/tmp/emulated_tpm/swtpm-sock \
	-drive media=cdrom,file=/usr/share/OVMF/UefiShell.iso,index=0 \
	-drive media=cdrom,file=../uefi_flashdrive_img/grub/fat.img,index=1 \
	-drive media=disk,file=debian11efi.qcow2,index=2
	