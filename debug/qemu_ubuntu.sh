#!/bin/bash

clear

# Use UEFI in qemu. Default: disabled
enable_uefi=0
# Use sw-tpm in qemu. Default: disabled
enable_swtpm=0
# Use 2GB mem and 4 cores in qemu. Otherwise, use 4GB mem and 16 cores in qemu. Default: enabled.
enable_vm_small=1

# Handling command-line options manually
for arg in "$@"; do
    case $arg in
        -uefi)
            enable_uefi=1
            shift # Move to next argument
            ;;
        -swtpm)
            enable_swtpm=1
            shift # Move to next argument
            ;;
        -vm_large)
            enable_vm_small=0
            shift # Move to next argument
            ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 1
            ;;
    esac
done

# Function to run QEMU with given memory and core settings
# Run QEMU (download debian11efi.qcow2 from Google Drive, put it to /PATH/TO/)
# /usr/share/OVMF/OVMF_CODE.fd is UEFI firmware image
# /usr/share/OVMF/UefiShell.iso contains UEFI shell
# You will see a line like "Image base: 0x7F9FE000" in UEFI console. This line
#  will be used for GDB
# [NOTE] Qemu does not need to load UefiShell.iso in Ubuntu, so we load fat.img in two disks to keep the FS* sequence.
run_qemu() {
    local mem=$1
    local cores=$2
    local additional_params=""
    local qemu_command=""

    if [ "$enable_swtpm" -eq 1 ]; then
        additional_params="-chardev socket,id=chrtpm,path=/tmp/emulated_tpm/swtpm-sock \
        	-tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0"
    fi

    if [ "$enable_uefi" -eq 1 ]; then
        qemu_command+="qemu-system-x86_64 \
            -m $mem \
            -gdb tcp::1234 \
            -smp $cores \
            -cpu Haswell,vmx=yes \
            -machine q35 -device intel-iommu \
            -enable-kvm \
            -bios /usr/share/ovmf/OVMF.fd \
            -net none \
            -serial stdio \
            -drive media=cdrom,file=../uefi_flashdrive_img/grub/fat.img,index=0 \
            -drive media=cdrom,file=../uefi_flashdrive_img/grub/fat.img,index=1 \
            -drive media=disk,file=debian11efi.qcow2,index=2"
    else
        qemu_command+="qemu-system-x86_64 \
            -m $mem \
            -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::2222-:22 \
            -gdb tcp::1234 \
            -smp $cores \
            -cpu Haswell,vmx=yes \
            -enable-kvm \
            -serial stdio \
            -drive media=disk,file=../grub/c.img,index=0 \
            -drive media=disk,file=debian11x64.qcow2,index=1"
    fi
    
    qemu_command+="$additional_params"

    # Print the full command
    echo "Executing QEMU command:"
    echo "$qemu_command"

    # Execute the command
    eval "$qemu_command"
}



# Check if enable_swtpm is set to 1
if [ "$enable_swtpm" -eq 1 ]; then
    # Run the TPM emulator in the background.
    ./qemu_tpm_emulator.sh &
fi

# Determine memory and cores based on enable_vm_small setting
if [ "$enable_vm_small" -eq 1 ]; then
    run_qemu "2G" "4"
else
    run_qemu "6G" "16"
fi