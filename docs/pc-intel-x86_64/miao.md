# Notes on lxy.md 

## QEMU/KVM debugging

### Sample commands

#### amd64 UEFI

1. Compile hypapp with "--with-extra-ap-init-count=1". This is equivilant to "./tools/ci/build.sh uefi fast --iss 1". For example:
```
./configure --with-approot=hypapps/trustvisor --enable-drt=no --with-target-subarch=amd64 --enable-quiesce-in-guest-mem-pio-traps=no --enable-allow-hypapp-disable-igfx-iommu=yes --enable-target-uefi --enable-skip-runtime-bss --with-extra-ap-init-count=1
```

2. Run ```sudo make install```

3. Download the <debian11efi.qcow2> to uberxmhf/debug from the link
# <https://drive.google.com/drive/folders/1rXDTAGcT9zeWmGbOrLvnexD9xJpoNrsl?usp=sharing>

4. Overwrite uberxmhf/debug/qemu_uefi_ubuntu.sh with uberxmhf/debug/qemu_uefi_fedora.sh if you will run qemu on Fedora (not Ubuntu)

5. Run ```make debug```



### QEMU enables PCI-serial card (16550 UART) for debugging
```
qemu-system-x86_64 \
	-m 2G \
	-gdb tcp::1234 \
	-smp 4 \
	-cpu Haswell,vmx=yes \
	-machine q35 -device intel-iommu \
	-enable-kvm \
	-bios /usr/share/ovmf/OVMF.fd \
	-net none \
    -chardev stdio,id=char0 \
	-device pci-serial,chardev=char0 \
	-chardev socket,id=chrtpm,path=/tmp/emulated_tpm/swtpm-sock \
	-tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
	-drive media=cdrom,file=../uefi_flushdrive_img/grub/fat.img,index=0 \
	-drive media=cdrom,file=../uefi_flushdrive_img/grub/fat.img,index=1 \
	-drive media=disk,file=debian11efi.qcow2,index=2
```

## Debugging on baremetal
### Use PCI-serial card (16550 UART)
I bought a PCI-serial card from https://www.amazon.com/StarTech-com-Profile-Native-Express-PEX1S553LP/dp/B0041ULUX6

One needs to:
(1) Find the PIO base of the PCI-serial card first with "lspci -vvv"
(2) Modify the <baseaddr> in <cb_serial> with that PIO base

Note: One should be careful with multi-ports PCI-serial card, because the code initialize the first logical port only.