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

* Step 1. Find the BDF, PIO base of the PCI-serial card first with "lspci -vvv". For example, the HP840 Aero G8 laptop has
the following info
```
00:16.3 Serial controller: Intel Corporation Device a0e3 (rev 20) (prog-if 02 [16550])
	Subsystem: Hewlett-Packard Company Device 880d
	Control: I/O+ Mem+ BusMaster- SpecCycle- MemWINV- VGASnoop- ParErr- Stepping- SERR- FastB2B- DisINTx-
	Status: Cap+ 66MHz+ UDF- FastB2B+ ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Interrupt: pin D routed to IRQ 19
	IOMMU group: 12
	Region 0: I/O ports at 3060 [size=8]
	Region 1: Memory at 6e301000 (32-bit, non-prefetchable) [size=4K]
	Capabilities: [40] MSI: Enable- Count=1/1 Maskable- 64bit+
		Address: 0000000000000000  Data: 0000
	Capabilities: [50] Power Management version 3
		Flags: PMEClk- DSI+ D1- D2- AuxCurrent=0mA PME(D0-,D1-,D2-,D3hot-,D3cold-)
		Status: D0 NoSoftRst+ PME-Enable- DSel=0 DScale=0 PME-
	Kernel driver in use: serial
```

Thus, the BDF is 00:16:03, PIO base is 0x3060.

* Step 2. Modify the generated startup.nsh to be used on the testbed (e.g., on the flashdrive), add ```mm 00160304 1 -pci``` in startup.nsh line 2 before "FS1:",
such as:
```
# Run XMHF
mm 00160304 1 -pci
FS1:
load \EFI\BOOT\init-x86-amd64.efi
```

00160304 is because the BDF is 00:16:03. 04 is the fixed offset. This command enables the PIO base of the PCI serial 
card, see https://forum.osdev.org/viewtopic.php?f=1&t=56649

* Step 3. Modify the <baseaddr> in <cb_serial> with the PIO base

* Notes:
(1) One should be careful with multi-ports PCI-serial card, because the code initialize the first logical port only.

### Use Intel ME and Serial-over-LAN (SOL)

On the debuggee machine:
* Step 1. Install Windows 10
* Step 2. Install tools/ACUWizardInstaller-12.1.0.87.msi on Windows 10
* Step 3. Run "Intel SCS ACUWizard" with admin priviledge. If using WIFI, then "Edit Configuration" --> "Network 
Configuration" --> Tick the "Enable synchronization of Intel AMT with host platform WIFI profiles" and empty "Allow WIFI 
connection with the following WIFI setups" list.

On the debugger machine:
* Install OpenSUSE 2024 or above (or use a VM which can use the host IP network).
* Install amtterm-1.7 or above in OpenSUSE.
* Run "amtterm -p <debuggee's AMT password> <debuggee's AMT IP address>"; e.g., "amtterm -p 82B6qr@Rtx 192.168.68.76"