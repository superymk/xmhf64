# lxy handoff notes

Written: May 10, 2023

## Build arguments for new XMHF features

I typically use `tools/ci/build.sh` to build XMHF. For example
```sh
./tools/ci/build.sh i386		# Build for 32-bit BIOS
./tools/ci/build.sh amd64		# Build for 64-bit BIOS
./tools/ci/build.sh uefi		# Built for 64-bit UEFI
./tools/ci/build.sh i386 -n		# Display configuration arguments for i386
./tools/ci/build.sh i386 --drt	# Build for 32-bit BIOS with DRT
```

For documentation, see comments in the beginning of `tools/ci/build.sh`.

### Configuration for nested virtualization

* `--enable-nested-virtualization`: enable nested virtualization support
* `--with-vmx-nested-max-active-ept=8`: for each CPU, track 8 EPT02s for the L1
  general purpose hypervisor.
	* When this value is too small, running L2 guests will be slow. Will see
	  `ept02_miss` event in event logger. See `nested-x86vmx-ept12.c`.
* `--with-vmx-nested-ept02-page-pool-size=512`: for each EPT02 tracked for the
  L1 general purpose hypervisor in each CPU, keep 512 pages of entries.
	* When this value is too small, running L2 guests will be slow. Will see
	  `ept02_full` event in event logger. See `nested-x86vmx-ept12.c`.
* `--enable-vmx-nested-msr-bitmap`: allow L1 general purpose hypervisor to use
  MSR bitmap (likely increases efficiency)
* `--with-hypapp-l2-vmcall-min=0x4c415000U`: see below
* `--with-hypapp-l2-vmcall-max=0x4c4150ffU`: for VMCALL and CPUID made by L2
  nested guest with EAX between 0x4c415000U and 0x4c4150ffU, call hypapp
  callback function. Otherwise, forward the VMCALL / CPUID intercept to L1
  general purpose hypervisor.

### Configuration for UEFI

* `--enable-target-uefi`: compile for UEFI, instead of BIOS

### Other configuration options

* `--enable-debug-event-logger`: enable event logger, this will print event
  statistics on serial port in YAML format. Good for performance debugging.

## UEFI installation

Recommended configurations:
```sh
./tools/ci/build.sh uefi fast
./tools/ci/build.sh uefi fast --drt
./tools/ci/build.sh uefi fast --dmap
./tools/ci/build.sh uefi fast --drt --dmap
```

Using `fast` in `build.sh` enables `--enable-skip-runtime-bss`. Without this,
`hypervisor-x86-amd64.bin` will be very large.

After compilation, two files will be generated:
* `init-x86-amd64.efi`: XMHF bootloader as an EFI file
* `hypervisor-x86-amd64.bin`: XMHF secureloader and runtime, without gz
  compression.

To install XMHF, prepare the EFI partition as follows:

```
.
`-- EFI
    `-- BOOT
        |-- 6th_7th_gen_i5_i7-SINIT_79.bin
        |-- BOOTX64.EFI
        |-- hypervisor-x86-amd64.bin
        |-- init-x86-amd64.efi
        |-- init-x86-amd64.efi.conf
        `-- startup.nsh
```

`6th_7th_gen_i5_i7-SINIT_79.bin` is the SINIT AC module downloaded from Intel's
website. This file is only needed when DRT is on.

`BOOTX64.EFI` is the EFI binary started by firmware. On different OSes this
may be different (e.g. `/EFI/debian/grubx64.efi`,
`/EFI/Microsoft/Boot/bootmgfw.efi`). Replace the original file with the UEFI
shell binary (e.g. `/usr/share/edk2/ovmf/Shell.efi` on Fedora).

`hypervisor-x86-amd64.bin` is copied from XMHF build.

`init-x86-amd64.efi` is copied from XMHF build.

`init-x86-amd64.efi.conf` is configuration file for XMHF. Its file name must
be the XMHF EFI partition plus ".conf". It must be ASCII text with exactly 3
lines, using `\n` as line separator.
* The first line is command line for XMHF (similar to the one in GRUB)
* The second line is path of `hypervisor-x86-amd64.bin` from the EFI partition
* The third line is path of the SINIT AC module from the EFI partition. The
  content of this line is ignored when DRT is off. But even when DRT is off,
  `init-x86-amd64.efi.conf` must still contain 3 lines.

Example for `init-x86-amd64.efi.conf`:
```
argv0 serial=115200,8n1,0x3f8 boot_drive=0x80
\EFI\BOOT\hypervisor-x86-amd64.bin
\EFI\BOOT\6th_7th_gen_i5_i7-SINIT_79.bin
```

`startup.nsh` is a script executed by EFI shell. It contains the following
logic:
1. Using the `load` command, load `init-x86-amd64.efi`
2. Boot the OS

Example of booting XMHF then Windows:
```
# Switch to FS0
FS0:
# Load XMHF
load \EFI\BOOT\init-x86-amd64.efi
# Sleep 1
stall 1000000
# Load Windows
\EFI\Microsoft\Boot\bootmgfw.efi
```

Example of booting XMHF then Fedora:
```
# Switch to FS0
FS0:
# Load XMHF
load \EFI\BOOT\init-x86-amd64.efi
# Sleep 1
stall 1000000
# Load Linux
\EFI\fedora\grubx64.efi_old
```

Example, if `/boot/efi/XMHF_TRY` exists, remove it and boot XMHF and Windows.
If it does not exist, boot Linux:
```
# Switch to FS0
FS0:
# Test whether should try XMHF
if exists \XMHF_TRY then
        rm \XMHF_TRY
        # Load XMHF
        load \EFI\BOOT\init-x86-amd64.efi
        # Sleep 1
        stall 1000000

        # Load Windows
        \EFI\Microsoft\Boot\bootmgfw.efi
endif
# Load Linux
\EFI\fedora\grubx64.efi_old
```

## PAL demo

PAL demo is a example program that runs TrustVisor.
It is build automatically in GitHub Actions:
<https://github.com/lxylxy123456/uberxmhf/actions>, search for "Build PAL demo".

To build it locally, run `./tools/ci/build_pal_demo.sh all`. All files are
located in `./hypapps/trustvisor/pal_demo/`.
* `pal_demo.tar.xz`: archive of all executables
* `pal_demo.zip`: archive of all executables
* There are 3 prefixes:
	* `test...`: call `TV_HC_TEST`
	* `main...`: register and run a PAL once
	* `test_args...`: register and run PALs many times
* There are many suffixes
	* `...32`: Linux i386 executable
	* `...64`: Linux amd64 executable
	* `...32L2`: Linux i386 executable, for L2 guests
	* `...64L2`: Linux amd64 executable, for L2 guests
	* `...32.exe`: Windows i386 executable
	* `...64.exe`: Windows amd64 executable
	* `...32L2.exe`: Windows i386 executable, for L2 guests
	* `...64L2.exe`: Windows amd64 executable, for L2 guests

I mostly only use this command to test TrustVisor. This command runs 3 PALs.
For each PAL it runs 7 times:
```
./test_args64 7 7 7
```

## QEMU/KVM debugging

QEMU/KVM can simulate many CPU features used by XMHF, including VMX and IOMMU.
It is very helpful in debugging XMHF

Pros and Cons
* Pro: can simulate VMX and IOMMU (XMHF's DMAP). For IOMMU, use QEMU argument 
  `-machine q35 -device intel-iommu`.
* Con: cannot simulate Intel TXT (XMHF's DRT).
* Pro: KVM can be debugged with GDB.
* Con: Debugging multiple processors is relatively difficult. Try to start with
  a single processor.
* Con: some corner cases are not simulated correctly by KVM. If you see things
  like "KVM internal error." or "qemu-system-x86\_64: Assertion ... failed.",
  you probably need to give up.

QEMU/KVM images I generated during the research are uploaded to:
<https://drive.google.com/drive/folders/1rXDTAGcT9zeWmGbOrLvnexD9xJpoNrsl?usp=sharing>

### Sample commands

#### amd64 BIOS

```sh
# Build XMHF
./tools/ci/build.sh amd64 fast

# Generate MBR disk image to boot XMHF in "grub/c.img"
python3 ./tools/ci/grub.py \
		--subarch "amd64" \
		--xmhf-bin "." \
		--work-dir "." \
		--boot-dir "./tools/ci/boot/"

# Run QEMU (download debian11x64.qcow2 from Google Drive, put it to /PATH/TO/)
# Explanation of arguments:
#  e1000 and netdev: port 2222 of host is forwarded to port 22 of guest (SSH)
#  gdb: use GDB to connect to port 1234 of host for debugging
#  smp: the guest has 4 cores
#  cpu: must have vmx=yes, because XMHF requires VMX features
#  enable-kvm: must have this to enable VMX
#  serial: output serial port (3f8) output to command line, can also be a file
#  drive (first line): boot XMHF
#  drive (second line): after XMHF, boot Debian
qemu-system-x86_64 \
	-m 2G \
	-device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::2222-:22 \
	-gdb tcp::1234 \
	-smp 4 \
	-cpu Haswell,vmx=yes \
	-enable-kvm \
	-serial stdio \
	-drive media=disk,file=grub/c.img,index=0 \
	-drive media=disk,file=/PATH/TO/debian11x64.qcow2,index=1
```

To boot Windows, you need a specially compiled BIOS image that disables SMM.
See <https://github.com/lxylxy123456/uberxmhf/blob/notes/bug_031/>. You also
need `grub_windows.img` as the second disk (first one is `grub/c.img`, third is
`win10x64.qcow2`. See
<https://github.com/lxylxy123456/uberxmhf/tree/notes/bug_077>.

#### amd64 UEFI

```
# Build XMHF
# Using --iss (--with-extra-ap-init-count) because for some reason booting
#  rich OS requires INIT-SIPI-SIPI twice
./tools/ci/build.sh uefi fast --iss 1

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
for %i in \EFI\debian\grubx64.efi \EFI\BOOT\BOOTX64.EFI
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
	for i in init-x86-amd64.efi hypervisor-x86-amd64.bin grub/startup.nsh \
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
	-enable-kvm \
	-bios /usr/share/OVMF/OVMF_CODE.fd \
	-net none \
	-serial stdio \
	-drive media=cdrom,file=/usr/share/OVMF/UefiShell.iso,index=0 \
	-drive media=cdrom,file=grub/fat.img,index=1 \
	-drive media=disk,file=/PATH/TO/debian11efi.qcow2,index=2
```

#### GDB debugging

Use GDB command `target remote :::1234` to connect to QEMU.

Make sure to build with `--enable-debug-symbols`. To load symbol files in GDB:
```
# Load symbols of XMHF bootloader, when XMHF is booted by BIOS
symbol-file xmhf/src/xmhf-core/xmhf-bootloader/init_syms.exe

# Load symbols of XMHF bootloader, when XMHF is booted by UEFI
# (Change 0x7F9FE000 to the address printed on UEFI console)
symbol-file xmhf/src/xmhf-core/xmhf-bootloader/init-x86-amd64.so -o 0x7F9FE000

# Load symbols of XMHF secureloader, when virtual addr 0 != physical addr 0
# This is true when most of the secureloader's C code is running
symbol-file -o 0 xmhf/src/xmhf-core/xmhf-secureloader/sl_syms.exe

# Load symbols of XMHF secureloader, when virtual addr 0 == physical addr 0
symbol-file -o 0x10000000 xmhf/src/xmhf-core/xmhf-secureloader/sl_syms.exe

# Load symbols of XMHF runtime
symbol-file xmhf/src/xmhf-core/xmhf-runtime/runtime.exe

# Debugging the Linux kernel is possible
symbol-file /PATH/TO/usr/lib/debug/boot/vmlinux-5.10.0-10-686
symbol-file /PATH/TO/usr/lib/debug/boot/vmlinux-5.10.0-9-amd64
```

More GDB scripts are in
<https://github.com/lxylxy123456/uberxmhf/tree/notes/gdb>.

## Future work

Compatibility
* Windows 11 (UEFI) with DRT (maybe also DMAP) may not be stable. Sometimes see
  bluescreen of `CRITICAL_SERVICE_FAILED` during boot (Dell 7050).
* Support VMCS shadowing for L1 general-purpose hypervisors (looks like
  VirtualBox requires it for nested virtualization, where L0=XMHF,
  L1=VirtualBox, L2=VirtualBox-guest, L3=VirtualBox-nested-guest).

Logistics
* Merge to XMHF64 (a.k.a. XMHF+) to uberXMHF repo.

Performance
* There may be some unnecessary VMCS checks and updates in nested
  virtualization. Can remove them to increase efficiency.
* Consider shadow paging for EPT02 (but likely will break atomicity of XMHF)
* Use large pages for EPT (save memory and CPU)

Other / low priority
* Support other features of TrustVisor (e.g. nonvolatile storage, uTPM)
* Make XMHF able to run in VMware and VirtualBox
* Make sure Xen can run in XMHF
* The NMI virtualization in nested virtualization is not fully transparent.
  See <https://github.com/lxylxy123456/uberxmhf/tree/notes/bug_087>, see branch
  `lhv-nmi`. There are two experiments (experiment 18 and experiment 26) that
  do not pass.
* This configuration does not run a long time ago: KVM (SMP), XMHF, KVM. Maybe
  consider supporting it.
  Related: <https://github.com/lxylxy123456/uberxmhf/tree/notes/bug_090>.

