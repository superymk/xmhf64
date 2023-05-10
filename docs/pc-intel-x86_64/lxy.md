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

