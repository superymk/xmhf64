# QEMU/KVM debugging

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
