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
