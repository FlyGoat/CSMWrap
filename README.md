# CSMWrap [![Build Status](https://github.com/FlyGoat/CSMWrap/actions/workflows/build.yml/badge.svg)](https://github.com/FlyGoat/CSMWrap/actions/workflows/build.yml) [![Discord](https://img.shields.io/discord/1390940493873025074?color=5865F2&label=Discord&logo=discord&logoColor=white)](https://discord.gg/3CCgJpzNXH)

CSMWrap is an EFI application designed to be a drop-in solution to enable legacy BIOS booting on modern UEFI-only (class 3) systems.
It achieves this by wrapping a Compatibility Support Module (CSM) build of the [SeaBIOS project](https://www.seabios.org/)
as an out-of-firmware EFI application, effectively creating a compatibility layer for traditional PC BIOS operation.

## Executive Summary

The idea is to drop the 64-bit or 32-bit version of CSMWrap (depending on the hardware, dropping both also works) in a `/EFI/BOOT/`
directory on a FAT (16 or 32) partition on the medium containing the legacy BIOS OS. UEFI firmware will pick this up and show the
medium as a bootable device. Ideally, that's all that would be needed.

1. **Download:** Get the latest `csmwrap<ARCH>.efi` from the [Releases page](https://github.com/FlyGoat/CSMWrap/releases).
2. **Deploy:** Copy `csmwrap<ARCH>.efi` to the FAT-formatted partition, typically as `EFI/BOOT/BOOTX64.EFI` (for 64-bit) or `EFI/BOOT/BOOTIA32.EFI` (for 32-bit).
3. **Boot:** Select the UEFI boot entry for CSMWrap.

## Additional Prerequisites

### Secure Boot

Secure boot should be disabled unless one wants to manually sign the CSMWrap EFI application, which is possible.

### Firmware Settings

CSMWrap is designed to be as drop-in as possible, without requiring changes to firmware for settings that may not even be exposed
(depending on the firmware), or that might conflict with other UEFI OSes being multi-booted on the system. That said, if at all
possible, changing these settings may make things smoother and it is recommended to do so:

1. **Above 4G Decoding**
2. **Resizable BAR/Smart Access Memory**
3. **X2APIC**

### Video Card Considerations

CSMWrap also wraps the "SeaVGABIOS" module of SeaBIOS for providing a bare bones implementation of a legacy Video BIOS. That said,
SeaVGABIOS is far from ideal, and many, **many** things requiring more direct access to legacy video modes won't work properly
(e.g. pretty much all MS-DOS games, MS-DOS Editor, etc.). More modern OSes using the VESA BIOS extensions (VBE) standard only
(e.g. more modern Windows NT, Linux, etc.) should still work fine, though.

Therefore it is **highly recommended**, if possible, to install a legacy-capable video card. If one is present, its Video BIOS
will be used instead of SeaVGABIOS, providing a much better, pretty much native-like, experience.

## Frequently Asked Questions

### Is this an emulator?

No! At least not in the sense of it being a full-screened emulator window. Running a legacy OS with CSMWrap means that it is *natively*
running on the system. CSMWrap attempts to recreate, natively, and as closely as possible, a legacy BIOS PC environment on modern
UEFI class 3 systems.

### I booted a multi-core capable OS and I am missing a core, what gives?

This is expected. CSMWrap reserves 1 core for "system" use due to the limitations of running out-of-firmware and not being able to
use [SMM (System Management Mode)](https://en.wikipedia.org/wiki/System_Management_Mode).

## Documentation

For detailed installation, usage, advanced scenarios, and troubleshooting, please consult [our Wiki](https://github.com/FlyGoat/CSMWrap/wiki).

## Contributing

Contributions are welcome! Whether it's reporting bugs, suggesting features, improving documentation, or submitting code changes, your help is appreciated.
Please read the [Contributing](https://github.com/FlyGoat/CSMWrap/wiki/Contributing) guide for more details.

Additionally, one can join our [Discord server](https://discord.gg/3CCgJpzNXH) for any project-related discussion, or to otherwise chat with likeminded
people.

## Credits & Acknowledgements

*   The **[SeaBIOS project](https://www.seabios.org/)** for their CSM and VBIOS code.
*   **[PicoEFI](https://codeberg.org/PicoEFI/PicoEFI)** for the EFI C runtime, build system, and headers.
*   **[EDK2 (TianoCore)](https://github.com/tianocore/edk2)** for UEFI specifications and some code snippets.
*   **[uACPI](https://github.com/uACPI/uACPI)** for ACPI table handling.
*   **@CanonKong** for test feedback and general knowledge.
*   All contributors and testers from the community!
