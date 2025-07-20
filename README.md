# CSMWrap [![Build Status](https://github.com/FlyGoat/CSMWrap/actions/workflows/build.yml/badge.svg)](https://github.com/FlyGoat/CSMWrap/actions/workflows/build.yml) [![Discord](https://img.shields.io/discord/1390940493873025074?color=5865F2&label=Discord&logo=discord&logoColor=white)](https://discord.gg/3CCgJpzNXH)

CSMWrap is a cool UEFI application designed to enable legacy BIOS booting on modern UEFI-only systems. It achieves this by leveraging the Compatibility Support Module (CSM) and VESA VBIOS components from the [SeaBIOS project](https://www.seabios.org/), effectively creating a compatibility layer for traditional PC BIOS operation.

## Core Features

*   **Native Legacy BIOS Environment:** Provides essential BIOS services (INT 10h, INT 13h, etc.).
*   **SeaBIOS Integration:** Utilizes SeaBIOS CSM and VBIOS for compatibility.
*   **UEFI Compatibility:** Builds for IA32 and x86_64 UEFI systems.
*   **Resource Management:** Handles E820 memory mapping, ACPI/SMBIOS passthrough.

## Prerequisites

Before attempting to use CSMWrap, your system's UEFI firmware settings **MUST** be configured as follows:

1.  **Secure Boot MUST be DISABLED.**
2.  **"Above 4G Decoding" / "Resizable BAR" / "Smart Access Memory" MUST be DISABLED.**
    *   This is critical for legacy VBIOS compatibility and ensures PCI resources are mapped within the accessible 4GB address space.
3.  **Native CSM (Compatibility Support Module):**
    *   **Try disabling it first.** CSMWrap aims to be its own CSM. If issues arise, you can experiment with enabling it.

Failure to correctly configure these settings is the most common reason for CSMWrap not working.

## Quick Start

1.  **Download:** Get the latest `csmwrap<ARCH>.efi` from the [Releases page](https://github.com/FlyGoat/CSMWrap/releases).
2.  **Configure UEFI:** Ensure all **Crucial UEFI Prerequisites** above are met.
3.  **Deploy:** Copy `csmwrap<ARCH>.efi` to your EFI System Partition (ESP), typically as `EFI/BOOT/BOOTX64.EFI` (for 64-bit) or `EFI/BOOT/BOOTIA32.EFI` (for 32-bit).
4.  **Boot:** Select the UEFI boot entry for CSMWrap.

## Documentation

For detailed installation, usage, advanced scenarios, and troubleshooting, please consult our Wiki.
Please visit [this](https://github.com/FlyGoat/CSMWrap/wiki).

## Contributing

Contributions are welcome! Whether it's reporting bugs, suggesting features, improving documentation, or submitting code changes, your help is appreciated.
Please read the [Contributing](https://github.com/FlyGoat/CSMWrap/wiki/Contributing) guide for more details.

Additionally, one can join our [Discord server](https://discord.gg/3CCgJpzNXH) for any project-related discussion, or to otherwise chat with likeminded
people.

## Credits & Acknowledgements

*   The **[SeaBIOS project](https://www.seabios.org/)** for their CSM and VBIOS code.
*   **[Nyu-EFI](https://codeberg.org/osdev/nyu-efi)** for the EFI C runtime, build system, and headers.
*   **[EDK2 (TianoCore)](https://github.com/tianocore/edk2)** for UEFI specifications and some code snippets.
*   **[uACPI](https://github.com/uACPI/uACPI)** for ACPI table handling.
*   **@CanonKong** for test feedback and general knowledge.
*   All contributors and testers from the community!
