# Sniffer with CC3100 and WireShark

Restored example from [CC3100 Programming User Guide](http://www.ti.com/lit/ug/swru368b/swru368b.pdf) for
the CC3100 BoosterPack and Advanced Emulation Kit.

## Build and run

1. Install `MinGW` and add it ot the `PATH`
2. Install CC3100SDK 1.2.0 (`C:\TI\CC3100SDK_1.2.0`)
3. Copy:
    - all from `${SDK}\cc3100-sdk\simplelink` to `simple-link\simple_link`
    - files from `${SDK}\cc3100-sdk\platform\simplelinkstudio` to `simple-link\simple_link_studio`
4. `mingw32-make -f Makefile` - build project
5. `Debug\cc3100-wireshark-sniffer.exe` - run
