# Install

- install serial port drivers for CP2104 chip from Silicon Labs
    - <https://www.silabs.com/products/development-tools/software/usb-to-uart-bridge-vcp-drivers>
    - must enable "system extension" immediately after install
    - expect to find `/dev/tty.SLAB_USBtoUART` when M5Stack is connected

- [download and install Ardinuo](https://docs.m5stack.com/#/en/quick_start/m5core/m5stack_core_quick_start)

- for MacOS, follow [this guide](https://docs.m5stack.com/#/en/quick_start/m5core/m5stack_core_get_started_Arduino_MacOS)

- install an additional libraries: Tools > Manage Libraries...
    - "USB Host Shield Library 2.0" .. search for "usb max"

- open "verifier.ino" and press Run

- you need the USB unit in your stack, of course.

## Making logo

Make a nice two-colour black and white to start (in `bw.png`), then:

```
% pngtopam bw.png | pamthreshold | pamtopnm | pbmtoxbm -name od_logo > od_logo.h
```
