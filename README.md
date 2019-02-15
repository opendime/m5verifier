# Get Yours!

Visit [Opendime.com](https://opendime.com) to get more Opendimes!

Aliexpress has the M5Stack systems... many options and packages.
At a minimum, you'll need the "Basic" plus a "USB", but other
combinations are possible.

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

# How it Works.

Every Opendime comes with an x.509 ceriticate that is signed by the factory.
The public key which that certificate atests-to, is stored inside an
ATECC508A chip (in fact, it has never left that chip, and was generated
inside it). The x.509 certiciate chain is verified all the way to the factory
root certificate, and then the public key from the certificate is verified
against a (nonce) message signed by the Opendime. The process does take a few
moments.

Code can be found in `certs.ino`, and is equivilent to
the python code shipped on every Opendime, in the file `trustme.py`.

# TODO

- initialize factory-fresh Opendimes with good entropy so they will pick a key
- cycle through a few good third-party websites for balance checking QR
    - middle click for next site
    - remember your favourite
- improve bitcoin signed-message verification process
- display current balance on screen with help of Internet connection

# Important

Only use your own verifier to check an Opendime! The M5Stack
platform is open to any changes, and it would not be hard to
modify the code here to display something fraudulent.

You can only trust your own verifier and ideally build it
yourself from this source code.

## Comment on Balance Display

It would be great to show the current balance on screen. It's not too
hard, but requires Wifi access and a backend service of some kind.
That could be an Electrum server, or a Bitcoin web service.  Wifi access
requires a setup process so the M5Stack can get a wifi password to
use, and the interaction with a back-end service may reveal your
location and/or identity plus it may tie you into future and pass
applications of the specific Opendime.

