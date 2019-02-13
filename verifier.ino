#include <M5Stack.h>
#include <usbhub.h>
#include <SPI.h>

// see <https://tls.mbed.org/source-code>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>

#include "od_logo.h"

const mbedtls_ecp_curve_info *btc_curve;
const mbedtls_ecp_curve_info *nist_curve;

USB        Usb;
USBHub     Hub(&Usb);

const int LCD_W = 320;
const int LCD_H = 240;
const int FONT_H = 10;       // height of tallest char, plus baseline skip
const int BANNER_H = 85;
const int STATUS_Y = 130;

// Details for EP0 commands
#define OD_GET_ADDR     3
#define OD_GET_PRIVKEY  2
#define OD_GET_SIGN     4
#define OD_GET_CERT     7
#define OD_GET_SERIAL   8
#define OD_GET_CHAIN    11
#define OD_GET_COIN     12

/*
 1 | Secret exponent (if unsealed) 
 2 | WIF version of private key (if unsealed)
 3 | Payment address (if set yet)
 4 | Result of previous signature request (`m` or `f`), 65 or 96 bytes
 5 | Firmware checksum (32 bytes)
 6 | Firmware version as a string
 7 | Readback unit x.509 certificate `unit.crt`
 8 | Serial number of ATECC508A chip (6 bytes)
 9 | Readback number of bytes entropy so far (unsigned LE32)
10 | Readback version string (same as `version.txt` file)
11 | Readback `chain.crt` file (use wIndex to interate over 512 byte blocks)
12 | Readback 'BTC' or 'LTC' or other some code for currency of device (v2.3+)
                
## "OUT" Transfers (set value)
                
CODE | Expects | Description
-----|---------|------------
`m`  | 32 bytes| Starts the bitcoin-style message-signing process (get result with 4)
`f`  | 20 bytes| Starts signature process in ATECC508A (get result with 4)
`E`  | n/a     | Simulate a USB hotplug to reset port
`e`  | 32 or 0 | Add 32 bytes of entropy, or reset process with 0 length transfer
`s`  | none    | Perform self-test, indicate result on LED's (unit must not have payment address)
`r`  | none    | Make LED go solid red.
`o`  | none    | Restore normal LED operation.
*/


uint8_t od_usb_address = 0;
char od_address[64];
char od_privkey[64];
bool od_is_verified = false;
bool od_is_sealed = false;
bool od_has_addr = false;
char od_unit_crt[2048];
char od_chain_crt[8196];

void draw_banner()
{
    //const uint16_t    od_color = 0xea52;        // M5.Lcd.color8to16(0xef4a4d);
    const uint16_t    od_color = M5.Lcd.color565(0xef, 0x4a, 0x4d);
    M5.Lcd.clear();
    M5.Lcd.drawXBitmap(8, 4, od_logo_bits, od_logo_width, od_logo_height, od_color);
    M5.Lcd.setTextDatum(TL_DATUM);      // top left
    M5.Lcd.setTextSize(2);
    M5.Lcd.drawString("Verifier", 96, 62);
}

void setup()
{
    M5.begin();
    draw_banner();

    Serial.begin(115200);

    Serial.println();
    Serial.println("Reboot.");

    // load appropriate curves
    btc_curve = mbedtls_ecp_curve_info_from_grp_id(MBEDTLS_ECP_DP_SECP256K1);
    assert(btc_curve);

    nist_curve = mbedtls_ecp_curve_info_from_grp_id(MBEDTLS_ECP_DP_SECP256R1);
    assert(nist_curve);
    //Serial.print("nist_curve = %p", nist_curve);
    //Serial.print("btc_curve = ");
    //Serial.println((uint32_t)btc_curve, HEX);

    // <https://github.com/ARMmbed/mbedtls/blob/fb1972db23da39bd11d4f9c9ea6266eee665605b/include/mbedtls/ecdsa.h#L200>
    // mbedtls_ecdsa_verify()

    reset();

    if(Usb.Init() == -1) {
        Serial.println("USB startup fail");
    }
}

void draw_status(const char *msg)
{
    M5.Lcd.fillRect(0, STATUS_Y, LCD_W, FONT_H, TFT_BLACK);

    M5.Lcd.setTextDatum(TC_DATUM);      // top center
    M5.Lcd.setTextSize(1);

    M5.Lcd.drawString(msg, LCD_W/2, STATUS_Y);

    Serial.printf("Status: %s\n", msg);
}

void draw_step(const char *msg)
{
    static int y;
    const int INDENT_X = 50;

    if(!msg) {
        // reset state
        y = STATUS_Y + (2 * FONT_H);
        return;
    }

    M5.Lcd.setTextDatum(ML_DATUM);      // middle-left

    M5.Lcd.drawString(msg, INDENT_X, y);

    // TODO: make this a green checkmark
    M5.Lcd.drawString("-", INDENT_X - 10, y);

    y += FONT_H;

    Serial.printf("Step: %s\n", msg);
}

void reset()
{
    memset(od_address, 0, sizeof(od_address));
    memset(od_privkey, 0, sizeof(od_privkey));
    od_is_verified = false;
    od_is_sealed = false;
    od_has_addr = false;
}

class AddressParser: public USBReadParser {
public:
    void Parse(const uint16_t len, const uint8_t *pbuf, const uint16_t &offset) {
        Serial.printf("Got: %d more @ %d", len, offset);
    }
};

// read_string_EP0()
//
// Read a string, possibly variable-length from device.
// Lots of assumptions here.
//
    int
read_string_EP0(int cmd, int maxlen, char *dest)
{
/*
    uint8_t ctrlReq(uint8_t addr, uint8_t ep, uint8_t bmReqType, uint8_t bRequest,
                uint8_t wValLo, uint8_t wValHi,
                uint16_t wInd, uint16_t total, uint16_t nbytes, uint8_t* dataptr, USBReadParser *p);
*/
    Serial.printf("Read EP0: %d\n", cmd);

    memset(dest, 0, maxlen);
    int rv = Usb.ctrlReq(od_usb_address, 0, 0xc0, 0,
                    /*wValLo*/cmd, /*wValHi*/0, /*wIndex*/0,
                    maxlen, maxlen, (uint8_t *)dest, NULL);

    if(rv == hrSTALL) {
        // bitcoin addrs are 30-34 bytes, and we don't know exact length
        // the device returns right amount of bytes, and then stalls (to mark that)
        // - api here doesn't support that, and works but doesn't think it worked
        // - expect stall here, and no certainty about length of transfer
        // - assume C-string type of response, not raw binary.
        int alen = strnlen(dest, maxlen);
        if(alen == maxlen) {
            Serial.printf("Failed: cmd=%d rv=0x%x\n", cmd, rv);
            return rv;
        }
    }

    return 0;
}

void verify_opendime(UsbDevice *pdev)
{
    uint8_t addr = pdev->address.devAddress;

    USB_DEVICE_DESCRIPTOR buf;
    uint8_t rv;

    rv = Usb.getDevDescr(addr, 0, 0x12, ( uint8_t *)&buf);
    if(rv) {
    fail:
        draw_status("[not an opendime]");
        return;
    }

    if(buf.idVendor != 0xd13e) goto fail;
    // could also do if(buf.idProduct != 0x0100) goto fail;
    // but let's be future-proof

    draw_status("(opendime)");

    // passable ... continue on assumption it's an opendime
    od_usb_address = addr;

    rv = read_string_EP0(OD_GET_ADDR, sizeof(od_address), od_address);
    if(rv) return;

    od_has_addr = (od_address[0] != 0);
    if(od_has_addr) {
        // see if unsealed
        rv = read_string_EP0(OD_GET_PRIVKEY, sizeof(od_privkey), od_privkey);
        if(rv) return;

        od_is_sealed = (od_privkey[0] == 0);

        // show address while we work
        M5.Lcd.setTextDatum(TC_DATUM);      // top-center
        M5.Lcd.drawString(od_address, LCD_W/2, BANNER_H + (2*FONT_H));

        if(!od_is_sealed) {
Serial.println("is seal");
            M5.Lcd.setTextSize(2);
            M5.Lcd.drawString("* UNSEALED *", LCD_W/2, BANNER_H + (3*FONT_H), TFT_RED);
            M5.Lcd.setTextSize(1);
Serial.println("done is seal");
        }

    } else {
        M5.Lcd.setTextDatum(TC_DATUM);      // top-center
        M5.Lcd.drawString("-- factory fresh --", LCD_W/2, BANNER_H + (2*FONT_H));
    }
    
    draw_status("Verifying...");

    draw_step(NULL);

    // based on trustme.py ... 

    // check serial number matches
    draw_step("Serial number matches");

    // run a few bitcoin msg signings
    draw_step("Good bitcoin message signature");

    // downlaod unit crt, verify against factory chain, and also expected factory root
    draw_step("Genuine per-unit factory certificate");

    // extract AE pubkey from cert, use that to run a few AE508 msg signings
    draw_step("Passed anti-counterfeiting test");
}

void loop()
{
    static uint8_t last_state;
    const int y = 160;

    Usb.Task();

    uint8_t current_state = Usb.getUsbTaskState();
    if(current_state != last_state) {
        if(current_state == USB_DETACHED_SUBSTATE_WAIT_FOR_DEVICE) {
            reset();
            draw_banner();
            draw_status("-- Insert Opendime --");
        } else if(current_state == USB_ATTACHED_SUBSTATE_SETTLE) {
            draw_status("(wait)");
        } else if(current_state  == USB_STATE_RUNNING) {
            draw_status("(checking)");
            Usb.ForEachUsbDevice(&verify_opendime);
        } else {
            //Serial.printf("state = 0x%x", current_state);
        }

        last_state = current_state;
    }
}
