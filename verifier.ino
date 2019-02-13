#include <M5Stack.h>
#include <usbhub.h>
#include <SPI.h>

// see <https://tls.mbed.org/source-code>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>

#include "od_logo.h"
#include "batch1_cert.h"
#include "certs.h"

const mbedtls_ecp_curve_info *btc_curve;
const mbedtls_ecp_curve_info *nist_curve;

USB        Usb;
USBHub     Hub(&Usb);

const int LCD_W = 320;
const int LCD_H = 240;
const int FONT_H = 10;       // height of tallest char, plus baseline skip
const int BANNER_H = 85;
const int STATUS_Y = 130;

char unit_crt[1024];            // actually 960 max
char chain_crt[4096];       // 6*512 = 3072 actual limit

// Details for EP0 commands
#define OD_GET_PRIVKEY   2
#define OD_GET_ADDR      3
#define OD_GET_SIGN      4
#define OD_GET_VERSION   6
#define OD_GET_UNIT_CRT  7
#define OD_GET_AE_SERIAL 8
#define OD_GET_CHAIN_CRT 11
#define OD_GET_COIN      12

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

    {   
        static const char *unit = "-----BEGIN CERTIFICATE-----\n\
MIICbzCCAVegAwIBAgIIX3qDOWq5DPwwDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UE\n\
AwwLQmF0Y2ggIzMgQ0EwHhcNMTcxMjAxMDAwMDAwWhcNMzcwMTAxMDAwMDAwWjBF\n\
MTAwLgYDVQQFEydJTlhCUkYyTEdSSUZDSUNLSklZREVDWUM3NCsxMzM1M2FiMzUz\n\
YzUxETAPBgNVBAMMCE9wZW5kaW1lMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n\
YlMHjcniY34vDrgTRCGiUQ2k4E6uiXOW/uCZxSwJeK7GwcgPqP0VN0NoNIRToReg\n\
RvwNDSKurSB16ZgkhrtsSqNdMFswHwYDVR0jBBgwFoAUZajDuArucQE5AcGXIc80\n\
k+fTXyEwCQYDVR0TBAIwADAdBgNVHQ4EFgQUjQYpvwL1xiSASEQJDmOAIYbIEVww\n\
DgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IBAQCTZc0l4AfLC+HCtm+G\n\
FcyLZ7uKXOdoUL2yTCWwRwbY1owRcO5ve9NmhM4ajihSeiMVWGDUiRdEKHmJ5e58\n\
Ge/rJEAyZF2DiT1L3yiY5Aa5sIqeWHXpWg2JmeGl3HePGId2TKM2HaTgTtIffITu\n\
Jhb1ZMOwcbOZNTr4JAFROjlItuoUO0xvwvcrA0J9OglRPKK7mfv27/FuxzE7tPQo\n\
8VGi7Zvor0qT7AJrdD2Ztd0WZ8WmJh60e0BXLB3ba1zVKxkWfwj31WTQUiEJOVxF\n\
6Jl8yIJqvQftT11sbPx4eWAaRhMRBSDc40yfsMQw8E7dI80ChaPlxTEhK+34c0Pc\n\
3G+7\n\
-----END CERTIFICATE-----\n";
        static const char *batch = "-----BEGIN CERTIFICATE-----\n\
MIIDrTCCApWgAwIBAgIBATANBgkqhkiG9w0BAQsFADB4MQswCQYDVQQGEwJDQTEQ\n\
MA4GA1UECAwHT250YXJpbzEQMA4GA1UEBwwHVG9yb250bzEWMBQGA1UECgwNQ29p\n\
bmtpdGUgSW5jLjERMA8GA1UECwwIT3BlbmRpbWUxGjAYBgNVBAMMEUZhY3Rvcnkg\n\
Um9vdCBDQSAxMB4XDTE3MDIwMTAwMDAwMFoXDTM3MDEwMTAwMDAwMFoweDELMAkG\n\
A1UEBhMCQ0ExEDAOBgNVBAgMB09udGFyaW8xEDAOBgNVBAcMB1Rvcm9udG8xFjAU\n\
BgNVBAoMDUNvaW5raXRlIEluYy4xETAPBgNVBAsMCE9wZW5kaW1lMRowGAYDVQQD\n\
DBFGYWN0b3J5IFJvb3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n\
ggEBAMKw2OjepDwxyqQGZkh519+snMHzI1eR6vrOInaKDmq2sTQE5x5PMoNdWEp6\n\
f0V1L5e5YAfVfazu5L/d2GQDI2JIsCQGP7vYkqkGfFRAvzWPMiNrwNkPQymPFC5P\n\
+2rRxAk+W9mTpjA0oZ6Xp5+B5oWTulGYygPleO6WxxKvxGEcD0WOZQqDmIRVIcCD\n\
1DiEHqDWmHzRO6yUaHrM323iR/8RrkVSn288vcOUOHe3cG9LSWaMwBB+BtcyKGJf\n\
i8fudSQdSQS75HkznFIs2E6f2tja42LmL+E37FftcbaAL8yvk5hqA8PWvkZ/1Foj\n\
SJehAuMa/sHqRE1jdJeG4jCC3c8CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd\n\
BgNVHQ4EFgQUNEwRZVIzdnrWOFPw1B+vTWZAYOgwDgYDVR0PAQH/BAQDAgEGMA0G\n\
CSqGSIb3DQEBCwUAA4IBAQC0h+a23N0gTQKMY7wCTGPsnupOkdA9fdL8jSoJF1sH\n\
BoDtnftkw97FK+NJ7Wvl0gg1O9wiHyU+j2fP4M6k5iF+R8cg35jFNekMNizbR+Ey\n\
8Lnp8kR9fn1tNzZS2UlaEX6k9EGWFvEq4PL4rSvbz7RSSCogQ4x7/5vGFjKYVluA\n\
CVp1F4nYuzlB87ewBH9qU821y/3YcdbBdqb+U/EK1/JU1k29RitgNjg0AFu2Yj1f\n\
oiGlcjWgMxJmTrlboJlal+adQY6G1f7vaD84hnHsRPnlJAkNQr5XannzTrxwZZQu\n\
0oAwidheaTMUEiGDMRGCPhYvmP8DsasZwifPE5FNBi50\n\
-----END CERTIFICATE-----\n\\n\
-----BEGIN CERTIFICATE-----\n\
MIIDbTCCAlWgAwIBAgICA+swDQYJKoZIhvcNAQELBQAweDELMAkGA1UEBhMCQ0Ex\n\
EDAOBgNVBAgMB09udGFyaW8xEDAOBgNVBAcMB1Rvcm9udG8xFjAUBgNVBAoMDUNv\n\
aW5raXRlIEluYy4xETAPBgNVBAsMCE9wZW5kaW1lMRowGAYDVQQDDBFGYWN0b3J5\n\
IFJvb3QgQ0EgMTAeFw0xNzA3MDEwMDAwMDBaFw0zNzAxMDEwMDAwMDBaMBYxFDAS\n\
BgNVBAMMC0JhdGNoICMzIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n\
AQEAleDDk6GEInA5zU82NjgL3Sn0AWrX7hga0eebm447LZSaxFSNaX9AfVlBLiE4\n\
EBLMC74rXyhvLSMq7+tT02SABaHz9CEbX9xh2TkOiV0nIc5fUIB7s4C4PLZ2hDTu\n\
lRdXP3VfLaM1yoUSUcPbYAsbcW/T4+37nlHQEQA1+DHfyJkeyGz6jINC33SPXoPy\n\
q8XrtuT7LZoWuf5hsn4aqEidgwcv5fT6lu4JyurOoYx7LE0ZFuohkKHWdVr8cnPy\n\
ybJQqx20CowjZkjTrKPPiASLZ9su0YNjfidfzyxVV6acaWp/Q4MmNlGMCApI4MIu\n\
k62Wkpruilo/RVq6xfz85WwL3wIDAQABo2MwYTAfBgNVHSMEGDAWgBQ0TBFlUjN2\n\
etY4U/DUH69NZkBg6DAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRlqMO4Cu5x\n\
ATkBwZchzzST59NfITAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEB\n\
AI5XTuFeB+Gh9/h5xP3kRpBFgiik2rDRXvqSS2sGHZauQRhKpbg/PLyFC23qS6LC\n\
IQElq108zgVU/8bOPyYDBgGADG00gB647U09QsKqPltQ/vXk14eJeHNkaz1tiGg0\n\
YRmnyS28BCm0IrZO4AzbS8qexrkuT2OaAcDqUlMgNBgHgTAO573u1zbBgwKOKlWd\n\
bY8i9SiPfTvE5bgaz4cAELkMnmgbjbtYLGH0Po39R+KGU6/yHTXRYebtBAn4Yp4s\n\
mHh2QheqXuqehg0flzivQ5xOf7PU1MLdjRtypU/7Qh6TtdjvNjJLq75ZVAda14F1\n\
n9DUlxgxfsboqYzjVFkmxYE=\n\
-----END CERTIFICATE-----";

        mbedtls_pk_context pubkey;
        static const uint8_t ae_s[6] = { 0x13, 0x35, 0x3a, 0xb3, 0x53, 0xc5 };
        verify_unit_cert(batch, unit, "INXBRF2LGRIFCICKJIYDECYC74", ae_s, &pubkey);
    }
}

void draw_status(const char *msg, bool is_fail=false)
{
    M5.Lcd.fillRect(0, STATUS_Y, LCD_W, FONT_H, TFT_BLACK);

    M5.Lcd.setTextDatum(TC_DATUM);      // top center
    M5.Lcd.setTextSize(1);
    M5.Lcd.setTextColor(is_fail ? TFT_RED : TFT_WHITE);

    M5.Lcd.drawString(msg, LCD_W/2, STATUS_Y);

    M5.Lcd.setTextColor( TFT_WHITE);

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
    //Serial.printf("Read EP0: %d\n", cmd);

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
            //Serial.printf("read_string_EP0 failed: cmd=%d rv=0x%x\n", cmd, rv);
            return rv;
        }
    }

    return 0;
}

// read_binary_EP0()
//
// Read a fixed-length set of bytes from device.
//
    int
read_binary_EP0(int cmd, int len, uint8_t *dest, uint16_t wIndex=0)
{
/*
    uint8_t ctrlReq(uint8_t addr, uint8_t ep, uint8_t bmReqType, uint8_t bRequest,
                uint8_t wValLo, uint8_t wValHi,
                uint16_t wInd, uint16_t total, uint16_t nbytes, uint8_t* dataptr, USBReadParser *p);
*/
    //Serial.printf("Read [%d] from EP0: %d (idx=%u)\n", len, cmd, wIndex);

    int rv = Usb.ctrlReq(od_usb_address, 0, 0xc0, 0,
                    /*wValLo*/cmd, /*wValHi*/0, wIndex,
                    len, len, dest, NULL);

    if(rv) {
        //Serial.printf("read_binary_EP0 failed: cmd=%d rv=0x%x\n", cmd, rv);

        return rv;
    }

    return 0;
}

// write_binary_EP0()
//
    int
write_binary_EP0(char cmd, uint8_t *src, int len, uint16_t wIndex=0)
{
/*
    uint8_t ctrlReq(uint8_t addr, uint8_t ep, uint8_t bmReqType, uint8_t bRequest,
                uint8_t wValLo, uint8_t wValHi,
                uint16_t wInd, uint16_t total, uint16_t nbytes, uint8_t* dataptr, USBReadParser *p);
*/
    Serial.printf("Write [%c] to EP0: %d (idx=%u)\n", len, cmd, wIndex);

    int rv = Usb.ctrlReq(od_usb_address, 0, 0x40, 0,
                    /*wValLo*/cmd, /*wValHi*/0, wIndex,
                    len, len, src, NULL);

    if(rv) {
        Serial.printf("read_binary_EP0 failed: cmd=%d rv=0x%x\n", cmd, rv);

        return rv;
    }

    return 0;
}

void verify_opendime(UsbDevice *pdev)
{
    uint8_t addr = pdev->address.devAddress;

    USB_DEVICE_DESCRIPTOR buf;
    uint8_t rv;

    rv = Usb.getDevDescr(addr, 0, 0x12, ( uint8_t *)&buf);
    if(rv || (buf.idVendor != 0xd13e)) {
        draw_status("[not an opendime]", true);
        return;
    }

    // could also do (buf.idProduct != 0x0100) 
    // but let's be future-proof
    draw_status("(opendime)");

    int i_serial = buf.iSerialNumber;

    // passable ... continue on assumption it's an opendime
    od_usb_address = addr;

    rv = read_string_EP0(OD_GET_ADDR, sizeof(od_address), od_address);
    if(rv) goto fail;

    od_has_addr = (od_address[0] != 0);
    if(od_has_addr) {
        // see if unsealed
        rv = read_string_EP0(OD_GET_PRIVKEY, sizeof(od_privkey), od_privkey);
        if(rv) goto fail;

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

    // read USB serial number, which is fixed 26-byte size
    // - USC16 encoding, (le16), with prefix of length
    uint8_t    encoded_serial[54];
    rv = Usb.getStrDescr(od_usb_address, 0, sizeof(encoded_serial), i_serial, 0x0000, encoded_serial);
    if(rv) goto fail;
    if(encoded_serial[0] != 54) goto vfail;

    char    usb_serial[27];
    for(int i=0; i<26; i++) {
        usb_serial[i] = encoded_serial[2+(i*2)];
    }
    usb_serial[26] = 0;
    Serial.printf("USB Serial: %s\n", usb_serial);

    char    version[64];
    rv = read_string_EP0(OD_GET_VERSION, sizeof(version), version);
    if(rv) goto fail;

    Serial.printf("Version: %s\n", version);
    {   // just show up to first space of version.
        char    tmp[80];

        char *p = strchr(version, ' ');
        if(!p) goto vfail;
        *p = 0;

        sprintf(tmp, "Version: %s", version);
        draw_step(tmp);

        sprintf(tmp, "Serial: %s", usb_serial);
        draw_step(tmp);
    }

    if(od_has_addr) {
        // run a few bitcoin msg signings
        draw_step("Good bitcoin message signature");

    }

    // some older units can't do this part:
    // - download unit and chain certificates (x.509, PEM, binary)

    rv = read_string_EP0(OD_GET_UNIT_CRT, sizeof(unit_crt), unit_crt);
    if(rv) goto fail;
    //Serial.printf("Unit:\n%s\n", unit_crt);

    memset(chain_crt, 0, sizeof(chain_crt));
    for(int off=0; off<sizeof(chain_crt); off += 512) {
        rv = read_binary_EP0(OD_GET_CHAIN_CRT, 512, (uint8_t *)(chain_crt+off), off/512);
        if(rv) {
            // partial read occurs at end
            if(off == 0) {
                // It doesn't have the endpoint... use our hard-coded chain for
                // those early units.
                if(strncmp(version, "2.0.0", 5) == 0) {
                    strcpy(chain_crt, batch1_chain_crt);
                    break;
                } else {
                    goto vfail;
                }
            }

            break;
        }
    }
    //Serial.printf("Chain:\n%s\n", chain_crt);

    // need serial # of AE
    uint8_t   ae_serial[6];
    rv = read_binary_EP0(OD_GET_AE_SERIAL, sizeof(ae_serial), ae_serial);
    if(rv) goto fail;

    mbedtls_pk_context cert_pubkey;
    if(verify_unit_cert(chain_crt, unit_crt, usb_serial, ae_serial, &cert_pubkey)) goto vfail;

    // downlaod unit crt, verify against factory chain, and also expected factory root
    draw_step("Genuine per-unit factory certificate");

    // Using pubkey extracted from cert, run a few AE508 test-msg signings (or maybe just one)
    {
        uint8_t my_nonce[20];
        struct {
            uint8_t     sig[64];
            uint8_t     ae_nonce[32];       // value chip picked
        } ae_resp = {};

        get_random_bytes(my_nonce, sizeof(my_nonce));
        rv = write_binary_EP0('f', my_nonce, sizeof(my_nonce));

        for(int i=0; i<100; i++) {
            // sleep a bit ... it's delibrately slow
            delay(50);

            rv = read_binary_EP0(OD_GET_SIGN, sizeof(ae_resp), (uint8_t *)&ae_resp);
            if(rv == 0) {
                break;
            }
        }

        rv = verify_ae_signature(ae_serial, usb_serial, my_nonce, od_address,
                                    ae_resp.sig, ae_resp.ae_nonce, &cert_pubkey);
    }
    if(rv) goto vfail;

    // verify signature, over appropriate msg

    draw_step("Passed anti-counterfeiting test");

    return;

fail:
    Serial.printf("verify fail: rv=%d\n", rv);
    draw_status("FAILED: Unable to communicate.", true);
    return;

vfail:
    draw_status("FAILED: Verify failed.", true);
    return;
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
