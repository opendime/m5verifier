#include <mbedtls/pk.h>

// NOTE: this captures the pubkey held in the unit's certificate
int verify_unit_cert(const char *chain_crt, const char *unit_crt,
                        const char *usb_serial, const uint8_t ae_serial[6]);

void get_random_bytes(uint8_t *dest, int len);

int verify_ae_signature(const uint8_t ae_serial[6], const char *usb_serial, 
                    const uint8_t my_nonce[20], const char *address,
                    const uint8_t ae_sig[64], const uint8_t ae_nonce[32]);

int verify_bitcoin_signature(const uint8_t my_nonce[32], const char *od_address,
                                const uint8_t signature[65], const char *coin_type);

// EOF
