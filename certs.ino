// See: <https://tls.mbed.org/source-code>

#include <mbedtls/x509_crt.h>
#include <mbedtls/error.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <mbedtls/asn1write.h>

#include "utility/MPU9250.h"

// SHA-1 fingerprint of the factory's root certificate.
const uint8_t factory_root_fingerprint[20] =  {
    0xA1, 0x02, 0x01, 0xE3, 0x02, 0x0E, 0xC9, 0x6B, 0x30, 0x90, 0x62,
    0x69, 0xCD, 0xE3, 0x6F, 0x82, 0x80, 0x35, 0xA9, 0x8B };

// lifted from mbedtls/library/ecdsa.c
/*  
 * Convert a signature (given by context) to ASN.1
 */
static int ecdsa_signature_to_asn1( const mbedtls_mpi *r, const mbedtls_mpi *s,
                                    unsigned char *sig, size_t *slen )
{   
    int ret;
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char *p = buf + sizeof( buf );
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &p, buf, s ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &p, buf, r ) );
    
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &p, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &p, buf,
                                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );
    
    memmove( sig, p, len );
    *slen = len;
    
    return( 0 );
}


    
// verify_unit_cert()
//
    int
verify_unit_cert(const char *chain_crt, const char *unit_crt, const char *usb_serial, const uint8_t ae_serial[6], mbedtls_pk_context *cert_pubkey)
{
    // take a certificate chain back to the factory's root key, a per-unit certicate
    // and what we think the subject should be (serial numbers from product) and verify
    // it all
    int rv = 0;
    uint32_t flags_out = 0;

    mbedtls_x509_crt    batch;
    static mbedtls_x509_crt    unit;
    mbedtls_x509_crt_init(&batch);
    mbedtls_x509_crt_init(&unit);

    mbedtls_x509_crl    empty_crl;
    mbedtls_x509_crl_init(&empty_crl);

    rv = mbedtls_x509_crt_parse(&batch, (const uint8_t *)chain_crt, strlen(chain_crt)+1);
    if(rv) goto fail;

    rv = mbedtls_x509_crt_parse(&unit, (const uint8_t *)unit_crt, strlen(unit_crt)+1);
    if(rv) goto fail;

    // check fingerprint of root cert. SHA-1 for historical reasons/openssl CLI compat.
    uint8_t digest[20];
    mbedtls_sha1_ret(batch.raw.p, batch.raw.len, digest);
    if(memcmp(digest, factory_root_fingerprint, sizeof(factory_root_fingerprint)) != 0) {
        Serial.println("fact cert wrong");
        rv = 1;
        goto fail;
    }

/*
    Serial.printf("fing: len=%d %02x %02x %02x\n", factory->raw.len, digest[0], digest[1], digest[2]);

    {   uint8_t tmp[2000];
        size_t actual = 0;
        mbedtls_base64_encode(tmp, sizeof(tmp), &actual, factory->raw.p, factory->raw.len);
        tmp[actual] = 0;
        Serial.println((char *)tmp);
    }
*/
    
    rv = mbedtls_x509_crt_verify(&unit, &batch, &empty_crl, "Opendime", 
                     &flags_out, NULL, NULL);
    if(rv) goto fail;

    char expected_subj[80];
    sprintf(expected_subj, "serialNumber=%s+%02x%02x%02x%02x%02x%02x, CN=Opendime", 
                usb_serial, 
                ae_serial[0], ae_serial[1], ae_serial[2],
                ae_serial[3], ae_serial[4], ae_serial[5]);

    // only now we can trust things!
    // - verify subject
    char subj[80];
    mbedtls_x509_dn_gets(subj, sizeof(subj), &unit.subject);
    Serial.printf("found: %s\n", subj);
    if(strcmp(subj, expected_subj) != 0) {
        Serial.printf("Unit cert is for some other unit!: '%s' != '%s'", subj, expected_subj);
        rv = 3;
        goto fail;
    }
    
    // - extract pubkey
    // unit.pk => mbedtls_pk_context
    //*cert_pubkey = unit.pk;

    {   uint8_t    buf[500];
        // mbedtls_pk_context *ctx, unsigned char *buf, size_t size
        int bl = mbedtls_pk_write_pubkey_der(&unit.pk, buf, sizeof(buf));
        uint8_t *result = buf+500-bl;

        uint8_t tmp[2000];
        size_t actual = 0;
        mbedtls_base64_encode(tmp, sizeof(tmp), &actual, result, bl);
        tmp[actual] = 0;
        Serial.printf("pubkey der = \n%s", (char *)tmp);

        //int mbedtls_pk_parse_public_key( mbedtls_pk_context *ctx,
                         //const unsigned char *key, size_t keylen );

        rv = mbedtls_pk_parse_public_key(cert_pubkey, result, bl);
        if(rv) goto fail;
    }



fail:
    mbedtls_x509_crl_free(&empty_crl);
    mbedtls_x509_crt_free(&batch);
    //XXX//mbedtls_x509_crt_free(&unit);

    if(rv < 0) {
        char msg[128];
        mbedtls_strerror(rv, msg, sizeof(msg)); 

        Serial.printf("Mbedtls error: 0x%04x = %s\n", rv, msg);
    } else if(rv == 0) {
        Serial.printf("Mbedtls approves the cert\n");
    }

    return rv;
}

// get_random_bytes()
//
    void
get_random_bytes(uint8_t *dest, int len)
{
    // BIG PROBLEM: No hardware RNG on the ESP32!!!
    // - use the MAC address
    // - environment data from accelerometer
    // - a counter
    // - I hate this sort of fakery, but no choice.

    static mbedtls_sha256_context   ctx;
    static int count = 0;

    static MPU9250 IMU;

    if(!count) {
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts_ret(&ctx, 0);
        count++;

        IMU.calibrateMPU9250(IMU.gyroBias, IMU.accelBias);
        IMU.initMPU9250();
        IMU.initAK8963(IMU.magCalibration);
    }

    while(len > 0) {
        uint64_t chipid = ESP.getEfuseMac();
        mbedtls_sha256_update_ret(&ctx, (uint8_t *)&chipid, sizeof(chipid));

        int16_t    axis[3];

        IMU.readAccelData(axis);
        mbedtls_sha256_update_ret(&ctx, (uint8_t *)&axis, sizeof(axis));
        IMU.readGyroData(axis);
        mbedtls_sha256_update_ret(&ctx, (uint8_t *)&axis, sizeof(axis));
        IMU.readMagData(axis);
        mbedtls_sha256_update_ret(&ctx, (uint8_t *)&axis, sizeof(axis));

        uint16_t tmp = IMU.readTempData();
        mbedtls_sha256_update_ret(&ctx, (uint8_t *)&tmp, sizeof(tmp));

        count++;
        mbedtls_sha256_update_ret(&ctx, (uint8_t *)&count, sizeof(count));

        mbedtls_sha256_context   ro;
        mbedtls_sha256_clone(&ro, &ctx);

        uint8_t digest[32];
        mbedtls_sha256_finish_ret(&ro, digest);

        // double-SHA256 because Bitcoin
        mbedtls_sha256_init(&ro);
        mbedtls_sha256_starts_ret(&ctx, 0);
        mbedtls_sha256_update_ret(&ro, digest, 32);
        mbedtls_sha256_finish_ret(&ro, digest);

        memcpy(dest, digest, (len > 32) ? 32 : len);
        len -= 32;
    }
}

// print_hex()
//
    void
print_hex(const char *label, const uint8_t *src, int len=32, int xval=-1)
{
    Serial.printf("%s: ", label);

    for(int i=0; i<len; i++) {
        Serial.printf("%02x", src[i]);
    }

    if(xval >= 0) {
        Serial.printf("  => %d", xval);
    }

    Serial.println();
}

// print_base64()
//
    void
print_base64(const char *label, const uint8_t *src, int len)
{
    uint8_t tmp[2000];
    size_t actual = 0;

    mbedtls_base64_encode(tmp, sizeof(tmp), &actual, src, len);

    tmp[actual] = 0;
    Serial.printf("%s (%d bytes) = '%s'\n", label, len, (char *)tmp);
}

// verify_ae_signature()
//
    int
verify_ae_signature(const uint8_t ae_serial[6], const char *usb_serial, 
                    const uint8_t my_nonce[20], const char *address,
                    const uint8_t ae_sig[64], const uint8_t ae_nonce[32],
                    mbedtls_pk_context *cert_pubkey)
{
/* python
def verify_ae_signature(pubkey, expect, numin, ae_rand, sig):
    H = lambda x: sha256(x).digest()
                
    if 'ad' in expect:
        slot13 = A2B(expect['ad'].ljust(72))[0:32]
        lock = b'\0'
    else:       
        slot13 = b'\xff' * 32
        lock = b'\1'
                
    slot14 = A2B(expect['sn'] + "+" + expect['ae'])[0:32]
            
    fixed = b'\x00\xEE\x01\x23' + b'\0' *25
    msg1 = slot14 + b'\x15\x02\x0e' + fixed + H(ae_rand + numin + b'\x16\0\0')
    msg2 = slot13 + b'\x15\x02\x0d' + fixed + H(msg1)
    SN = a2b_hex(expect['ae'])
    
    body = H(msg2) + b'\x41\x40\x00\x00\x00\x00\x3c\x00\x2d\0\0\xEE' \
                + SN[2:6] + b'\x01\x23'+ SN[0:2] + lock + b'\0\0'
                
    from ecdsa.keys import BadSignatureError
    try:        
        ok = pubkey.verify(sig, body, hashfunc=sha256)
    except BadSignatureError:
        ok = False
*/
    print_hex("ae_serial", ae_serial, 6);
    print_hex("my_nonce", my_nonce, 20);
    print_hex("ae_sig", ae_sig, 64);
    print_hex("ae_nonce", ae_nonce, 32);
    Serial.printf("usb_serial: %s\n", usb_serial);
    Serial.printf("address: %s\n", address);

    uint8_t slot13[32];
    uint8_t lock;

    if(address[0]) {
        memcpy(slot13, address, 32);
        lock = 0;
    } else {
        memset(slot13, 0xff, 32);
        lock = 1;
    }

    uint8_t slot14[64];     // only going to use first 32 bytes
    sprintf((char *)slot14, "%s+%02x%02x%02x%02x%02x%02x", 
                usb_serial, 
                ae_serial[0], ae_serial[1], ae_serial[2],
                ae_serial[3], ae_serial[4], ae_serial[5]);

    uint8_t fixed[29] = { 0x00, 0xEE, 0x01, 0x23 };  // and 25 zeros

    // ... = H(ae_rand + numin + b'\x16\0\0')
    mbedtls_sha256_context   ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, ae_nonce, 32);
    mbedtls_sha256_update_ret(&ctx, my_nonce, 20);
    const uint8_t f16[3] = { 0x16, 0, 0 };
    mbedtls_sha256_update_ret(&ctx, f16, 3);

    uint8_t m1tail[32];
    mbedtls_sha256_finish_ret(&ctx, m1tail);
    print_hex("m1tail", m1tail, 32, ctx.total[0]);

    // msg1 = slot14 + b'\x15\x02\x0e' + fixed + H(ae_rand + numin + b'\x16\0\0')
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, slot14, 32);
    const uint8_t f15e[3] = { 0x15, 0x02, 0x0e };
    mbedtls_sha256_update_ret(&ctx, f15e, 3);
    mbedtls_sha256_update_ret(&ctx, fixed, 29);
    mbedtls_sha256_update_ret(&ctx, m1tail, 32);

    uint8_t msg1[32];
    mbedtls_sha256_finish_ret(&ctx, msg1);
    print_hex("msg1", msg1, 32, ctx.total[0]);
    
    // msg2 = slot13 + b'\x15\x02\x0d' + fixed + H(msg1)
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, slot13, 32);
    const uint8_t f15d[3] = { 0x15, 0x02, 0x0d };
    mbedtls_sha256_update_ret(&ctx, f15d, 3);
    mbedtls_sha256_update_ret(&ctx, fixed, 29);
    mbedtls_sha256_update_ret(&ctx, msg1, 32);

    uint8_t msg2[32];
    mbedtls_sha256_finish_ret(&ctx, msg2);
    print_hex("msg2", msg2, 32, ctx.total[0]);

    //body = H(msg2) + b'\x41\x40\x00\x00\x00\x00\x3c\x00\x2d\0\0\xEE' \
    //            + SN[2:6] + b'\x01\x23'+ SN[0:2] + lock + b'\0\0'
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, msg2, 32);
    const uint8_t lots[12] = { 0x41, 0x40, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x2d, 0,0, 0xEE };
    mbedtls_sha256_update_ret(&ctx, lots, 12);
    mbedtls_sha256_update_ret(&ctx, ae_serial+2, 4);
    const uint8_t f0123[2] = { 0x01, 0x23 };
    mbedtls_sha256_update_ret(&ctx, f0123, 2);
    mbedtls_sha256_update_ret(&ctx, ae_serial+0, 2);
    mbedtls_sha256_update_ret(&ctx, &lock, 1);
    const uint8_t z2[2] = { 0, 0 };
    mbedtls_sha256_update_ret(&ctx, z2, 2);

    uint8_t digest[32];
    mbedtls_sha256_finish_ret(&ctx, digest);
    print_hex("digest", digest, 32, ctx.total[0]);

    // mbedtls wants full ASN.1 formated signature (DER)
    // we have two 32-byte numbers: R, S
    // static int ecdsa_signature_to_asn1( const mbedtls_mpi *r, const mbedtls_mpi *s,
    //                              unsigned char *sig, size_t *slen )
    // int mbedtls_mpi_read_binary( mbedtls_mpi *X, const unsigned char *buf, size_t buflen );
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_read_binary(&r, ae_sig, 32);
    mbedtls_mpi_read_binary(&s, ae_sig+32, 32);
    uint8_t asn_sig[100];
    size_t  a_len = sizeof(asn_sig);

    int rv = ecdsa_signature_to_asn1(&r, &s, asn_sig, &a_len);

    if(rv) goto fail;

    print_base64("sig", asn_sig, a_len);

    rv = mbedtls_pk_verify(cert_pubkey, MBEDTLS_MD_SHA256, digest, 32, asn_sig, a_len);

    if(rv < 0) {
fail:
        char msg[128];
        mbedtls_strerror(rv, msg, sizeof(msg)); 

        Serial.printf("Mbedtls PK: 0x%04x = %s\n", rv, msg);
    } else if(rv == 0) {
        Serial.printf("Mbedtls approves the AE signature\n");
    }

    return rv;
}

// EOF
