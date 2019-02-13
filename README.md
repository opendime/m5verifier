
- packages/esp32/hardware/esp32/1.0.1/tools/sdk/include/mbedtls/mbedtls/ecdh.h

- <https://tls.mbed.org/source-code>
- curves: <https://github.com/ARMmbed/mbedtls/blob/master/include/mbedtls/ecp.h>

# Making logo

- make a nice two-colour black and white to start, then:

```
% pngtopam bw.png | pamthreshold | pamtopnm | pbmtoxbm -name od_logo > od_logo.h
```
