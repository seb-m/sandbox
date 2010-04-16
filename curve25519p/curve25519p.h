#ifndef SM_
#define SM_

#define CRYPTO_BYTES 32
#define CRYPTO_SCALARBYTES 32

int crypto_scalarmult_base(unsigned char *q,
                           const unsigned char *n);

int crypto_scalarmult_base_ref(unsigned char *q,
                               const unsigned char *n);

int crypto_scalarmult(unsigned char *q,
                      const unsigned char *n,
                      const unsigned char *p);

int crypto_scalarmult_ref(unsigned char *q,
                          const unsigned char *n,
                          const unsigned char *p);

#endif // SM_
