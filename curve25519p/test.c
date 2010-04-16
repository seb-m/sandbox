#include <stdio.h>
#include "randombytes.h"
#include "curve25519p.h"

static void printb(const unsigned char p[32]) {
  int i;

  for (i = 0; i < 32; ++i) {
    printf("%3d ", p[i]);
  }
  printf("\n");
}

static int cmp_k(const unsigned char k1[32], const unsigned char k2[32]) {
  int i;

  for (i = 0; i < 32; ++i)
      if (k1[i] != k2[i]) {
        printb(k1);
        printb(k2);
        return -1;
      }

  return 0;
}

int main() {
  unsigned char q1[32];
  unsigned char q2[32];
  unsigned char q3[32];
  unsigned char n[32];
  const int loop = 100;
  int count;

  for (count = 0; count < loop; ++count) {
    randombytes(n, 32);
    crypto_scalarmult_base(q1, n);
    crypto_scalarmult_base_ref(q2, n);
    if (cmp_k(q1, q2) != 0)
      return -1;

    randombytes(n, 32);
    crypto_scalarmult(q2, n, q1);
    crypto_scalarmult_ref(q3, n, q1);
    if (cmp_k(q2, q3) != 0)
      return -1;
  }

  printf("Success!\n");
  return 0;
}
