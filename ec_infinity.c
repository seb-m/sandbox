// 10/05/2010 - Sebastien Martini (seb@dbzteam.org)
//
// This code shows various issues in the EC code of OpenSSL with the handling of
// the point at infinity:
//
// - EC_GROUP_check() should not accept to validate a group whose the generator
//   is the point at infinity.
// - EC_KEY_generate_key() should not accept to return a key pair with the point
//   at infinity as public key.
// - EC_KEY_check_key() should not validate a public key representing a point at
//   infinity.
//
// Running this code:
//   $ gcc -Wall -o ec_infinity ec_infinity.c -lcrypto
//   $ ./ec_infinity ecparams.pem
//   # ecparams.pem are NID_X9_62_prime256v1 parameters plus the neutral point
//   # as generator.
//   $ openssl ecparam -in ecparams.pem -inform PEM -check -noout
//   # Interestingly this last command fails without -noout because of the
//   # printing code.
//
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

int main(int argc, char *argv[]) {
  /* Construct a group with a point at infinity as generator */

  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  if (group == NULL)
    return 1;

  EC_POINT *generator = EC_POINT_new(group);
  if (generator == NULL)
    return 2;

  if (!EC_POINT_set_to_infinity(group, generator))
    return 3;

  BIGNUM *order = BN_new();
  BIGNUM *one = BN_new();
  if (order == NULL || one == NULL)
    return 4;

  if (!BN_one(one) || !EC_GROUP_get_order(group, order, NULL))
    return 5;

  if (!EC_GROUP_set_generator(group, generator, order, one))
    return 6;

  if (EC_GROUP_check(group, NULL) == 1)
    printf("EC_GROUP_check(): ok\n");
  else
    printf("EC_GROUP_check(): ko\n");


  /* Generate a new key pair from these group parameters */

  EC_KEY *eckey = EC_KEY_new();
  if (eckey == NULL)
    return 7;

  if (!EC_KEY_set_group(eckey, group))
    return 8;

  if (!EC_KEY_generate_key(eckey))
    return 9;

  const EC_POINT *pubkey = EC_KEY_get0_public_key(eckey);
  if (pubkey == NULL)
    return 10;

  if (EC_POINT_is_at_infinity(group, pubkey) == 1)
    printf("Public key: point at infinity\n");
  else
    printf("Public key: not point at infinity\n");

  if (EC_KEY_check_key(eckey) == 1)
    printf("EC_KEY_check_key(): ok\n");
  else
    printf("EC_KEY_check_key(): ko\n");


  /* Output curve parameters */

  if (argc == 2) {
    BIO *out = BIO_new(BIO_s_file());
    if (out == NULL)
      return 11;

    BIO_write_filename(out, argv[1]);
    PEM_write_bio_ECPKParameters(out, group);
    BIO_free(out);
    printf("Dumped ec parameters to %s\n", argv[1]);
  }


  /* final clean-up */

  if (group != NULL)
    EC_GROUP_free(group);
  if (generator != NULL)
    EC_POINT_free(generator);
  if (order != NULL)
    BN_free(order);
  if (one != NULL)
    BN_free(one);
  if (eckey != NULL)
    EC_KEY_free(eckey);

  return 0;
}
