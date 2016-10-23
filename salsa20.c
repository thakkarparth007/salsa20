#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "salsa20.h"

// Implements DJB's definition of '<<<'
static uint32_t rotl(uint32_t value, int shift)
{
  return (value << shift) | (value >> (32 - shift));
}

static void s20_quarterround(uint32_t *y0, uint32_t *y1, uint32_t *y2, uint32_t *y3)
{
  *y1 = *y1 ^ rotl(*y0 + *y3, 7);
  *y2 = *y2 ^ rotl(*y1 + *y0, 9);
  *y3 = *y3 ^ rotl(*y2 + *y1, 13);
  *y0 = *y0 ^ rotl(*y3 + *y2, 18);
}

static void s20_rowround(uint32_t y[static 16])
{
  s20_quarterround(&y[0], &y[1], &y[2], &y[3]);
  s20_quarterround(&y[5], &y[6], &y[7], &y[4]);
  s20_quarterround(&y[10], &y[11], &y[8], &y[9]);
  s20_quarterround(&y[15], &y[12], &y[13], &y[14]);
}

static void s20_columnround(uint32_t x[static 16])
{
  s20_quarterround(&x[0], &x[4], &x[8], &x[12]);
  s20_quarterround(&x[5], &x[9], &x[13], &x[1]);
  s20_quarterround(&x[10], &x[14], &x[2], &x[6]);
  s20_quarterround(&x[15], &x[3], &x[7], &x[11]);
}

static void s20_doubleround(uint32_t x[static 16])
{
  s20_columnround(x);
  s20_rowround(x);
}

// Creates a little-endian word from 4 bytes pointed to by b
static uint32_t s20_littleendian(uint8_t *b)
{
  return b[0] +
         ((uint_fast16_t) b[1] << 8) +
         ((uint_fast32_t) b[2] << 16) +
         ((uint_fast32_t) b[3] << 24);
}

// Moves the little-endian word into the 4 bytes pointed to by b
static void s20_rev_littleendian(uint8_t *b, uint32_t w)
{
  b[0] = w;
  b[1] = w >> 8;
  b[2] = w >> 16;
  b[3] = w >> 24;
}

// The core function of Salsa20
static void s20_hash(uint8_t seq[static 64], uint8_t out[static 64], int rounds)
{
  int i;
  int halfRounds = rounds/2;
  uint32_t x[16];
  uint32_t z[16];

  // Create two copies of the state in little-endian format
  // First copy is hashed together
  // Second copy is added to first, word-by-word
  for (i = 0; i < 16; ++i)
    x[i] = z[i] = s20_littleendian(seq + (4 * i));

  for (i = 0; i < halfRounds; ++i)
    s20_doubleround(z);

  for (i = 0; i < 16; ++i) {
    z[i] += x[i];
    s20_rev_littleendian(out + (4 * i), z[i]);
  }
}


// The core function of HSalsa20
static void hs20_hash(uint8_t seq[static 64], uint8_t out[static 32], int rounds)
{
  int i;
  int halfRounds = rounds/2;
  uint32_t z[16];

  // Create two copies of the state in little-endian format
  // First copy is hashed together
  // Second copy is added to first, word-by-word
  for (i = 0; i < 16; ++i)
    z[i] = s20_littleendian(seq + (4 * i));

  for (i = 0; i < halfRounds; ++i)
    s20_doubleround(z);

  // store the output in out
  s20_rev_littleendian(out,    z[0]);
  s20_rev_littleendian(out+4,  z[5]);
  s20_rev_littleendian(out+8,  z[10]);
  s20_rev_littleendian(out+12, z[15]);
  s20_rev_littleendian(out+16, z[6]);
  s20_rev_littleendian(out+20, z[7]);
  s20_rev_littleendian(out+24, z[8]);
  s20_rev_littleendian(out+28, z[9]);
}


// The 16-byte (128-bit) key expansion function
static void s20_expand16(uint8_t *k,
                         uint8_t n[static 16],
                         uint8_t keystream[static 64])
{
  int i, j;
  // The constants specified by the Salsa20 specification, 'tau'
  // "expand 16-byte k"
  uint8_t t[4][4] = {
    { 'e', 'x', 'p', 'a' },
    { 'n', 'd', ' ', '1' },
    { '6', '-', 'b', 'y' },
    { 't', 'e', ' ', 'k' }
  };

  // Copy all of 'tau' into the correct spots in our keystream block
  for (i = 0; i < 64; i += 20)
    for (j = 0; j < 4; ++j)
      keystream[i + j] = t[i / 20][j];

  // Copy the key and the nonce into the keystream block
  for (i = 0; i < 16; ++i) {
    keystream[4+i]  = k[i];
    keystream[44+i] = k[i];
    keystream[24+i] = n[i];
  }
}


// The 32-byte (256-bit) key expansion function
static void s20_expand32(uint8_t *k,
                         uint8_t n[static 16],
                         uint8_t keystream[static 64])
{
  int i, j;
  // The constants specified by the Salsa20 specification, 'sigma'
  // "expand 32-byte k"
  uint8_t o[4][4] = {
    { 'e', 'x', 'p', 'a' },
    { 'n', 'd', ' ', '3' },
    { '2', '-', 'b', 'y' },
    { 't', 'e', ' ', 'k' }
  };

  // Copy all of 'sigma' into the correct spots in our keystream block
  for (i = 0; i < 64; i += 20)
    for (j = 0; j < 4; ++j)
      keystream[i + j] = o[i / 20][j];

  // Copy the key and the nonce into the keystream block
  for (i = 0; i < 16; ++i) {
    keystream[4+i]  = k[i];
    keystream[44+i] = k[i+16];
    keystream[24+i] = n[i];
  }
}


// Performs up to 2^32-1 bytes of encryption or decryption under a
// 128- or 256-bit key and 64-byte nonce.
enum s20_status_t s20_crypt(uint8_t *key,
                            enum s20_keylen_t keylen,
                            uint8_t nonce[static 8],
                            uint32_t rounds,
                            uint32_t si,
                            uint8_t *buf,
                            uint32_t buflen)
{
  uint8_t keystream[64];
  // 'n' is the 8-byte nonce (unique message number) concatenated
  // with the per-block 'counter' value (4 bytes in our case, 8 bytes
  // in the standard). We leave the high 4 bytes set to zero because
  // we permit only a 32-bit integer for stream index and length.
  uint8_t n[16] = { 0 };
  uint32_t i;

  // Pick an expansion function based on key size
  void (*expand)(uint8_t *, uint8_t *, uint8_t *) = NULL;
  if (keylen == S20_KEYLEN_256)
    expand = s20_expand32;
  if (keylen == S20_KEYLEN_128)
    expand = s20_expand16;

  // If any of the parameters we received are invalid
  if (expand == NULL || key == NULL || nonce == NULL || buf == NULL)
    return S20_FAILURE;

  // Set up the low 8 bytes of n with the unique message number
  for (i = 0; i < 8; ++i)
    n[i] = nonce[i];

  // If we're not on a block boundary, compute the first keystream
  // block. This will make the primary loop (below) cleaner
  if (si % 64 != 0) {
    // Set the second-to-highest 4 bytes of n to the block number
    s20_rev_littleendian(n+8, si / 64);
    // Expand the key with n and hash to produce a keystream block
    (*expand)(key, n, keystream);
    s20_hash(keystream, keystream, rounds);
  }

  // Walk over the plaintext byte-by-byte, xoring the keystream with
  // the plaintext and producing new keystream blocks as needed
  for (i = 0; i < buflen; ++i) {
    // If we've used up our entire keystream block (or have just begun
    // and happen to be on a block boundary), produce keystream block
    if ((si + i) % 64 == 0) {
      s20_rev_littleendian(n+8, ((si + i) / 64));
      (*expand)(key, n, keystream);
      s20_hash(keystream, keystream, rounds);
    }

    // xor one byte of plaintext with one byte of keystream
    buf[i] ^= keystream[(si + i) % 64];
  }

  return S20_SUCCESS;
}


// XSalsa20 algorithm
// Performs up to 2^32-1 bytes of encryption or decryption under a
// 128- or 256-bit key and 64-byte nonce.
enum s20_status_t xs20_crypt(uint8_t *key,
                             enum s20_keylen_t keylen,
                             uint8_t nonce[static 24],
                             uint32_t rounds,
                             uint32_t si,
                             uint8_t *buf,
                             uint32_t buflen)
{
  uint8_t keystream[64];
  // 'n' is a part of the nonce
  uint8_t n[16];

  uint8_t keyFromHSalsa[32];

  uint32_t i;

  // Pick an expansion function based on key size
  void (*expand)(uint8_t *, uint8_t *, uint8_t *) = NULL;
  if (keylen == S20_KEYLEN_256)
    expand = s20_expand32;
  if (keylen == S20_KEYLEN_128)
    expand = s20_expand16;

  // If any of the parameters we received are invalid
  if (expand == NULL || key == NULL || nonce == NULL || buf == NULL)
    return S20_FAILURE;

  memcpy((void *) n, (void *) nonce, sizeof(uint8_t) * 16);

  // If we're not on a block boundary, compute the first keystream
  // block. This will make the primary loop (below) cleaner
  if (si % 64 != 0) {
    // Expand the key with n and hash to produce a keystream block
    (*expand)(key, n, keystream);

    // get key from hSalsa
    hs20_hash(keystream, keyFromHSalsa, rounds);

    // copy last 8 bytes of nonce into first 8 bytes of n
    // fill rest 4 bytes of n with si/64
    // leave highest 4 bytes 0
    memcpy((void*) n, (void*) (nonce+17), sizeof(uint8_t) * 8);
    s20_rev_littleendian(n+8, si / 64);

    // use the key from HSalsa and n to make the final keystream
    s20_expand32(keyFromHSalsa, n, keystream); // this can be optimized
                                               // [Definition of XSalsa20] (http://cr.yp.to/snuffle/xsalsa-20081128.pdf)
                                               // (x0', x5', x10', x15') remain the same
                                               // But expand32 'changes' them too
    s20_hash(keystream, keystream, rounds);
  }

  // Walk over the plaintext byte-by-byte, xoring the keystream with
  // the plaintext and producing new keystream blocks as needed
  for (i = 0; i < buflen; ++i) {
    // If we've used up our entire keystream block (or have just begun
    // and happen to be on a block boundary), produce keystream block
    if ((si + i) % 64 == 0) {
      // Expand the key with n and hash to produce a keystream block
      (*expand)(key, n, keystream);

      // get key from hSalsa
      hs20_hash(keystream, keyFromHSalsa, rounds);

      // copy last 8 bytes of nonce into first 8 bytes of n
      // fill rest 4 bytes of n with si/64
      // leave highest 4 bytes 0
      memcpy((void*) n, (void*) (nonce+17), sizeof(uint8_t) * 8);
      s20_rev_littleendian(n+8, si / 64);

      // use the key from HSalsa and n to make the final keystream
      s20_expand32(keyFromHSalsa, n, keystream);
      s20_hash(keystream, keystream, rounds);
    }

    // xor one byte of plaintext with one byte of keystream
    buf[i] ^= keystream[(si + i) % 64];
  }

  return S20_SUCCESS;
}
