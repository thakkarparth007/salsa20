#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "salsa20.h"

int main(int argc, char *argv[])
{
  char usage[] = "Salsa20/HSalsa20/XSalsa20 demo program\n"
                 "\n"
                 "Will encrypt or decrypt from standard input (the operation\n"
                 "is reversible for salsa20) until EOF, using a 128-bit key.\n"
                 "WARNING: Do not use this program for serious security. No\n"
                 "         appropriate key expansion function is used for\n"
                 "         converting a password to a cryptographic key.\n"
                 "         Use this program as a demo ONLY.\n"
                 "\n"
                 "Usage:\n"
                 "salsa20 <salsa/hsalsa/xsalsa> <16-character key> <nonce> <rounds>\n";

  if (!(argc == 5 && strlen(argv[2]) == 16)) {
    puts(usage);
    return 1;
  }

  enum s20_status_t (*crypt_function)(
    uint8_t *,
    enum s20_keylen_t,
    uint8_t [static 8],
    uint32_t,
    uint32_t,
    uint8_t*,
    uint32_t
  ) = NULL;

  if (!strcmp(argv[1], "salsa")) {
    if (strlen(argv[3]) != 8) {
      puts("nonce must be 8 character long (64 bits) for Salsa20");
      return 1;
    }

    crypt_function = s20_crypt;
  }
  // conditions for other functions
  else {
    puts("Unsupported algorithm");
    return 1;
  }


  int in;
  int rounds = atoi(argv[4]);
  // Stream index
  uint32_t si = 0;
  while ((in = getchar()) != EOF) {
    uint8_t c = in;
    // Encrypt a single character at a time
    //                              key     128-bit key                 nonce           encrypt one byte
    if (crypt_function((uint8_t *) argv[2], S20_KEYLEN_128, (uint8_t *) argv[3], rounds, si++, &c, 1) == S20_FAILURE)
      puts("Error: encryption failed");
    putchar(c);
  }

  return 0;
}
