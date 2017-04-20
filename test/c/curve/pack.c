
#include <stdio.h>

#include "uint64_pack.h"

crypto_uint64 parse_args(int argc, char** argv) {
  crypto_uint64 result = 0;

  if(2 == argc) {
    long x;
    sscanf(argv[1], "%ld", &x);
    result = (crypto_uint64) x;
  } else {
    printf("Usage: `pack {n} where n is a 64-bit signed integer");
  }
  return result;
}

int main (int argc, char** argv) {
  int result = -1;

  crypto_uint64 x = parse_args(argc, argv);
  if (x) {
    //printf("Packing %llu into an array of bytes\n", x);
    unsigned char y[8];
    uint64_pack(y, x);

    for(int i=0; i<8; i++) {
      printf("\t0x%x", y[i]);
    }
    printf("\n");

    result = 0;
  }
  return result;
}
