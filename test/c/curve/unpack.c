
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "uint64_unpack.h"

unsigned char* parse_args(int argc, const char** argv) {
  unsigned char* result = NULL;

  if (9 == argc) {
    // Callers are responsible for freeing
    result = malloc(sizeof(unsigned char) * 8);
    for(int i=1; i<9; i++) {
      errno = 0;
      int success = strtol(argv[i], NULL, 0);
      if(errno != 0) {
        printf("Unable to process arg %d, %s\n", i, argv[i]);
        free(result);
        result = NULL;
        break;
      } else {
        // printf("Converted %s to %d\n", argv[i], success);
        result[i-1] = (unsigned char)success;
      }
    }
  } else {
    printf("Usage: unpack {b0 ... b7}\n");
    printf("Where b0 through b7 are unsigned bytes in hex format");
  }

  return result;
}

int main (int argc, const char** argv) {
  int result = -1;

  unsigned char* bytes = (parse_args(argc, argv));
  if(bytes) {
    crypto_uint64 unpacked = uint64_unpack(bytes);
    long long original = (long long) unpacked;
    printf("%lld\n", original);
    free(bytes);
    result = 0;
  }

  return result;
}
