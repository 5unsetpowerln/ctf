#include <stdio.h>
long decrypt(long cipher) {
  puts("The decryption uses the fact that the first 12bit of the plaintext "
       "(the fwd pointer) is known,");
  puts("because of the 12bit sliding.");
  puts("And the key, the ASLR value, is the same with the leading bits of the "
       "plaintext (the fwd pointer)");
  long key = 0;
  long plain;

  for (int i = 1; i < 6; i++) {
    int bits = 64 - 12 * i;
    if (bits < 0)
      bits = 0;
    plain = ((cipher ^ key) >> bits) << bits;
    key = plain >> 12;
    printf("round %d:\n", i);
    printf("key:    %#016lx\n", key);
    printf("plain:  %#016lx\n", plain);
    printf("cipher: %#016lx\n\n", cipher);
  }
  return plain;
}

int main() {
  // long cipher = 0x000055500000e70a;
  long cipher = 0x571b85ad600a;
  long plain = decrypt(cipher);
  printf("plain: %#016lx\n", plain);
  return 0;
}
