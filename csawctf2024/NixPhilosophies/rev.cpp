#include <cstdint>
#include <iostream>
#include <string>
int main() {
  std::string __str;
  std::cout << "Tell me what you know about *nix philosophies: ";
  std::cin >> __str;
  int32_t AAAA = 0; // $rbp - 0x28c
  int32_t BBBB = 1;
  void CCCC;
  while (true) {
      std::string::size_type DDDD;
      /// is BBBB less than ___str.size()?
      DDDD = ((int64_t) BBBB ) < __str.size();
      if (DDDD == 0) {
          break;
      }
      char EEEE = __str[BBBB];
      /// EEEE: rbp - 0x29 (1byte) -> __str[BBBB] ?
      std::string::iterator FFFF;
      std::string::iterator* GGGG = &FFFF;
      void HHHH;
      // the data of CCCC will be data of HHHH
      std::string CCCC = HHHH;
      // IIII = rbp-0x270
      // the address in IIII is the address of top of CCCC(string) (not data)
      // IIII: rbp - 0x270
      void *IIII = &CCCC;
      // iterator: rbp - 0x280
      std::string::iterator iterator = std::string::begin(IIII):
      // FFFF: rbp - 0x278
      FFFF = std::string::end(this: IIII);
      // ...
      while (true) {
          if (&iterator != FFFF) {
              break;
          }
          AAAA = (AAAA + iterator);
          iterator ++;
      }
      // this is destruction of CCCC
      std::string::~string(&CCCC);
      BBBB += 1;

      // to prevent optimization
      std::cout << __str[BBBB] ;
  }

  return 0;
}
