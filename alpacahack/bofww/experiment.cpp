#include <iostream>
#include <string>
int main() {
  std::string hello = "AAAAAAAA";
  std::string world = "BBBBBBBB";
  world = hello;
  std::cout << world << std::endl;
  return 0;
}
