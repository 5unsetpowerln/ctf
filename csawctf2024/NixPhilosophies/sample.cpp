#include <iostream>
#include <string>
int main() {
    std::string __str;
    std::cout << "hello?\n";
    std::cin >> __str;
    std::string __str_new = __str;
    std::string __str_new_new = __str_new;
    std::cout << __str_new_new << "\n";

    return 0;
}
