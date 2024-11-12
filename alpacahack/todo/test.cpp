#include <iostream>
#include <ostream>
#include <string>
#include <vector>

int main() {
	std::string str;
	std::vector<std::string> vec;

	std::cout << "capacity: " << vec.capacity() << std::endl;

	str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	vec.emplace_back(str);
	std::cout << "capacity: " << vec.capacity() << std::endl;

	str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	vec.emplace_back(str);
	std::cout << "capacity: " << vec.capacity() << std::endl;

	str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	vec.emplace_back(str);
	std::cout << "capacity: " << vec.capacity() << std::endl;

	str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	vec.emplace_back(str);
	vec.emplace_back(str);
	std::cout << "capacity: " << vec.capacity() << std::endl;

	str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	vec.emplace_back(str);
	std::cout << "capacity: " << vec.capacity() << std::endl;

	str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	vec.emplace_back(str);
	std::cout << "capacity: " << vec.capacity() << std::endl;

	vec.erase(vec.begin() + 3);
	vec.erase(vec.begin() + 3);

	std::cout << vec.at(0) << std::endl;

	return 0;
}
