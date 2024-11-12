#include <iostream>
#include <vector>

int main() {
	size_t choice, index;
	std::string todo;
	std::vector<std::string> todo_list;

	std::cin.rdbuf()->pubsetbuf(nullptr, 0);
	std::cout.rdbuf()->pubsetbuf(nullptr, 0);

	std::cout << "1. add" << std::endl
			  << "2. show" << std::endl
			  << "3. edit" << std::endl
			  << "4. delete" << std::endl;
	while (std::cin.good()) {
		std::cout << "> ";
		std::cin >> choice;

		switch (choice) {
		case 1: // add
			std::cout << "TODO: ";
			std::cin.ignore();
			std::getline(std::cin, todo);
			todo_list.emplace_back(todo);
			break;

		case 2: // show
			std::cout << "Index: ";
			std::cin >> index;
			if (index >= todo_list.capacity()) {
				std::cout << "[-] Invalid index" << std::endl;
				break;
			}
			std::cout << "TODO: " << todo_list[index] << std::endl;
			break;

		case 3: // edit
			std::cout << "Index: ";
			std::cin >> index;
			if (index >= todo_list.capacity()) {
				std::cout << "[-] Invalid index" << std::endl;
				break;
			}
			std::cout << "TODO: ";
			std::cin.ignore();
			std::getline(std::cin, todo_list[index]);
			break;

		case 4: // delete
			std::cout << "Index: ";
			std::cin >> index;
			if (index >= todo_list.capacity()) {
				std::cout << "[-] Invalid index" << std::endl;
				break;
			}
			todo_list.erase(todo_list.begin() + index);
			break;

		default:
			return 0;
		}
	}
	return 0;
}
