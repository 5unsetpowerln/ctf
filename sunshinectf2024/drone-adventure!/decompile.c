#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void func_40139c() {
	uint64_t command; // rbp - 0x15
	uint64_t args;	  // rbp - 0x120

	memset(&command, 0, 5);
	memset(&args, 0, 0x100);

	printf("Enter command verb >>> ");
	read(0, &command, 5);

	printf("Enter command params >>> ");
	read(0, &args, 0x100);

	func_402120(&command, &args);
	return;
}

int64_t func_402120(uint64_t *command, uint64_t *args) {
	uint64_t command_ptr = (uint64_t)command;
	uint64_t args_ptr = (uint64_t)args;
	// int64_t rdi;
	// int64_t var_690 = rdi;
	// int64_t rsi;
	// int64_t var_698 = rsi;
	void var_688;
	__builtin_memcpy(&var_688, &data_4062c0, 0x4c8);
	jump(*(uint64_t *)(&var_688 + 0x70)); // 0x402413
}

int64_t func_402413() {
	if (strncmp(&command, "RECD", 4)) {
		atoi(&args);
	}
}
