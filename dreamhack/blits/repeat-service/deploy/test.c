#include <stdio.h>
int main() {
	int current_max_overflow = 0;
	for (int i = 1; i < 81; i++) {
		int count = 0;
		int len = i;
		int target_len = 1000;
		while (count < target_len) {
			// memcpy(buf + count, inp, len);
			// printf("%d final_count: %d\n", i, count);
			count += len; // if len == 0, infinity loop
		}
		int final_count = count - len;
		int overflow = final_count + len - 1000;

		printf("len: %d, final_count: %d, overflow: %d\n", len, final_count,
			   overflow);
		// if (current_max_overflow < overflow) {
		// 	printf("len: %d, final_count: %d, overflow: %d\n", len, final_count,
		// overflow); 	current_max_overflow = overflow;
		// }
	}
	return 0;
}
