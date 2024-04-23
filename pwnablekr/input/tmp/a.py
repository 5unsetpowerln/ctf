bin_name = "test"
argv = [bin_name]
for _ in range(99):
    argv.append("A")
argv[ord("A")] = "hello"
argv[ord("B")] = "hello"
print(argv)
