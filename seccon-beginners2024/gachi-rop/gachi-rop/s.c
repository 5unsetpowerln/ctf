{
    install_seccomp();
    printf("system@%p\n", system);
    int64_t buf = 0;
    int64_t var_10 = 0;
    printf("Name: ");
    gets(&buf);
    printf("Hello, gachi-rop-%s!!\n", &buf);
    return 0;
}

