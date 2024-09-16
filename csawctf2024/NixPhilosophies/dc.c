int32_t main(int32_t argc, char** argv, char** envp)

    void* fsbase
    int64_t rax = *(fsbase + 0x28)
🛑    void __str
    std::string::string(this: &__str)
    std::operator<<<std::char_traits<char> >(__out: &std::cout, __s: "Tell me what you know about *nix…")
    std::operator>><char>(__in: &std::cin, __str: &__str)
    int32_t AAAA = 0
    int32_t BBBB = 1
    void CCCC
    while (true)
        std::string::size_type DDDD
        DDDD.b = sx.q(BBBB) u< std::string::size(this: &__str)
        if (DDDD.b == 0)
            break
        char EEEE = *std::string::operator[](this: &__str, __pos: sx.q(BBBB))
        std::string::iterator FFFF
        std::string::iterator* GGGG = &FFFF
        void HHHH
        std::string::string(this: &CCCC, __l: HHHH)
        void* IIII = &CCCC
        std::string::iterator iterator = std::string::begin(this: IIII)
        FFFF = std::string::end(this: IIII)
        while (true)
            if (operator!=<char*, std::string>(&iterator, &FFFF) == 0)
                break
            AAAA = AAAA + sx.d(*__normal_iterator<char*, std::string>::operator*(&iterator))
            __normal_iterator<char*, std::string>::operator++(&iterator)
        std::string::~string(this: &CCCC)
        BBBB = BBBB + 1
    int32_t var_28c = read(fd: AAAA - 0x643, buf: &buf, nbytes: 0x20)
    if (strcmp("make every program a filter\n", &buf) != 0)
        std::ostream::operator<<(this: std::operator<<<std::char_traits<char> >(__out: &std::cout, __s: "You still lack knowledge about *…"), __pf: std::endl<char>)
    else
        std::ifstream::ifstream(this: &CCCC, __s: "flag.txt")
        void var_148
        if (std::ios::good(this: &var_148) == 0)
            std::ostream::operator<<(this: std::operator<<<std::char_traits<char> >(__out: std::ostream::operator<<(this: &std::cout, __pf: std::endl<char>), __s: "flag.txt: No such file or direct…"), __pf: std::endl<char>)
            std::ostream::operator<<(this: std::operator<<<std::char_traits<char> >(__out: &std::cout, __s: "If you're running this locally, …"), __pf: std::endl<char>)
        else
            std::ostream::operator<<(this: std::operator<<<std::char_traits<char> >(__out: std::ostream::operator<<(this: &std::cout, __pf: std::endl<char>), __s: "Welcome to pwning ^_^"), __pf: std::endl<char>)
            system(line: "/bin/cat flag.txt")
        std::ifstream::~ifstream(this: &CCCC)
    std::string::~string(this: &__str)
    *(fsbase + 0x28)
    if (rax == *(fsbase + 0x28))
        return 0
    __stack_chk_fail()
    noreturn

