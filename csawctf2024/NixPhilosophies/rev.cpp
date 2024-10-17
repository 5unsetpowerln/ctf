#include <string>
int main() {
    void* fsbase;
    int64_t rax = *(uint64_t*)((char*)fsbase + 0x28);
🛑    void __str;
    std::string::string(&__str);
    std::operator<<<std::char_traits<char> >(&std::cout, "Tell me what you know about *nix…");
    std::operator>><char>(&std::cin, &__str);
    int32_t AAAA = 0;
    int32_t BBBB = 1;
    void CCCC;
    while (true)
    {
        string DDDD;
        DDDD = ((int64_t)BBBB) < std::string::size(&__str);
        if (DDDD == 0)
        {
            break;
        }
        char EEEE = *(uint8_t*)std::string::operator[](&__str, ((int64_t)BBBB));
        std::string::iterator FFFF;
        std::string::iterator* GGGG = &FFFF;
        void HHHH;
        std::string::string(&CCCC, HHHH);
        void* IIII = &CCCC;
        std::string::iterator iterator = std::string::begin(IIII);
        FFFF = std::string::end(IIII);
        while (true)
        {
            if (operator!=<char*, std::string>(&iterator, &FFFF) == 0)
            {
                break;
            }
            AAAA = (AAAA + ((int32_t)*(uint8_t*)__normal_iterator<char*, std::string>::operator*(&iterator)));
            __normal_iterator<char*, std::string>::operator++(&iterator);
        }
        std::string::~string(&CCCC);
        BBBB = (BBBB + 1);
    }
    int32_t var_28c = read((AAAA - 0x643), &buf, 0x20);
    if (strcmp("make every program a filter\n", &buf) != 0)
    {
        std::ostream::operator<<(std::operator<<<std::char_traits<char> >(&std::cout, "You still lack knowledge about *…"), std::endl<char>);
    }
    else
    {
        std::ifstream::ifstream(&CCCC, "flag.txt");
        void var_148;
        if (std::ios::good(&var_148) == 0)
        {
            std::ostream::operator<<(std::operator<<<std::char_traits<char> >(std::ostream::operator<<(&std::cout, std::endl<char>), "flag.txt: No such file or direct…"), std::endl<char>);
            std::ostream::operator<<(std::operator<<<std::char_traits<char> >(&std::cout, "If you're running this locally, …"), std::endl<char>);
        }
        else
        {
            std::ostream::operator<<(std::operator<<<std::char_traits<char> >(std::ostream::operator<<(&std::cout, std::endl<char>), "Welcome to pwning ^_^"), std::endl<char>);
            system("/bin/cat flag.txt");
        }
        std::ifstream::~ifstream(&CCCC);
    }
    std::string::~string(&__str);
    *(uint64_t*)((char*)fsbase + 0x28);
    if (rax == *(uint64_t*)((char*)fsbase + 0x28))
    {
        return 0;
    }
    __stack_chk_fail();
}
