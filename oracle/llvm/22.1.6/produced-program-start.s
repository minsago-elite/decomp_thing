# Linux amd64 only; no interpreter, libc, environment, or filesystem access.
.section .rodata
message:
    .ascii "issue97-produced-program\n"
.set message_size, . - message
.section .text
.globl _start
.type _start,@function
_start:
    mov $1, %eax
    mov $1, %edi
    lea message(%rip), %rsi
    mov $message_size, %edx
    syscall
    cmp $message_size, %rax
    jne failed
    mov $60, %eax
    mov $42, %edi
    syscall
failed:
    mov $60, %eax
    mov $43, %edi
    syscall
.size _start, . - _start
.section .note.GNU-stack,"",@progbits
