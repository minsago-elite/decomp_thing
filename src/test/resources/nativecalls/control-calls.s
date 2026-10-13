.text
.globl _start
.type _start,@function
_start:
.globl repeated_first
repeated_first: call worker
.globl repeated_second
repeated_second: call worker
    lea worker(%rip), %rax
.globl resolved_register
resolved_register: call *%rax
.globl unresolved_register
unresolved_register: call *%r11
.globl resolved_memory
resolved_memory: call *slot(%rip)
.globl empty_memory
empty_memory: call *empty_slot(%rip)
.globl external_reference
external_reference: call *%r10
    cmp $0, %edi
.globl conditional_branch
conditional_branch: je branch_done
.globl unresolved_switch
unresolved_switch: jmp *%r12
branch_done: ret
.size _start, .-_start

.globl worker
.type worker,@function
worker: ret
.size worker, .-worker

.globl recursive
.type recursive,@function
recursive: call recursive
    ret
.size recursive, .-recursive

.globl zero_calls
.type zero_calls,@function
zero_calls: mov $1, %eax
    ret
.size zero_calls, .-zero_calls

.globl switch_control
.type switch_control,@function
switch_control:
    cmp $1, %edi
    ja switch_return
.globl switch_dispatch
switch_dispatch: jmp *switch_table(,%rdi,8)
switch_case_zero: xor %eax, %eax
    ret
switch_case_one: mov $1, %eax
    ret
switch_return: mov $-1, %eax
    ret
.size switch_control, .-switch_control

.globl tail
.type tail,@function
tail: jmp worker
.size tail, .-tail

.globl thunk_outer
.type thunk_outer,@function
thunk_outer: jmp thunk_inner
.size thunk_outer, .-thunk_outer
.globl thunk_inner
.type thunk_inner,@function
thunk_inner: jmp worker
.size thunk_inner, .-thunk_inner

.globl return_override
.type return_override,@function
return_override: call worker
    ret
.size return_override, .-return_override

.globl call_return_override
.type call_return_override,@function
call_return_override: call worker
    ret
.size call_return_override, .-call_return_override

.globl analysis_call_candidate
.type analysis_call_candidate,@function
analysis_call_candidate: jmp worker
.size analysis_call_candidate, .-analysis_call_candidate

.globl fallthrough_override
.type fallthrough_override,@function
fallthrough_override: call worker
    nop
    ret
.size fallthrough_override, .-fallthrough_override

.globl length_override
.type length_override,@function
length_override: call worker
    ret
.size length_override, .-length_override

.data
.globl slot
slot: .quad worker
.globl empty_slot
empty_slot: .quad 0
.align 8
switch_table: .quad switch_case_zero, switch_case_one

.section .note.GNU-stack,"",@progbits
