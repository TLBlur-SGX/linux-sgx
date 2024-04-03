        # TLBlur vTLB/shadow page table update, called by instrumentation
        # 
        # args: %rdi = accessed address
        # %rax used as a scratch register
        __tlblur_pt_size = 0x1000000
        .global tlblur_tlb_update
tlblur_tlb_update:
        # Index in software TLB %rdi = ((%rdi - <enclave base>) >> 9) & (<size> - 1)
        lea     __ImageBase(%rip), %rax
        sub     %rax, %rdi
        shr     $9, %rdi
        and     $__tlblur_pt_size - 1, %rdi

        # Then update the software TLB
        leaq    __tlblur_shadow_pt(%rip), %rax
        add     %rax, %rdi

        # Increment global counter, and store it in %rax
        movq    __tlblur_global_code_counter(%rip), %rax
        incq    __tlblur_global_code_counter(%rip)

        # Update shadow page table by storing incremented global counter
        movq    %rax, (%rdi)
        ret

.global my_fun, my_fun_noc3
    .align 0x1000
my_fun:
    .space 0x100
    ret
    .space 0x1000
my_fun_noc3:
    .space 0x1000

        .data

        .align 0x1000   # 4KiB
        .global __tlblur_shadow_pt
__tlblur_shadow_pt:
        .zero   __tlblur_pt_size
__tlblur_shadow_pt_end:

        .global __tlblur_global_counter
__tlblur_global_counter:
        .quad   0

        .global __tlblur_global_code_counter
__tlblur_global_code_counter:
        .quad   0

        .global page_a, page_b, page_c, page_d
        .align 0x1000
page_a:
    .space 0x1000
page_b:
    .space 0x1000
page_d:
    .space 0x1000

    .section .rodata
    .align 0x1000
page_c:
    .space 0x1000
