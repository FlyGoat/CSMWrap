; AP Trampoline for BIOS Proxy Helper Core
; This code is copied to 0x7000 and runs when an AP wakes from SIPI
; AP starts at CS:IP = 0x0700:0x0000 = linear 0x7000
;
; This trampoline stays in 16-bit real mode and jumps to the SeaBIOS
; 16-bit entry point, which handles the GDT load and 32-bit mode switch.

bits 16

section .rodata

global ap_trampoline_start
ap_trampoline_start:
    cli
    cld

    ; Set up DS=0 so we can read from trampoline data area
    xor ax, ax
    mov ds, ax
    mov es, ax

    ; Load 32-bit values into registers for SeaBIOS
    ; (16-bit mode can still use 32-bit registers with operand size prefix)
    mov ebx, [0x7000 + trampoline_mailbox - ap_trampoline_start]
    mov esp, [0x7000 + trampoline_stack - ap_trampoline_start]
    mov esi, (0x7000 + trampoline_helper_ready - ap_trampoline_start)

    ; Far jump to SeaBIOS 16-bit entry point (segment:offset)
    jmp far [0x7000 + trampoline_target16 - ap_trampoline_start]

; --- Data area (filled in by C code) ---

align 4
trampoline_mailbox:
    dd 0

trampoline_stack:
    dd 0

; Far pointer for 16-bit jump: offset (16-bit) then segment (16-bit)
trampoline_target16:
    dw 0        ; offset
    dw 0        ; segment

trampoline_helper_ready:
    dd 0

ap_trampoline_end:

global ap_trampoline_size
ap_trampoline_size: equ (ap_trampoline_end - ap_trampoline_start)

; Export size and offsets for C code
global ap_trampoline_size_value
ap_trampoline_size_value: dd ap_trampoline_size

global ap_trampoline_mailbox_offset
ap_trampoline_mailbox_offset: dd (trampoline_mailbox - ap_trampoline_start)

global ap_trampoline_stack_offset
ap_trampoline_stack_offset: dd (trampoline_stack - ap_trampoline_start)

global ap_trampoline_target16_offset
ap_trampoline_target16_offset: dd (trampoline_target16 - ap_trampoline_start)

global ap_trampoline_helper_ready_offset
ap_trampoline_helper_ready_offset: dd (trampoline_helper_ready - ap_trampoline_start)

section .note.GNU-stack noalloc noexec nowrite progbits
