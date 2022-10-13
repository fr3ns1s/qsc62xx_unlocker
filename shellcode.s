.section .text
.global _main
.syntax unified

@ZTE F116 H3G_IT_P640A30V1.0.0B11-S
@diag   0x11985b3
@probe  0xc3e83d
@read   0xc3e973
@erase  0xc3e8ff
@write  0xc3e877

@ZTE T95 TEL_AU_P622C6V1.0.2B03-S
@diag   0x1264df7
@probe  0x29e0cd
@read   0x29e203
@erase  0x29e18f
@write  0x29e107

@commands
@0x40 exec loader
@0x41 nand init
@0x42 read nand
@0x43 erase nand
@0x44 copy data to buffer
@0x45 write buffer to nand

_main:
    .code 16
    push {r1-r7,lr}
    movs r7, r0
    movs r6, r1
    ldrb r0, [r7,#1]
    cmp r0, #0x40
    bne lbl_read_nand
    movs r0, #0xba
    movs r1, #26
    blx func_diagpkt_alloc
    adds r4, r0, #0
    blx func_print_loader
    b lbl_epilogue
lbl_read_nand:
    cmp r0, #0x42
    bne lbl_erase_nand
    blx func_nand_probe
    adds r0, r7, #2
    blx func_format_address
    adds r1, r0, #0
    blx func_read_nand_page
    cmp r0, #0
    bne lbl_error
    movs r0, #0xba
    adr r1,pages_size_ptr
    ldr r1, [r1]
    adds r1, r1, #3
    blx func_diagpkt_alloc
    adds r4, r0, #0
    blx func_copy_buffer_to_resp
    b lbl_epilogue
lbl_erase_nand:
    cmp r0, #0x43
    bne lbl_copy_data_to_write
    cmp r6, #6
    bcc lbl_error
    adds r0, r7, #2
    blx func_format_address
    adds r1, r0, #0
    blx func_nand_erase_block
    cmp r0, #0
    bne lbl_error
    movs r0, #0xba
    movs r1, #4
    blx func_diagpkt_alloc
    adds r4, r0, #0
    movs r0, #0x1
    strb r0, [r4,#1]
    movs r0, #0x00
    strb r0, [r4,#2]
    movs r0, #0x1
    strb r0, [r4,#3]
    b lbl_epilogue
lbl_copy_data_to_write:
    cmp r0, #0x44 
    bne lbl_write_nand
    adds r0, r7, #2
    blx func_format_address
    adds r3, r0, #0
    adds r0, r7, #6
    blx func_format_address
    adds r2, r0, #0
    adds r2, #0xa
    cmp r6, r2
    bcc lbl_error
    subs r2, #0xa
    adds r0, r7, #6
    adds r0, r0, #4
    adds r1, r0, #0
    adds r0, r3, #0
    blx func_copy_data_at
    cmp r0, #0
    bne lbl_error
    movs r0, #0xba
    movs r1, #4
    blx func_diagpkt_alloc
    adds r4, r0, #0
    movs r0, #0x1
    strb r0, [r4,#1]
    movs r0, #0x00
    strb r0, [r4,#2]
    movs r0, #0x1
    strb r0, [r4,#3]
    b lbl_epilogue
lbl_write_nand:
    cmp r0, #0x45
    bne lbl_nand_init
    cmp r6, #6
    bne lbl_error
    blx func_nand_probe
    adds r0, r7, #2
    blx func_format_address
    adds r1, r0, #0
    blx func_write_nand_page
    cmp r0, #0
    bne lbl_error
    movs r0, #0xba
    movs r1, #4
    blx func_diagpkt_alloc
    adds r4, r0, #0
    movs r0, #0x1
    strb r0, [r4,#1]
    movs r0, #0x00
    strb r0, [r4,#2]
    movs r0, #0x1
    strb r0, [r4,#3]
    b lbl_epilogue
lbl_nand_init:
    cmp r0, #0x41
    bne lbl_error
    blx func_nand_probe
    movs r0, #0xba
    movs r1, #4
    blx func_diagpkt_alloc
    adds r4, r0, #0
    movs r0, #0x1
    strb r0, [r4,#1]
    movs r0, #0x00
    strb r0, [r4,#2]
    movs r0, #0x1
    strb r0, [r4,#3]
    b lbl_epilogue
lbl_error:
    movs r0, #0xba
    movs r1, #3
    blx func_diagpkt_alloc
    adds r4, r0, #0
    movs r0, #0x0
    strb r0, [r4,#1]
    movs r0, #0x0
    strb r0, [r4,#2]
lbl_epilogue:
    mov r0, r4
    pop {r1-r7,pc}


func_print_loader:
    .code 32
    push {r3-r7,lr}
    adr r1, loader_version
    movs r0, #22
    strb r0, [r4,#1]
    movs r0, #0
    strb r0, [r4,#2]
    movs r2, #3
lbl_loop_print:
    ldrb r0, [r1], #1
    strb r0, [r4,r2]
    adds r2, r2, #1
    cmp r2, #25
    movs r0, #0
    strb r0, [r4,r2]
    bcc lbl_loop_print
    pop {r3-r7,pc}

func_format_address:
    .code 32
    push {r1-r7,lr}
    adds r5, r0, #0
    ldrb r0, [r5,#3]
    lsls r1, r0, #8
    ldrb r0, [r5,#2]
    orrs r0, r1
    lsls r1, r0, #8
    ldrb r0, [r5,#1]
    orrs r0, r1
    lsls r1, r0,#8
    ldrb r0, [r5]
    orrs r1, r0
    adds r0, r1, #0
    pop {r1-r7,pc}

func_copy_data_at:
    .code 32
    push {r3-r7,lr}
    movs r3, #0
lbl_loop_copy_at:
    ldrb r4, [r1,r3]
    strb r4, [r0,r3]
    adds r3, r3, #1
    cmp r3, r2
    bcc lbl_loop_copy_at
    movs r0, #0
    pop {r3-r7,pc}

func_copy_buffer_to_resp:
    .code 32
    push {r1-r7,lr}
    adr r1, buffer_ptr
    ldr r1, [r1]
    adr r2,pages_size_ptr
    ldr r2, [r2]
    and r0, r2, #0xff
    strb r0, [r4,#1]
    asr r0, r2, #0x8
    strb r0, [r4,#2]
    adds r2, r2, #3
    movs r3, #3
lbl_loop_copy_to:
    ldrb r0, [r1],#1
    strb r0, [r4,r3]
    adds r3, r3, #1
    cmp r3, r2
    bcc lbl_loop_copy_to
    pop {r1-r7,pc}

func_read_nand_page:
    .code 32
    adr r0, nand_probe_array_ptr
    ldr r0, [r0]
    adr r2, buffer_ptr
    ldr r2, [r2]
    adr r12, nand_read_ptr
    ldr r12, [r12]
    bx r12

func_nand_erase_block:
    .code 32
    adr r0, nand_probe_array_ptr
    ldr r0, [r0]
    adr r2, buffer_ptr
    ldr r2, [r2]
    adr r12, nand_erase_ptr
    ldr r12, [r12]
    bx r12

func_write_nand_page:
    .code 32
    adr r0, nand_probe_array_ptr
    ldr r0, [r0]
    adr r2, buffer_ptr
    ldr r2, [r2]
    movs r3, #0x0
    adr r12, nand_write_ptr
    ldr r12, [r12]
    bx r12

func_nand_probe:
    .code 32
    adr r0, nand_probe_array_ptr
    ldr r0, [r0]
    movs r1, #0
    adr r12, nand_probe_ptr
    ldr r12, [r12]
    bx r12

func_diagpkt_alloc:
    .code 32
    adr r12, diag_ptr
    ldr r12, [r12]
    bx r12

pages_size_ptr: .word 0x800
loader_version: .asciz "(c)fr3nsis loader v1.0"
.balign 16
diag_ptr: .word 0x41414141
nand_probe_ptr: .word 0x42424242
nand_read_ptr: .word 0x43434343
nand_erase_ptr: .word 0x44444444
nand_write_ptr: .word 0x45454545
nand_probe_array_ptr: .word 0x46464646
buffer_ptr: .word 0x47474747

