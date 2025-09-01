        .equ RCGC_GPIO_R, 0x4000000
        .equ RCGC_GPIO_PORT_A, 0x01

        .thumb
        .syntax unified

main:
        MOVW    R0, #(RCGC_GPIO_R & 0xFFFF)    @ load low half (0x0000)
        MOVT    R0, #(RCGC_GPIO_R >> 16)       @ load high half (0x2000)

        LDR     R1, [R0]           @ read current value at 0x2000000
        MOVS    R2, #5             @ R2 = 5
        ORRS    R1, R1, R2         @ R1 |= 5
        STR     R1, [R0]           @ store back to 0x2000000
        BX      LR

        .end