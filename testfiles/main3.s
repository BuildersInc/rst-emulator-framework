// .section .data
// .syntax unified

.equ RCGC_GPIO_R, 0x1000000
.equ RCGC_GPIO_PORT_A, 0x01
.equ RCGC_GPIO_PORT_B, 0x02
.equ RCGC_GPIO_PORT_C, 0x04
.equ RCGC_GPIO_PORT_D, 0x08
.equ RCGC_GPIO_PORT_E, 0x10
.equ RCGC_GPIO_PORT_F, 0x20

// .section .text
// .global main
// .align

main:
    // avtivate clock on portF
    LDR R0, =RCGC_GPIO_R
    LDR R1, [R1]
    ORR R1, R1, #RCGC_GPIO_PORT_F
    STR R1, [R0]

.end
