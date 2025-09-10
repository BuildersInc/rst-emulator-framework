// .section .data
// .syntax unified

.equ RCGC_GPIO_R, 0x400FE608
.equ RCGC_GPIO_PORT_A, 0x01
.equ RCGC_GPIO_PORT_B, 0x02
.equ RCGC_GPIO_PORT_C, 0x04
.equ RCGC_GPIO_PORT_D, 0x08
.equ RCGC_GPIO_PORT_E, 0x10
.equ RCGC_GPIO_PORT_F, 0x20

.equ GPIO_PORT_F_DATA_R, 0x400253FC
.equ GPIO_PORT_F_DEN_R,  0x4002551C
.equ GPIO_PORT_F_DIR_R,  0x40025400
.equ GPIO_PORT_F_PUR_R,  0x40025510

.equ GPIO_PORT_D_DATA_R, 0x400253FC
.equ GPIO_PORT_D_DEN_R,  0x4002551C
.equ GPIO_PORT_D_DIR_R,  0x40025400
.equ GPIO_PORT_D_PUR_R,  0x40025510

.equ PIN0, 0x01
.equ PIN1, 0x02
.equ PIN2, 0x04
.equ PIN3, 0x08
.equ PIN4, 0x10
.equ PIN5, 0x20
.equ PIN6, 0x40
.equ PIN7, 0x80
.equ ALL_PINS, 0xFF
.equ white, 0x0E
.equ Timer, 0xF4240
.equ Leftbit, 0x80000000
// .section .text
// .global main
// .align

main:
    // avtivate clock on portF
    LDR R0, =RCGC_GPIO_R
    LDR R1, [R1]
    ORR R1, R1, #RCGC_GPIO_PORT_F
    STR R1, [R0]


    // enable digital output for ledwhite
    LDR R0,=GPIO_PORT_F_DEN_R
    LDR R1,[R0]
    ORR R1,R1, #white
    STR R1,[R0]

    // enable digital output for ledblue
    LDR R0,=GPIO_PORT_F_DEN_R
    LDR R1,[R0]
    ORR R1,R1, #PIN2
    STR R1,[R0]
    // enable digital input for sw1
    LDR R0, =GPIO_PORT_D_DEN_R
    LDR R1,[R0]
    ORR R1,R1, #PIN4
    STR R1, [R0]
    // set direction to output for led-white
    LDR R0,=GPIO_PORT_F_DIR_R
    LDR R1,[R0]
    ORR R1,R1, #white
    STR R1,[R0]
    // set direction to output for led-blue
    LDR R0,=GPIO_PORT_F_DIR_R
    LDR R1,[R0]
    ORR R1,R1, #PIN2
    STR R1,[R0]
    // set button sw1 as input
    LDR R0, =GPIO_PORT_F_DIR_R
    LDR R1, [R0]
    BIC R1, R1, #PIN4
    STR R1, [R0]
    // enable pullup on button
    LDR R0, =GPIO_PORT_F_PUR_R
    LDR R1, [R0]
    ORR R1, R1, #PIN4
    STR R1, [R0]
    // set initiate r7 = 0x1
    MOV R7, #0x1

    LDR R0, =GPIO_PORT_F_DATA_R
    LDR R1, [R0]
    ORR R1, R1, #white
    STR R1, [R0]

nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop

.end
