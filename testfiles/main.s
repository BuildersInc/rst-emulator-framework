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
; .equ Timer, 0xF
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
    B Checkbutton
init_hardware:
LEDWHITE:
    // turn white-led on
    LDR R0, =GPIO_PORT_F_DATA_R
    LDR R5, [R0]
    ORR R5, R5, #white
    STR R5, [R0]
    BX LR
Checkbutton:
    // check button sw1 pressed or not
    LDR R0, =GPIO_PORT_F_DATA_R
    LDR R1, [R0]
    LDR R2, [R0]
    BIC R1,R1,#PIN4
    CMP R1,R2
    BEQ handle_btn_pressed
    B handle_btn_not_pressed
LEDBLUE:
// turn led-white off, then turn led-blue on
    LDR R0, =GPIO_PORT_F_DATA_R
    LDR R1, [R0]
    BIC R1, R1, #white
    STR R1, [R0]
    LDR R0, =GPIO_PORT_F_DATA_R
    LDR R1, [R0]
    ORR R1, R1, #PIN2
    STR R1, [R0]
    BX LR
handle_btn_not_pressed:
    MOV R0, #0x0
    LDR R1, =Timer
    BL endless_loop
    BL LEDWHITE
    MOV R1, #Leftbit
    LSL R7, R7,#1
    CMP R1, R7
    BEQ ResetRight
    B Checkbutton
handle_btn_pressed:
    MOV R0, #0x0
    LDR R1, =Timer
    BL endless_loop
    BL LEDWHITE
    MOV R1, #0x1
    LSR R7, R7, #1
    CMP R1,R7
    BEQ ResetLeft
    B Checkbutton
endless_loop:
// timer
    MOV R2, #0x1
    ADD R0, R0, R2
    CMP R0, R1
    BNE endless_loop
    BX LR
ResetRight:
    MOV R7, #0x1
    B Checkbutton
ResetLeft:
    LDR R7, =Leftbit
    B Checkbutton
.end
