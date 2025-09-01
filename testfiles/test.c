// DIESER CODE GEHT

#include <unicorn/unicorn.h>
#include <stdio.h>

// code to be emulated
#define X86_CODE32 "\xB9\x05\x00\x00\x00\x51\x5A"

// memory address where emulation starts
#define ADDRESS 0x600000
#define STACK_ADDR 0x700000
#define STACK_SIZE 0x10000  // 64 KB stack

int main(int argc, char **argv)
{
    uc_engine *uc;
    uc_err err;
    int r_ecx, r_edx, r_esp;
    int r_esp0 = STACK_ADDR + STACK_SIZE / 2; // initial stack pointer in middle of stack

    printf("Emulate i386 code\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return -1;
    }

    // map 2MB memory for code
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // map stack memory
    uc_mem_map(uc, STACK_ADDR, STACK_SIZE, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return -1;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ESP, &r_esp0);
    uc_reg_write(uc, UC_X86_REG_EBP, &r_esp0);

    // emulate code
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
               err, uc_strerror(err));
    }

    // read out registers
    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    uc_reg_read(uc, UC_X86_REG_ESP, &r_esp);

    printf("Emulation done. Below is the CPU context\n");
    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);
    printf(">>> ESP = 0x%x\n", r_esp);

    uc_close(uc);
    return 0;
}