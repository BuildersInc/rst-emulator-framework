#include <unicorn/unicorn.h>
#include <stdio.h>
#define X86_CODE32 "\xB9\x05\x00\x00\x00\x51\x5A" // memory address where emulation starts #define ADDRESS 0x600000 //#define ADDRESS_STC 0x100000 #define ADDRESS_STC 0x6000000 int main(int argc, char **argv, char **envp) { uc_engine *uc; //uc_engine *uc0; uc_err err; uc_err err0; //int r_ecx = 0x1234; // ECX register int r_ecx; // ECX register int r_edx; // EDX register int r_esp; int r_esp0 = 0x7FFFFF; printf("Emulate i386 code\n"); // Initialize emulator in X86-32bit mode err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc); if (err != UC_ERR_OK) { printf("Failed on uc_open() with error returned: %u\n", err); return -1; } // map 2MB memory for this emulation uc_mem_map(uc, ADDRESS, 1 * 1024 * 1024, UC_PROT_ALL); //uc_mem_map(uc, ADDRESS_STC, 2 * 1024 * 1024, UC_PROT_ALL); printf("Mike \n"); // write machine code to be emulated to memory if (uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1)) { printf("Failed to write emulation code to memory, quit!\n"); return -1; } printf("Mike 0\n"); // initialize machine registers uc_reg_write(uc,UC_X86_REG_EBP, &r_esp0+512); uc_reg_write(uc,UC_X86_REG_ESP, &r_esp0+512); printf("Mike 01\n"); // emulate code in infinite time & unlimited instructions err=uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0); if (err) { printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err)); uc_reg_read(uc,UC_X86_REG_RSP,&r_esp0); printf("esp0 0x%x\n",r_esp0); } // now print out some registers printf("Emulation done. Below is the CPU context\n"); uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx); uc_reg_read(uc, UC_X86_REG_EBP, &r_edx); uc_reg_read(uc, UC_X86_REG_ESP, &r_esp); printf(">>> EX = 0x%x\n", r_ecx); printf(">>> EDX = 0x%x\n", r_edx); printf(">>> ESP = 0x%x\n", r_esp); uc_close(uc); return 0; }#include <unicorn/unicorn.h>

// code to be emulated
#define X86_CODE32 "\xB9\x05\x00\x00\x00\x51\x5A"

// memory address where emulation starts
#define ADDRESS 0x600000
// #define ADDRESS_STC 0x100000
#define ADDRESS_STC 0x6000000

    int
    main(int argc, char **argv, char **envp)
{
    uc_engine *uc;
    // uc_engine *uc0;
    uc_err err;
    uc_err err0;
    // int r_ecx = 0x1234;     // ECX register
    int r_ecx; // ECX register
    int r_edx; // EDX register
    int r_esp;
    int r_esp0 = 0x7FFFFF;

    printf("Emulate i386 code\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err != UC_ERR_OK)
    {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return -1;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 1 * 1024 * 1024, UC_PROT_ALL);
    // uc_mem_map(uc, ADDRESS_STC, 2 * 1024 * 1024, UC_PROT_ALL);
    printf("Mike \n");

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1))
    {
        printf("Failed to write emulation code to memory, quit!\n");
        return -1;
    }
    printf("Mike 0\n");

    // initialize machine registers

    uc_reg_write(uc, UC_X86_REG_EBP, &r_esp0 + 512);
    uc_reg_write(uc, UC_X86_REG_ESP, &r_esp0 + 512);

    printf("Mike 01\n");

    // emulate code in infinite time & unlimited instructions
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
    if (err)
    {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
               err, uc_strerror(err));
        uc_reg_read(uc, UC_X86_REG_RSP, &r_esp0);
        printf("esp0 0x%x\n", r_esp0);
    }

    // now print out some registers
    printf("Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EBP, &r_edx);
    uc_reg_read(uc, UC_X86_REG_ESP, &r_esp);

    printf(">>> EX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);
    printf(">>> ESP = 0x%x\n", r_esp);

    uc_close(uc);

    return 0;
}