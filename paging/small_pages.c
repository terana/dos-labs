#include "stdio.h"
#include "stdlib.h"

typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned short int uint16;

#define NP 512 /* This page will be marked as not present */
#define PAGE_SIZE 4096
#define PTE_SIZE 4
#define PTE_PER_PAGE (PAGE_SIZE/PTE_SIZE)

#define PF_NUM 14 /* Number of PF handler gate in IDT */

#define PF_ADDR 0x80000000 /* page #512 (NP*4Mb) */

uint32 incr = 0;

typedef struct _IDT_ENTRY {
    uint16 offset_l;
    uint16 seg_sel;
    uint8 zero;
    uint8 flags;
    uint16 offset_h;
} IDT_ENTRY, *PIDT_ENTRY;

typedef struct _DTR {
    uint16 limit;
    uint32 base;
    uint16 _padding;
} DTR, *PDTR;

typedef union _SELECTOR {
    uint16 raw;
    struct {
        uint16 pl:2;
        uint16 table:1;
        uint16 index:13;
    };
} SELECTOR, *PSELECTOR;

typedef struct _SYSINFO {
    SELECTOR cs;
    uint32 cr0;
    DTR gdtr;
    DTR idtr;
    SELECTOR ldt;
    SELECTOR tr;
} SYSINFO, *PSYSINFO;

void get_sysinfo(SYSINFO *sysinfo) {
    uint16 _cs = 0;
    uint32 _cr0 = 0;
    DTR *_gdtr = &sysinfo->gdtr;
    DTR *_idtr = &sysinfo->idtr;
    uint16 _ldt = 0;
    uint16 _tr = 0;

    /* We can't get the value of the system register directly,
     * so doing it with the register of general purpose - eax:
     * cr0 -> eax, eax -> _cro
     */
    __asm {
    mov eax, cr0
    mov _cr0, eax
    mov ax, cs
    mov _cs, ax

    mov eax, _gdtr
    sgdt[eax]      /* Store GDT Register */
    mov eax, _idtr
    sidt[eax]      /* Store IDT Register */
    sldt _ldt      /* Store LDT Register */
    str _tr        /* Store Task Register */
    }

    sysinfo->cr0 = _cr0;
    sysinfo->cs.raw = _cs;
    sysinfo->ldt.raw = _ldt;
    sysinfo->tr.raw = _tr;
}

void idt_set_gate(PIDT_ENTRY idt, uint8 num, uint32 offset, uint16 seg_sel, uint8 flags) {
    idt[num].offset_l = offset & 0xFFFF;
    idt[num].offset_h = (offset >> 16) & 0xFFFF;
    idt[num].seg_sel = seg_sel;
    idt[num].zero = 0;
    idt[num].flags = flags;
}

/* Page table we create should contain aligned pages */
uint32 *pt_aligned;
uint32 *np_page_ptr; /* Not preset page */
uint32 *p_np_pde;

void page_table_create() {
    int i = 0;
    char *p = (char *) malloc(8 * 1024 * 1024); // 8Mb

    pt_aligned = (uint32 *) ((((uint32) p) & 0xffc00000) + 0x400000);

    for (i = 0; i < PTE_PER_PAGE; i++) {
        /* Page directory entry */
        uint32 pde = i * 0x400000 /* 4Mb page */
                     + 0x87; /* Present, RW, US, PS bits on */
        pt_aligned[i] = pde;
        if (i == NP) {
            pt_aligned[i] = pt_aligned[i] & 0xFFFFFFFE;
            p_np_pde = &pt_aligned[i];
        }
    }

    printf("Page %d is not present now\n", NP);
}

/* Sets up a stack frame for local variables */
void __declspec(naked) pf_handler(void) {
    __asm {
    push eax
    push edx
    mov edx, cr2
    cmp edx, PF_ADDR
    jnz pf
    mov eax, p_np_pde
    or dword ptr[eax], 1h // set present bit
    invlpg[eax] // flush TLB cache entry
    lea eax, incr // increment our counter
    add[eax], 1
    jmp done
    pf:
    pop edx
    pop eax
    push old_segment // call default PF-handler
    push old_offset
    retf
    done:
    pop edx
    pop eax
    add esp, 4 // pop error code
    iretd // 32-bit return from interrupt!
    }
}

int main() {
    SYSINFO sysinfo;
    PIDT_ENTRY idt = (PIDT_ENTRY) sysinfo.idtr.base;
    char *addr;
    uint32 new_offset = 0;
    uint16 new_segment = 0;
    /* Store default PF-handler */
    uint32 old_offset = idt[PF_NUM].offset_l | (idt[PF_NUM].offset_h << 16);
    uint16 old_segment = idt[PF_NUM].seg_sel;

    printf("Getting system info...");
    get_sysinfo(&sysinfo);


    page_table_create();

    __asm {
    pushfd        /* Push EFLAGS onto the stack */
    cli
    mov eax, pt_aligned
    mov cr3, eax  /* Put our page table address into CR3 */
    mov eax, cr4
    or eax, 0x90  /* Enable CR4.PSE (incr page size to 4 MB)*/
    mov cr4, eax  /* and CR4.PGE (address translations (PDE or PTE records) may be shared between address spaces) */
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax  /* Enable CR0.PG - paging enabled */
    popfd
    }

    addr = (uint32 *) PF_ADDR;
    printf("Memory %p: %d\n", addr, *addr); // BSOD

    /* Get offset and segment to put into IDT */
    __asm {
    mov edx, offset pf_handler
    mov new_offset, edx
    mov ax, seg pf_handler
    mov new_segment, ax
    }


    /* Replace default handler with our handler */
    idt_set_gate(idt, PF_NUM, (uint32) new_offset, new_segment, idt[PF_NUM].flags);

    addr = (uint32 *) PF_ADDR;

    /* Access to the memory that we marked as not present should generate page fault exception */

    /* To see default page fault */
    printf("Memory %p: %d\n", addr, *(addr + 4));
    printf("Memory %p: %d\n", addr, *addr); /* To recover page */
}