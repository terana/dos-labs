#include "stdio.h"
#include "stdlib.h"

typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned short int uint16;

#define CR0_PE 0x1 /* Protected mode Enabled bit of CR0 */
#define CR0_PG (1<<31) /* Paging on bit of CR0: 0x80000000 */

#define PF_NUM 14 /* Number of PF handler gate in IDT */

#define PAGE_SIZE 4096
#define PTE_SIZE 4
#define PTE_PER_PAGE (PAGE_SIZE/PTE_SIZE)

#define PTE_TRIVIAL_SELFMAP     0x007  /* Enable read-write, user, 4Kb */
#define PTE_NOT_PRESENT         0xFFFFFFFE

#pragma pack (push, 1)

/* 4-12 Vol. 3A Table 4-6 */
typedef union _PTE {
    uint32 raw;
    struct {
        uint32 p:1;   /* Present */
        uint32 rw:1;  /* Read/Write */
        uint32 us:1;  /* User = 1/ Supervisor = 0 */
        uint32 pwt:1;
        uint32 pcd:1;
        uint32 a:1;   /* Accessed */
        uint32 d:1;   /* Dirty */
        uint32 pat:1;
        uint32 g:1;   /* Global; if CR4.PGE = 1, determines whether the translation is global */
        uint32 ignored:3;
        uint32 pfa:20;  /* Address of 4KB page frame */
    };
} PTE, *PPTE;

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
    sldt _ldt       /* Store LDT Register */
    str _tr        /* Store Task Register */
    }

    sysinfo->cr0 = _cr0;
    sysinfo->cs.raw = _cs;
    sysinfo->ldt.raw = _ldt;
    sysinfo->tr.raw = _tr;
}

char *PF_ADDR = 0;
int NP = 0; /* Not present page */
uint32 my_ptr = 0;
uint32 incr = 0;

void idt_set_gate(PIDT_ENTRY idt, uint8 num, uint32 offset, uint16 seg_sel, uint8 flags) {
    idt[num].offset_l = offset & 0xFFFF;
    idt[num].offset_h = (offset >> 16) & 0xFFFF;
    idt[num].seg_sel = seg_sel;
    idt[num].zero = 0;
    idt[num].flags = flags;
}

/* Sets up a stack frame for local variables */
void __declspec(naked) pf_handler(void) {
    __asm {
    push eax
    push edx
    mov edx, cr2
    cmp edx, PF_ADDR   /* My address */
    jnz pf
    mov eax, my_ptr         /* PDE/PTE corresponding to the unpresent address */
    or dword ptr[eax], 1h   /* restore Present bit */
    invlpg[eax]             /* Invalidate TLB for my address */
    lea eax, incr           /* inc counter of PsF */
    add[eax], 1
    jmp done
    pf:
    pop edx
    pop eax
    push old_segment /* Call default PF-handler */
    push old_offset
    retf             /* Returns to the address in the stack */
    done:
    pop edx
    pop eax
    add esp, 4  /* Pop error code */
    iretd       /* 32-bit return from interrupt! */
    }
}

void page_table_create() {
    int i = 0, j = 0;
    uint32 k4 = 4 * 1024;
    uint32 m4 = 4 * 1024 * 1024;

    char *addr = (char *) 0xF007F000;
    NP = 0x3c0 * 0x400 + 0x7F;

    void *p1 = malloc(k4 * 2);
    uint32 _p1 = (uint32) p1;
    uint32 _pd_aligned = (_p1 & ~(k4 - 1)) + k4;
    uint32 _pd = _pd_aligned + 0;
    PPTE pd = (PPTE) _pd;

    void *p2 = malloc(m4 * 2);
    uint32 _p2 = (uint32) p2;
    uint32 _pt_aligned = (_p2 & ~(m4 - 1)) + m4;
    uint32 _pt = _pt_aligned + 0;
    PPTE pt = (PPTE) _pt;

    printf("malloc 8Kb at 0x%08X-0x%08x, aligned at 0x%08X \n", _p1, _p1 + k4 * 2, _pd_aligned);
    printf("malloc 8Mb at 0x%08X-0x%08x, aligned at 0x%08X \n", _p2, _p2 + m4 * 2, _pt_aligned);

    /* Trivial mapping */
    for (i = 0; i < PTE_PER_PAGE; i++) {
        /* Page directory entry */
        pd[i].raw = (uint32) (pt + i * 1024);
        pd[i].raw |= PTE_TRIVIAL_SELFMAP;
    }
    for (i = 0; i < PTE_PER_PAGE; i++) {
        for (j = 0; j < PTE_PER_PAGE; j++) {
            int idx = i * 1024 + j;
            pt[idx].raw = idx * 0x1000;
            pt[idx].raw |= PTE_TRIVIAL_SELFMAP;
        }
    }

    pt[NP].raw &= PTE_NOT_PRESENT;
    printf("Page %d is not present now\n", NP);

    __asm {
    pushfd        /* Push EFLAGS onto the stack */
    cli
    mov eax, _pd_aligned
    mov cr3, eax  /* Put our page table address into CR3 */
    mov eax, cr4
    or eax, 0x90  /* Enable CR4.PSE (incr page size to 4 MB)*/
    mov cr4, eax  /* and CR4.PGE (address translations (PDE or PTE records) may be shared between address spaces) */
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax  /* Enable CR0.PG - paging enabled */
    popfd
    }

    PF_ADDR = addr + 17;
    my_ptr = (uint32) (&(pt[NP]));

    /* BSOD */
    // printf("BSOD\n");
    // printf("BSOD %p: %d\n", PF_ADDR, *PF_ADDR);
}

void pf_test(PSYSINFO sysinfo) {
    PIDT_ENTRY idt = (PIDT_ENTRY) sysinfo->idtr.base;

    /* Store default PF-handler */
    uint32 old_offset = idt[PF_NUM].offset_h << 16 | idt[PF_NUM].offset_l;
    uint16 old_segment = idt[PF_NUM].seg_sel;

    uint32 new_offset = 0;
    uint16 new_segment = 0;

    printf("MY PF counter: %d\n", incr);

    /* Get offset and segment to put into IDT */
    __asm {
    mov edx, offset pf_handler
    mov new_offset, edx
    mov ax, seg pf_handler
    mov new_segment, ax
    }

    /* Replace default handler with our handler */
    idt_set_gate(idt, PF_NUM, new_offset, new_segment, idt[PF_NUM].flags);

    printf("Memory %d\n", *PF_ADDR);       /* To recover page */
    printf("Memory %d\n", *(PF_ADDR + 4)); /* Not to see any page fault */

    printf("PF counter: %d\n", incr);
    ((PPTE) my_ptr)->raw &= PTE_NOT_PRESENT;
    printf("Memory %d\n", *(PF_ADDR + 9)); /* To see default page fault */
}

void main() {
    SYSINFO sysinfo;
    printf("Getting system info...\n");
    get_sysinfo(&sysinfo);
    printf("Creating page table...\n");
    page_table_create();
    printf("Generating page fault...\n");
    pf_test(&sysinfo);
}
