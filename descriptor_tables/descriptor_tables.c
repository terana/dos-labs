#include "stdio.h"
#include "stdlib.h"

typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned short int uint16;

#define CR0_PE 0x1 /* Protected mode Enabled bit of CR0 */
#define CR0_PG (1<<31) /* Paging on bit of CR0: 0x80000000 */

#define BASE_FROM_DESCRIPTOR(x) ((x->segment_descriptor.base_low) | (x->segment_descriptor.base_mid << 16) | (x->segment_descriptor.base_high << 24))
#define LIMIT_FROM_DESCRIPTOR(x) (((x->segment_descriptor.limit_low) | (x->segment_descriptor.limit_high << 16)) << (x->segment_descriptor.g ? 12 : 0))
#define OFFSET_FROM_DESCRIPTOR(x) ((x->interrupt_gate_descriptor.offset_lo) | (x->interrupt_gate_descriptor.offset_hi << 16))

#define IS_TASK_GATE(x) (x->task_gate_descriptor.tg_type == 5)
#define IS_INTERRUPT_GATE(x) ((x->interrupt_gate_descriptor.ig_type == 6) || (x->interrupt_gate_descriptor.ig_type == 14))
#define IS_TRAP_GATE(x) ((x->trap_gate_descriptor.trg_type == 7) || (x->trap_gate_descriptor.trg_type == 15))
#define GATE_SIZE_FROM_DESCRIPTOR(x) ( ((x->trap_gate_descriptor.trg_type >> 3) == 0) ? 4 : 2)

#pragma pack (push, 1)

typedef struct _DTR {
    uint16 limit;
    uint32 base;
    uint16 padding;
} DTR, *PDTR;

/* Vol3A p.3-10, Figure 3-8 */
typedef union _DESCRIPTOR {
    struct {
        uint32 low;
        uint32 high;
    } raw;

    struct {
        uint16 limit_low;
        uint16 base_low;
        uint8 base_mid;
        union {
            uint8 ar_raw;
            struct {
                uint8 A:1;      /* Accessed bit */
                uint8 type:3;   /* Without accessed bit */
                uint8 s:1;      /* Descriptor type 0 = system, 1 = code or data */
                uint8 dpl:2;    /* Descriptor privilege level */
                uint8 p:1;      /* Segment present */
            };
        };
        uint8 limit_high:4;
        uint8 avl:1;    /* Available for use by system software */
        uint8 l:1;      /* L bit only in 64bit, should be 0 */
        uint8 db:1;     /* Should be set to 0 for 16-bit code and data segments */
        uint8 g:1;      /* Granularity */
        uint8 base_high;
    } segment_descriptor;

/* Vol. 3A p. 6-11, Figure 6-2 IDT Gate Descriptors */
    struct {
        uint16 reserved1;
        uint16 tss_ss;      /* TSS Segment Selector */
        uint8 reserved2;
        uint8 tg_type:5;    /* 00101 */
        uint8 dpl:2;        /* Descriptor Privilege Level */
        uint8 p:1;          /* Segment Present flag */
        uint8 reserved3;
    } task_gate_descriptor;

    struct {
        uint16 offset_lo;
        uint16 ss;          /* Segment Selector */
        uint8 reserved1:5;
        uint8 zeros:3;      /* 000 */
        uint8 ig_type:5;    /* 0D110 */
        uint8 dpl:2;
        uint8 p:1;
        uint16 offset_hi;
    } interrupt_gate_descriptor;

    struct {
        uint16 offset_lo;
        uint16 ss;
        uint8 reserved1:5;
        uint8 zeros:3;
        uint8 trg_type:5;   /* 0D111 */
        uint8 dpl:2;
        uint8 p:1;
        uint16 offset_hi;
    } trap_gate_descriptor;

} DESCRIPTOR, *PDESCRIPTOR;

typedef union _SELECTOR {
    uint16 raw;
    struct {
        uint16 rpl:2;    /* Register Privilege Level */
        uint16 table:1;  /* Table Indicator: 0 = GDT, 1 = LDT */
        uint16 index:13;
    };
} SELECTOR, *PSELECTOR;

/* 7-4 Vol. 3A Figure 7-2. 32-Bit Task-State Segment (TSS) */
typedef struct _TSS {
    uint8 ptl;      /* Previous Task Link */
    uint8 reserved1;
    uint16 esp0;
    uint8 ss0;
    uint8 reserved2;
    uint16 esp1;
    uint8 ss1;
    uint8 reserved3;
    uint16 esp2;
    uint8 ss2;
    uint8 reserved4;
    uint16 cr3;     /* The base physical address of the page directory to be used by the task */
    uint16 eip;
    uint16 eflags;
    uint16 eax;
    uint16 ecx;
    uint16 edx;
    uint16 ebx;
    uint16 esp;
    uint16 ebp;
    uint16 esi;
    uint16 edi;
    uint8 es;
    uint8 reserved5;
    uint8 cs;
    uint8 reserved6;
    uint8 ss;
    uint8 reserved7;
    uint8 ds;
    uint8 reserved8;
    uint8 fs;
    uint8 reserved9;
    uint8 gs;
    uint8 reserved10;
    uint8 ldt_ss;
    uint8 reserved11;
    uint8 T:1;       /* Debug trap flag */
    uint8 reserved12:7;
    uint8 iomba;    /* I/O Map Based address */
} TSS, *PTSS;

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


int main() {
    int i = 0;
    PDESCRIPTOR ldt_desc = NULL;
    PDESCRIPTOR tss_desc = NULL;
    SYSINFO sysinfo;

    printf("Getting system info...\n");
    get_sysinfo(&sysinfo);

    printf("0x%08X - %s, %s \n",
           sysinfo.cr0,
           sysinfo.cr0 & CR0_PE ? "Protected mode" : "Real mode",
           sysinfo.cr0 & CR0_PG ? "Paging on" : "Paging off"
    );

    printf("0x%08X - %s \n",
           (int) sysinfo.cs.raw,
           (sysinfo.cs.rpl == 0) ? "Ring 0" : "Unprivileged :("
    );

    printf("================\n");

    printf("GDTR: base=0x%08X limit=0x%04X \n", sysinfo.gdtr.base, sysinfo.gdtr.limit);
    printf("IDTR: base=0x%08X limit=0x%04X \n", sysinfo.idtr.base, sysinfo.idtr.limit);
    printf("LDT: selector=0x%04X \n", sysinfo.ldt.raw);
    printf("TSS: selector=0x%04X \n", sysinfo.tr.raw);

    printf("================\n");

    printf("Printing GDT Data...\n");
    printf("\t SEL ADDR  --    BASE    --   LIMIT    -- TYPE -- S -- DPL -- PRES -- AVL -- L -- DB -- G\n");
    for (i = 0; i * 8 < sysinfo.gdtr.limit; i++) {
        PDESCRIPTOR descriptor = (PDESCRIPTOR) (sysinfo.gdtr.base + i * 8);
        printf("\t0x%p -- 0x%p -- 0x%p --  %02d  -- %d --  %d  --   %d  --  %d  -- %d --  %d -- %d\n",
                descriptor,
                BASE_FROM_DESCRIPTOR(descriptor),
                LIMIT_FROM_DESCRIPTOR(descriptor),
                descriptor->segment_descriptor.type,
                descriptor->segment_descriptor.s,
                descriptor->segment_descriptor.dpl,
                descriptor->segment_descriptor.p,
                descriptor->segment_descriptor.avl,
                descriptor->segment_descriptor.l,
                descriptor->segment_descriptor.db,
                descriptor->segment_descriptor.g);
    }


    printf("Printing IDT Data...\n");
    printf("\t SEL ADDR  --    BASE    --   LIMIT    -- TYPE -- S -- DPL -- PRES -- AVL -- L -- DB -- G\n");
    for (i = 0; i * 8 < sysinfo.idtr.limit; i++) {
        PDESCRIPTOR descriptor = (PDESCRIPTOR) (sysinfo.idtr.base + i * 8);

        if (IS_TASK_GATE(descriptor)) {
            printf("\t0x%p -- TASK GATE -- TSS_SS: 0x%x -- P: %d -- DPL: %d\n",
                    descriptor,
                    descriptor->task_gate_descriptor.tss_ss,
                    descriptor->task_gate_descriptor.p,
                    descriptor->task_gate_descriptor.dpl);

        } else if (IS_INTERRUPT_GATE(descriptor)) {
            printf("\t0x%p -- INPT GATE --     SS: 0x%x -- P: %d -- DPL: %d -- OFF: 0x%x -- GATE SIZE: %d\n",
                    descriptor,
                    descriptor->interrupt_gate_descriptor.ss,
                    descriptor->interrupt_gate_descriptor.p,
                    descriptor->interrupt_gate_descriptor.dpl,
                    OFFSET_FROM_DESCRIPTOR(descriptor),
                    GATE_SIZE_FROM_DESCRIPTOR(descriptor));

        } else if (IS_TRAP_GATE(descriptor)) {
            printf("\t0x%p -- TRAP GATE --     SS: 0x%x -- P: %d -- DPL: %d -- OFF: 0x%x -- GATE SIZE: %d\n",
                    descriptor,
                    descriptor->trap_gate_descriptor.ss,
                    descriptor->trap_gate_descriptor.p,
                    descriptor->trap_gate_descriptor.dpl,
                    OFFSET_FROM_DESCRIPTOR(descriptor),
                    GATE_SIZE_FROM_DESCRIPTOR(descriptor));

        } else {
            printf("\t0x%p -- OOPS: UNEXPECTED GATE --\n");
        }
    }


    printf("Printing LDT data...\n");
    printf("\tLDT selector: Index: 0x%x, TI: %x, RPL: %x\n", sysinfo.ldt.index, sysinfo.ldt.table,
            sysinfo.ldt.rpl);
    ldt_desc = (PDESCRIPTOR) (sysinfo.gdtr.base + sysinfo.ldt.index * 8);
    printf("\t SEL ADDR  --    BASE    --   LIMIT    -- TYPE -- S -- DPL -- PRES -- AVL -- L -- DB -- G\n");
    printf("\t0x%p -- 0x%p -- 0x%p --  %02d  -- %d --  %d  --   %d  --  %d  -- %d --  %d -- %d\n",
            ldt_desc,
            BASE_FROM_DESCRIPTOR(ldt_desc),
            LIMIT_FROM_DESCRIPTOR(ldt_desc),
            ldt_desc->segment_descriptor.type,
            ldt_desc->segment_descriptor.s,
            ldt_desc->segment_descriptor.dpl,
            ldt_desc->segment_descriptor.p,
            ldt_desc->segment_descriptor.avl,
            ldt_desc->segment_descriptor.l,
            ldt_desc->segment_descriptor.db,
            ldt_desc->segment_descriptor.g);

    printf("\tLDT actual content:\n");
    for (i = 0; i * 8 < LIMIT_FROM_DESCRIPTOR(ldt_desc); i++) {
        PDESCRIPTOR descriptor = (PDESCRIPTOR) (BASE_FROM_DESCRIPTOR(ldt_desc) + i * 8);
        printf("\t0x%p -- 0x%p -- 0x%p --  %02d  -- %d --  %d  --   %d  --  %d  -- %d --  %d -- %d\n",
                descriptor,
                BASE_FROM_DESCRIPTOR(descriptor),
                LIMIT_FROM_DESCRIPTOR(descriptor),
                descriptor->segment_descriptor.type,
                descriptor->segment_descriptor.s,
                descriptor->segment_descriptor.dpl,
                descriptor->segment_descriptor.p,
                descriptor->segment_descriptor.avl,
                descriptor->segment_descriptor.l,
                descriptor->segment_descriptor.db,
                descriptor->segment_descriptor.g);
    }


    printf("Printing TSS data...\n");
    printf("\tTSS selector: Index: 0x%x, TI: %x, RPL: %x\n", sysinfo.tr.index, sysinfo.tr.table, sysinfo.tr.rpl);

    if (sysinfo.tr.table == 1) {
        tss_desc = (PDESCRIPTOR) (BASE_FROM_DESCRIPTOR(ldt_desc) + sysinfo.tr.index * 8);

    } else {
        tss_desc = (PDESCRIPTOR) (sysinfo.gdtr.base + sysinfo.tr.index * 8);
    }

    printf("\t SEL ADDR  --    BASE    --   LIMIT    -- TYPE -- S -- DPL -- PRES -- AVL -- L -- DB -- G\n");
    printf("\t0x%p -- 0x%p -- 0x%p --  %02d  -- %d --  %d  --   %d  --  %d  -- %d --  %d -- %d\n",
            tss_desc,
            BASE_FROM_DESCRIPTOR(tss_desc),
            LIMIT_FROM_DESCRIPTOR(tss_desc),
            tss_desc->segment_descriptor.type,
            tss_desc->segment_descriptor.s,
            tss_desc->segment_descriptor.dpl,
            tss_desc->segment_descriptor.p,
            tss_desc->segment_descriptor.avl,
            tss_desc->segment_descriptor.l,
            tss_desc->segment_descriptor.db,
            tss_desc->segment_descriptor.g);

    if (LIMIT_FROM_DESCRIPTOR(tss_desc) == 0) {
        printf("\tNo TSS for you today.\n");

    } else {
        uint8 *memory = malloc(LIMIT_FROM_DESCRIPTOR(tss_desc) + 1);

        for (i = 0; i < LIMIT_FROM_DESCRIPTOR(tss_desc); i++)
            memory[i] = *((uint8 *) BASE_FROM_DESCRIPTOR(tss_desc) + i);

        for (i = 0; i * sizeof(TSS) < LIMIT_FROM_DESCRIPTOR(tss_desc); i++) {
            PTSS tss = ((PTSS) BASE_FROM_DESCRIPTOR(tss_desc) + i);
            printf("============TSS # %i ==============\n", i);
            printf("\tPrevious task link: 0x%x\n", tss->ptl);
            printf("\tESP0: 0x%x, SS0: 0x%x\n", tss->esp0, tss->ss0);
            printf("\tESP1: 0x%x, SS1: 0x%x\n", tss->esp1, tss->ss1);
            printf("\tESP2: 0x%x, SS2: 0x%x\n", tss->esp2, tss->ss2);
            printf("\tCR3:  0x%x, EIP: 0x%x\n", tss->cr3, tss->eip);
            printf("\tEFLAGS: 0x%x\n", tss->eflags);
            printf("\tEAX:  0x%x, ECX: 0x%x\n", tss->eax, tss->ecx);
            printf("\tEDX:  0x%x, EBX: 0x%x\n", tss->edx, tss->ebx);
            printf("\tESP:  0x%x, EBP: 0x%x\n", tss->esp, tss->ebp);
            printf("\tESI:  0x%x, EDI: 0x%x\n", tss->esi, tss->edi);
            printf("\tES:   0x%x, CS:  0x%x\n", tss->es, tss->cs);
            printf("\tSS:   0x%x, DS:  0x%x\n", tss->ss, tss->ds);
            printf("\tFS:   0x%x, GS:  0x%x\n", tss->fs, tss->gs);
            printf("\tLDT SS: 0x%x, T: 0x%x\n", tss->ldt_ss, tss->T);
            printf("\tI/O Map Base Address: 0x%x", tss->iomba);
        }
        free(memory);
    }

}
