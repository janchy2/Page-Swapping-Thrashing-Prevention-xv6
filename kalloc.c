// Physical memory allocator, for user processes,
// kernel stacks, page-table pages,
// and pipe buffers. Allocates whole 4096-byte pages.

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "riscv.h"
#include "defs.h"
#include "proc.h"

void freerange(void *pa_start, void *pa_end);

extern char end[]; // first address after kernel.
                   // defined by kernel.ld.

typedef struct framedesc {
    uint64 *pte;
    uint8 referencebits;
    uint8 isfree;
} framedesc;

struct {
    struct spinlock lock;
    struct framedesc *framedescs;
    char *frames;
    uint64 NUMFRAMES;
    uint64 freeframes;
} kmem;


void
kinit()
{
    initlock(&kmem.lock, "kmem");
    kmem.NUMFRAMES = ((uint64)PHYSTOP - (uint64)end + 1) / (sizeof(framedesc) + PGSIZE); //maksimalan broj okvira
    kmem.frames = (char*)((char*)end + sizeof(framedesc) * kmem.NUMFRAMES);
    kmem.frames = (char*)PGROUNDUP((uint64)kmem.frames); //mora da bude umnozak PGSIZE
    if(((uint64)PHYSTOP - (uint64)kmem.frames) / PGSIZE < (uint64)kmem.NUMFRAMES) { //ako ima jedan okvir manje zbog zaokruzivanja
        kmem.NUMFRAMES--;
    }
    kmem.freeframes = 0;
    kmem.framedescs = (framedesc*)end;
    freerange((void*)kmem.frames, (void*)PHYSTOP);
}

void
freerange(void *pa_start, void *pa_end)
{
  char *p;
  p = (char*)PGROUNDUP((uint64)pa_start);
  for(; p + PGSIZE <= (char*)pa_end; p += PGSIZE)
    kfree(p);
}

// Free the page of physical memory pointed at by pa,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(void *pa)
{
    if(((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
        panic("kfree");

    // Fill with junk to catch dangling refs.
    memset(pa, 1, PGSIZE);

    uint64 index = ((uint64)pa - (uint64)kmem.frames) / PGSIZE;

    acquire(&kmem.lock);
    kmem.freeframes++;
    kmem.framedescs[index].pte = 0;
    kmem.framedescs[index].referencebits = 0;
    kmem.framedescs[index].isfree = 1;
    release(&kmem.lock);
}

char*
getframeaddr(framedesc* desc) {
    uint index = desc - kmem.framedescs;
    char* frameaddr = (char*)kmem.frames + index * PGSIZE;
    return frameaddr;
}

void
removeptepointer(uint64 pa) {
	uint64 index = ((uint64)pa - (uint64)kmem.frames) / PGSIZE;
	kmem.framedescs[index].pte = 0;
}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
void *
kalloc(void)
{

    char* r = 0;
    acquire(&kmem.lock);
    if(kmem.freeframes == 0) { //ako nema slobodnih okvira
        framedesc* victim = choosevictimframe();
        release(&kmem.lock);
        int ret = evictpage(victim); //mora da se oslobodi brava
        if(ret == -1) {
            return 0; //nema mesta na disku
        }
        acquire(&kmem.lock);
        victim->isfree = 0;//okvir zauzet
        victim->pte = 0;
        r = getframeaddr(victim);
        release(&kmem.lock);
    }
    else {
        for(uint64 i = 0; i < kmem.NUMFRAMES; i++) {
            if(kmem.framedescs[i].isfree) {
                r = (char*)kmem.frames + i * PGSIZE;
                kmem.framedescs[i].isfree = 0;
                kmem.freeframes--;
                break;
            }
        }
        release(&kmem.lock);
    }

    if(r)
        memset((char*)r, 5, PGSIZE); // fill with junk

    return (void*)r;
}

void
setptepointer(uint64* pte, uint64* frame) {
    uint64 index = ((uint64)frame - (uint64)kmem.frames) / PGSIZE;
    acquire(&kmem.lock);
    kmem.framedescs[index].pte = pte; //postavljanje pokazivaca na pte
    release(&kmem.lock);
}

framedesc*
choosevictimframe()
{
    uint8 min = 0xff;
    framedesc *victim = 0;
    framedesc* reserve = 0; // ako se desi da su sve ff
    for(uint64 i = 0; i < kmem.NUMFRAMES; i++) {
        if(kmem.framedescs[i].pte && !kmem.framedescs[i].isfree) {
            if(*(kmem.framedescs[i].pte) & PTE_U && *(kmem.framedescs[i].pte) & PTE_V) { //samo korisnicke stranice se izbacuju
                if(!(*(kmem.framedescs[i].pte) & PTE_D)) { //samo ako je u memoriji
                    reserve = &kmem.framedescs[i];
                    if (kmem.framedescs[i].referencebits < min) {
                        victim = &kmem.framedescs[i];
                        min = kmem.framedescs[i].referencebits;
                    }
                }
            }
        }
    }
    if(!victim) victim = reserve;
    *(victim->pte) |= PTE_D; //postavimo da je izbacena (ne moze neki drugi proces da je izabere u medjuvremenu)
    *(victim->pte) &= ~PTE_V; //nije validna
    return victim;
}

int
evictpage(framedesc* desc)
{
    uint32 block = getfreeblocknum();
    if(block == 0xffffffff) {
        *(desc->pte) &= ~PTE_D; //nije izbacena
        *(desc->pte) |= PTE_V; //validna
        return -1;
    }

    uint64 pa = PTE2PA(*(desc->pte));
    uint64 mask = ~(0xffffffffff << 10); //mora da se ukloni fizicka adresa okvira iz pte
    *(desc->pte) &= mask;
    *(desc->pte) |= (block << 10); //umesto fizicke adrese je upisan broj bloka
    desc->referencebits = 0x80; //resetuje se jer ce nova stranica da se mapira u njega
    //80 da ne bi odmah bila izbacena ponovo
    uchar data[1024];
    uchar* frameaddr = (uchar*)pa;
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 1024; j++) {
            data[j] = *frameaddr; //sadrzaj okvira se upisuje u bafer
            frameaddr++;
        }
        write_block(block, (uchar*)data, 1);
        block++;
    }
    sfence_vma();
    return 0;
}


void
loadpage(framedesc* desc, uint64* pte)
{
    uint32 block = (*pte) >> 10;
    uchar data[1024];
    uchar* frameaddr = (uchar*)getframeaddr(desc);
    uint64 frame = (uint64)frameaddr; //cuvamo da bismo upisali u pte
    for(int i = 0; i < 4; i++) {
        read_block(block, (uchar*)data, 1);
        for(int j = 0; j < 1024; j++) {
            *frameaddr = data[j]; //sadrzaj okvira se upisuje u bafer
            frameaddr++;
        }
        block++;
    }
    uint64 flags = PTE_FLAGS(*pte);
    *pte = (PA2PTE(frame) | flags | PTE_V) & ~PTE_D; //ostave se isti flagovi samo se postavi V i skloni se D
    //sfence_vma();
}


int
handlepagefault(uint64 va)
{
    pagetable_t pagetable = myproc()->pagetable;
    uint64* pte = walk(pagetable, va, 0);
    if(pte == 0) return -1; //greska
    if((*pte & PTE_V) || !(*pte & PTE_D)) return -1; //nije u pitanju izbacena stranica
    if(!(*pte & PTE_U) && (*pte & PTE_D)) //dinamicko ucitavanje
    	return loadonrequest(pte);
    return handleevictedpage(pte);
}

void
updatereferencebits()
{
    for(uint64 i = 0; i < kmem.NUMFRAMES; i++) {
        if(kmem.framedescs[i].pte && !kmem.framedescs[i].isfree) {
            if (*(kmem.framedescs[i].pte) & PTE_U) { //samo korisnicke stranice se apdejtuju
                if (!(*(kmem.framedescs[i].pte) & PTE_D)) { //samo ako je u memoriji
                    kmem.framedescs[i].referencebits >>= 1;
                    if ((*(kmem.framedescs[i].pte) & PTE_A)) { // ako je stranici pristupano
                        kmem.framedescs[i].referencebits |= (1 << 7);
                        *(kmem.framedescs[i].pte) &= ~PTE_A;
                    }
                }
            }
        }
    }
}

int
handleevictedpage(uint64* pte) {

    framedesc* victim;
    uint64 newframe = (uint64)kalloc();
    uint64 index = (newframe - (uint64)kmem.frames) / PGSIZE;
    victim = &kmem.framedescs[index];
    loadpage(victim, pte);
    acquire(&kmem.lock);
    victim->pte = pte;
    victim->referencebits = 0x80;
    release(&kmem.lock);

    return 0;
}

int
loadonrequest(uint64* pte) {
	char* mem = kalloc();
	if(mem == 0) return -1;
	*pte |= PA2PTE(mem) | PTE_U | PTE_V;
	*pte &= ~PTE_D;
	setptepointer(pte, (uint64*)mem);
	return 0;
}

int
checkthrashing() {
    int numofaccessed = 0;
    for(uint64 i = 0; i < kmem.NUMFRAMES; i++) {
        if(kmem.framedescs[i].pte && !kmem.framedescs[i].isfree) {
            if (*(kmem.framedescs[i].pte) & PTE_U) { //samo korisnicke stranice se apdejtuju
                if (!(*(kmem.framedescs[i].pte) & PTE_D)) { //samo ako je u memoriji
                    kmem.framedescs[i].referencebits >>= 1;
                    if ((*(kmem.framedescs[i].pte) & PTE_A)) { // ako je stranici pristupano
                        numofaccessed++;
                        //*(kmem.framedescs[i].pte) &= ~PTE_A;
                    }
                }
            }
        }
    }
    if(numofaccessed > kmem.NUMFRAMES) return 1;
    return 0;
}
