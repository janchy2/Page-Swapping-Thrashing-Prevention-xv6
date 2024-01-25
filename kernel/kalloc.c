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

void freerange(void* pa_start, void* pa_end);

extern char end[]; // first address after kernel.
                   // defined by kernel.ld.

typedef struct framedesc {
    uint64* pte;
    uint16 referencebits;
    uint8 isfree;
    uint64 va; //sluzi za optimalniji flush TLB-a
    uint64 numofshared; //koliko procesa deli stranicu
} framedesc;

struct {
    struct spinlock lock;
    struct framedesc* framedescs;
    char* frames;
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
    if (((uint64)PHYSTOP - (uint64)kmem.frames) / PGSIZE < (uint64)kmem.NUMFRAMES) { //ako ima jedan okvir manje zbog zaokruzivanja
        kmem.NUMFRAMES--;
    }
    kmem.freeframes = 0;
    kmem.framedescs = (framedesc*)end;
    freerange((void*)kmem.frames, (void*)PHYSTOP);
}

void
freerange(void* pa_start, void* pa_end)
{
    char* p;
    p = (char*)PGROUNDUP((uint64)pa_start);
    for (; p + PGSIZE <= (char*)pa_end; p += PGSIZE)
        kfree(p);
}

// Free the page of physical memory pointed at by pa,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(void* pa)
{
    if (((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
        panic("kfree");

    // Fill with junk to catch dangling refs.
    memset(pa, 1, PGSIZE);

    uint64 index = ((uint64)pa - (uint64)kmem.frames) / PGSIZE;

    acquire(&kmem.lock);
    kmem.freeframes++;
    kmem.framedescs[index].pte = 0;
    kmem.framedescs[index].referencebits = 0;
    kmem.framedescs[index].isfree = 1;
    kmem.framedescs[index].numofshared = 0;
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
    acquire(&kmem.lock);
    uint64 index = ((uint64)pa - (uint64)kmem.frames) / PGSIZE;
    kmem.framedescs[index].pte = 0;
    release(&kmem.lock);
}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
void*
kalloc(void)
{

    char* r = 0;
    acquire(&kmem.lock);
    if (kmem.freeframes == 0) { //ako nema slobodnih okvira
        framedesc* victim = choosevictimframe();
        if (!victim) {
            release(&kmem.lock);
            return 0;
        }
        release(&kmem.lock);
        int ret = evictpage(victim); //mora da se oslobodi brava
        if (ret == -1) {
            return 0; //nema mesta na disku
        }
        acquire(&kmem.lock);
        victim->isfree = 0;//okvir zauzet
        victim->pte = 0;
        r = getframeaddr(victim);
        release(&kmem.lock);
    }
    else {
        for (uint64 i = 0; i < kmem.NUMFRAMES; i++) {
            if (kmem.framedescs[i].isfree) {
                r = (char*)kmem.frames + i * PGSIZE;
                kmem.framedescs[i].isfree = 0;
                kmem.framedescs[i].numofshared = 1;
                kmem.freeframes--;
                break;
            }
        }
        release(&kmem.lock);
    }

    if (r)
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

void
setvirtualaddress(uint64 va, uint64* frame) {
    uint64 index = ((uint64)frame - (uint64)kmem.frames) / PGSIZE;
    acquire(&kmem.lock);
    kmem.framedescs[index].va = va; //postavljanje virtuelne adrese
    release(&kmem.lock);
}

framedesc*
choosevictimframe()
{
    uint16 min = 0xffff;
    framedesc* victim = 0;
    framedesc* reserve = 0; // ako se desi da su sve ffff
    for (uint64 i = 0; i < kmem.NUMFRAMES; i++) {
        if (kmem.framedescs[i].pte && !kmem.framedescs[i].isfree) {
            if (*(kmem.framedescs[i].pte) & PTE_U && *(kmem.framedescs[i].pte) & PTE_V) { //samo korisnicke stranice se izbacuju
                if (!(*(kmem.framedescs[i].pte) & PTE_D) && !(*(kmem.framedescs[i].pte) & PTE_C)) { //samo ako je u memoriji
                    reserve = &kmem.framedescs[i];
                    if (kmem.framedescs[i].referencebits < min) {
                        victim = &kmem.framedescs[i];
                        min = kmem.framedescs[i].referencebits;
                    }
                }
            }
        }
    }
    if (!victim) victim = reserve;
    if (!victim) return 0;
    *(victim->pte) |= PTE_D; //postavimo da je izbacena (ne moze neki drugi proces da je izabere u medjuvremenu)
    *(victim->pte) &= ~PTE_V; //nije validna
    return victim;
}

int
evictpage(framedesc* desc)
{
    uint32 block = getfreeblocknum();
    uint64 pa = PTE2PA(*(desc->pte));
    if (block == 0xffffffff || ((pa % PGSIZE) != 0 || (char*)pa < end || pa >= PHYSTOP)) {
        *(desc->pte) &= ~PTE_D; //nije izbacena
        *(desc->pte) |= PTE_V; //validna
        return -1;
    }

    uint64 mask = ~(0xffffffffff << 10); //mora da se ukloni fizicka adresa okvira iz pte
    *(desc->pte) &= mask;
    *(desc->pte) |= (block << 10); //umesto fizicke adrese je upisan broj bloka
    desc->referencebits = 0x8000; //resetuje se jer ce nova stranica da se mapira u njega
    //8000 da ne bi odmah bila izbacena ponovo
    uchar data[1024];
    uchar* frameaddr = (uchar*)pa;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 1024; j++) {
            data[j] = *frameaddr; //sadrzaj okvira se upisuje u bafer
            frameaddr++;
        }
        if (isfork()) //ako je fork mora busywait
            write_block(block, (uchar*)data, 1);
        else
            write_block(block, (uchar*)data, 0);
        block++;
    }
    sfence_specific(desc->va); //uklanja TLB ulaze samo za datu virtuelnu adresu
    return 0;
}


void
loadpage(framedesc* desc, uint64* pte)
{
    uint32 block = (*pte) >> 10;
    uchar data[1024];
    uchar* frameaddr = (uchar*)getframeaddr(desc);
    uint64 frame = (uint64)frameaddr; //cuvamo da bismo upisali u pte
    for (int i = 0; i < 4; i++) {
        if (isfork()) //ako je fork mora busywait
            read_block(block, (uchar*)data, 1);
        else
            read_block(block, (uchar*)data, 0);
        for (int j = 0; j < 1024; j++) {
            *frameaddr = data[j]; //sadrzaj okvira se upisuje u bafer
            frameaddr++;
        }
        block++;
    }
    uint64 flags = PTE_FLAGS(*pte);
    *pte = (PA2PTE(frame) | flags | PTE_V) & ~PTE_D; //ostave se isti flagovi samo se postavi V i skloni se D
}


int
handlepagefault(uint64 va)
{
    pagetable_t pagetable = myproc()->pagetable;
    uint64* pte = walk(pagetable, va, 0);
    if (pte == 0) return -1; //greska
    if ((*pte & PTE_V) && !(*pte & PTE_C)) return -1; //greska
    if (!(*pte & PTE_D)) return -1; //greska
    if (!(*pte & PTE_U) && (*pte & PTE_D)) //dinamicko ucitavanje
        return loadonrequest(pte, va);
    if ((*pte & PTE_C) && !(*pte & PTE_W)) //copy on write
        return copyonwrite(pte, va);
    return handleevictedpage(pte, va); //izbacena stranica
}

void
updatereferencebits()
{
    for (uint64 i = 0; i < kmem.NUMFRAMES; i++) {
        if (kmem.framedescs[i].pte && !kmem.framedescs[i].isfree) {
            if (*(kmem.framedescs[i].pte) & PTE_U) { //samo korisnicke stranice se apdejtuju
                if (!(*(kmem.framedescs[i].pte) & PTE_D)) { //samo ako je u memoriji
                    kmem.framedescs[i].referencebits >>= 1;
                    if ((*(kmem.framedescs[i].pte) & PTE_A)) { // ako je stranici pristupano
                        kmem.framedescs[i].referencebits |= (1 << 15);
                        *(kmem.framedescs[i].pte) &= ~PTE_A;
                    }
                }
            }
        }
    }
}

int
handleevictedpage(uint64* pte, uint64 va) {

    framedesc* victim;
    uint64 newframe = (uint64)kalloc();
    if (!newframe) return -1;
    uint64 index = (newframe - (uint64)kmem.frames) / PGSIZE;
    victim = &kmem.framedescs[index];
    loadpage(victim, pte);
    acquire(&kmem.lock);
    victim->pte = pte;
    victim->referencebits = 0x8000;
    victim->va = va;
    victim->numofshared = 1;
    release(&kmem.lock);

    return 0;
}

int
loadonrequest(uint64* pte, uint64 va) {
    char* mem = kalloc();
    if (mem == 0) return -1;
    *pte |= PA2PTE(mem) | PTE_U | PTE_V;
    *pte &= ~PTE_D;
    setptepointer(pte, (uint64*)mem);
    setvirtualaddress(va, (uint64*)mem);
    return 0;
}

int
checkthrashing() {
    int numofaccessed = 0;
    for (uint64 i = 0; i < kmem.NUMFRAMES; i++) {
        if (kmem.framedescs[i].pte && !kmem.framedescs[i].isfree) {
            if (*(kmem.framedescs[i].pte) & PTE_U) { //samo korisnicke stranice se apdejtuju
                if (!(*(kmem.framedescs[i].pte) & PTE_D)) { //samo ako je u memoriji
                    if ((*(kmem.framedescs[i].pte) & PTE_A)) { // ako je stranici pristupano
                        numofaccessed++;
                    }
                    else if (kmem.framedescs[i].referencebits & 0xffff) {
                        //ako je stranici uopste pristupano u poslednjih sesnaest update perioda
                        numofaccessed++;
                    }
                }
            }
        }
    }

    if (numofaccessed > kmem.NUMFRAMES) return 1;
    return 0;
}

int
hasptepointer(uint64 pa) {
    acquire(&kmem.lock);
    uint64 index = (pa - (uint64)kmem.frames) / PGSIZE;
    if (kmem.framedescs[index].pte) {
        release(&kmem.lock);
        return 1;
    }
    release(&kmem.lock);
    return 0;
}

void
evictallpages(pagetable_t pagetable, uint64 sz) {
    if (sz == 0) return;
    uint64 npages = PGROUNDUP(sz) / PGSIZE;
    uint64 a = 0;
    uint64* pte;

    for (; a < npages * PGSIZE; a += PGSIZE) {
        pte = walk(pagetable, a, 0);
        if (!pte) continue;
        if ((*pte & PTE_V) && (*pte & PTE_U) && !(*pte & PTE_D)) {
            uint64 pa = PTE2PA(*pte);
            uint64 index = (pa - (uint64)kmem.frames) / PGSIZE;
            acquire(&kmem.lock);
            if (kmem.framedescs[index].pte) { //samo ako stranica moze da se izbacuje
                setisfork(1); //ne treba da se desava promena konteksta
                *pte |= PTE_D;
                *pte &= ~PTE_V;
                release(&kmem.lock);
                int ret = evictpage(&kmem.framedescs[index]);
                acquire(&kmem.lock);
                setisfork(0);
                if (ret == -1) { //nema mesta na disku, izbaceno je sta je moglo
                    release(&kmem.lock);
                    break;
                }
                kmem.framedescs[index].pte = 0;
                kmem.framedescs[index].isfree = 1;
                kmem.freeframes++;
            }
            release(&kmem.lock);
        }
    }
}

void
incnumofshared(uint64 pa) {
    acquire(&kmem.lock);
    uint64 index = (pa - (uint64)kmem.frames) / PGSIZE;
    kmem.framedescs[index].numofshared++;
    release(&kmem.lock);
}

int
decnumofshared(uint64 pa) {
    acquire(&kmem.lock);
    uint64 index = (pa - (uint64)kmem.frames) / PGSIZE;
    kmem.framedescs[index].numofshared--;
    if (kmem.framedescs[index].numofshared == 1) {
        //samo jedan proces drzi okvir (moze da pokazuje na onaj koji je izazvao pf, tako da ce drugi svakako izazvati jos jedan)
        *(kmem.framedescs[index].pte) |= PTE_W;
        *(kmem.framedescs[index].pte) &= ~PTE_C;
        *(kmem.framedescs[index].pte) &= ~PTE_D;
    }
    release(&kmem.lock);
    return kmem.framedescs[index].numofshared == 0;
}

int
copyonwrite(uint64* pte, uint64 va) {
    uint64 pa = PTE2PA(*pte);
    int num = decnumofshared(pa);
    char* mem;
    if (!num) { //ako nije jedini proces koji drzi okvir
        mem = kalloc();
        if (mem == 0) return -1;
    }
    else mem = (char*)pa;
    uint64 flags = PTE_FLAGS(*pte);
    *pte = PA2PTE(mem) | PTE_W | flags;
    *pte &= ~PTE_C;
    *pte &= ~PTE_D;
    setptepointer(pte, (uint64*)mem);
    setvirtualaddress(va, (uint64*)mem);
    sfence_specific(va);
    return 0;
}
