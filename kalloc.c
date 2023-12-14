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
 } framedesc;

struct {
    struct spinlock lock;
    struct framedesc *framedescs;
    char *frames;
    uint64 NUMFRAMES;
    uint64 freeframes;
} kmem;

typedef struct page { //radi lakse manipulacije pokazivacima na okvire
    char pagemem[PGSIZE];
} page;

void
kinit()
{
  initlock(&kmem.lock, "kmem");
  kmem.NUMFRAMES = ((uint64)PHYSTOP - (uint64)end) / (sizeof(framedesc) + PGSIZE); //maksimalan broj okvira
  kmem.frames = (char*)((char*)end + sizeof(framedesc) * kmem.NUMFRAMES);
  kmem.frames = (char*)PGROUNDUP((uint64)kmem.frames); //mora da bude umnozak PGSIZE
  if(((uint64)PHYSTOP - (uint64)kmem.frames) / PGSIZE < (uint64)kmem.NUMFRAMES) { //ako ima jedan okvir manje zbog zaokruzivanja
      kmem.NUMFRAMES--;
  }
  kmem.freeframes = 0;
  kmem.framedescs = (framedesc*)end;
  freerange((void*)kmem.frames, (void*)PHYSTOP);
}

uchar*
getframeaddr(framedesc* desc) {
    uint index = desc - kmem.framedescs;
    uchar* frameaddr = (uchar*)((char*)kmem.frames + index * PGSIZE);
    return frameaddr;
}

void
freerange(void *pa_start, void *pa_end) //prosledjuje se pokazivac na okvir
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
  kmem.framedescs[index].pte = 0; //okvir slobodan
  kmem.framedescs[index].referencebits = 0;
  release(&kmem.lock);
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
      if(ret == -1)
          return 0; //nema mesta na disku
      acquire(&kmem.lock);
      victim->pte = (uint64*)1; //samo da se oznaci da je okvir zauzet
      r = (char*)getframeaddr(victim);
  }
  else {
      for(uint64 i = 0; i < kmem.NUMFRAMES; i++) {
          if(!kmem.framedescs[i].pte) {
              r = (char*)kmem.frames + i * PGSIZE;
              kmem.framedescs[i].pte = (uint64*)1; //samo da se oznaci da je okvir zauzet
              kmem.freeframes--;
              break;
          }
      }
  }
  release(&kmem.lock);

  if(r)
    memset((char*)r, 5, PGSIZE); // fill with junk

  return (void*)r;
}

framedesc*
choosevictimframe()
{
    uint8 min = 0xff;
    framedesc *victim = 0;
    framedesc* reserve = 0; // ako se desi da su sve ff
    for(uint64 i = 0; i < kmem.NUMFRAMES; i++) {
        if(kmem.framedescs[i].pte && kmem.framedescs[i].pte != (uint64*)1) {
            if(*(kmem.framedescs[i].pte) & PTE_U) { //samo korisnicke stranice se izbacuju
                if(!(*(kmem.framedescs[i].pte) & PTE_D)) { //samo ako je u memoriji i nije init
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
    int block = getfreeblocknum();
    if(block == -1) {
        sfence_vma();
        return block;
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
        write_block(block, data, 0);
        block++;
    }
    sfence_vma(); //TLB se cisti jer vise nije validan OPTIMIZOVATI!!!
    return 0;
}

void
loadpage(framedesc* desc, uint64* pte)
{
    int block = (*pte) >> 10;
    uchar data[1024];
    uchar* frameaddr = getframeaddr(desc);
    uint64 frame = (uint64)frameaddr; //cuvamo da bismo upisali u pte
    for(int i = 0; i < 4; i++) {
        read_block(block, data, 1); //ovde se radi busy wait zbog fork-a
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
    if(!pte) return -1; //nije pronasao ulaz
    if((*pte & PTE_V) != 0 || (*pte & PTE_D) == 0) return -1; //nije u pitanju izbacena stranica
    //OBRADITI GRESKE!!!
    return handleEvictedPage(pte);
}

void
setPtePointer(uint64* pte, uint64* frame) {
    uint index = (page*)frame - (page*)kmem.frames;
    acquire(&kmem.lock);
    //printf("ind: %d ", index);
    //printf("pte*: %d ", (uint64)pte);
    //printf("pte: %d ", *pte);
    kmem.framedescs[index].pte = pte; //postavljanje pokazivaca na pte
    release(&kmem.lock);
}

void
updatereferencebits()
{
    for(uint64 i = 0; i < kmem.NUMFRAMES; i++) {
        if(kmem.framedescs[i].pte && kmem.framedescs[i].pte != (uint64*)1) {
            if (*(kmem.framedescs[i].pte) & PTE_U) { //samo korisnicke stranice se apdejtuju
                if (!(*(kmem.framedescs[i].pte) & PTE_D)) { //samo ako je u memoriji
                    kmem.framedescs[i].referencebits >>= 1;
                    if ((*(kmem.framedescs[i].pte) & PTE_A)) { // ako je stranici pristupano
                        kmem.framedescs[i].referencebits |= (1 << 7);
                    }
                }
            }
        }
    }
}

int
handleEvictedPage(uint64* pte) {
    framedesc* victim;
    acquire(&kmem.lock); //mora sinhronizacija jer se zove iz sistemskog poziva
    if(kmem.freeframes == 0) { //ako nema okvira, bira se zrtva
        victim = choosevictimframe();
        release(&kmem.lock);
        int ret = evictpage(victim);
        if(ret == -1) {
            return ret; //nema mesta na disku, proces treba da se ugasi
        }
    }
    else {
        release(&kmem.lock);
        uint64 newframe = (uint64)kalloc();
        uint64 index = (newframe - (uint64)kmem.frames) / PGSIZE;
        victim = &kmem.framedescs[index];
    }
    loadpage(victim, pte);
    victim->pte = pte;
    return 0;
}