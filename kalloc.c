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
  for(uint64 i = 0; i < kmem.NUMFRAMES; i++) {
      if(!kmem.framedescs[i].pte) {
          r = (char*)kmem.frames + i * PGSIZE;
          kmem.framedescs[i].pte = (uint64*)1; //samo trenutno
          kmem.freeframes--;
          break;
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
    for(uint64 i = 0; i < kmem.NUMFRAMES; i++) {
        if(*(kmem.framedescs[i].pte) & PTE_U) { //samo korisnicke stranice se izbacuju
            if(!(*(kmem.framedescs[i].pte) & PTE_D)) { //samo ako je u memoriji
                if (kmem.framedescs[i].referencebits < min) {
                    victim = kmem.framedescs + i;
                    min = kmem.framedescs[i].referencebits;
                }
            }
        }
    }
    *(victim->pte) |= PTE_D; //postavimo da je izbacena (ne moze neki drugi proces da je izabere u medjuvremenu)
    *(victim->pte) &= ~PTE_V; //nije validna
    return victim;
}

uchar*
getframeaddr(framedesc* desc) {
    uint64 index = (desc - kmem.framedescs) / sizeof(framedesc);
    uchar* frameaddr = (uchar*)((char*)kmem.frames + index * PGSIZE);
    return frameaddr;
}

void
evictpage(framedesc* desc)
{
    //sinfronizacija?????
    int block = getfreeblocknum();
    uint64 mask = ~(0xffffffffff << 10); //mora da se ukloni fizicka adresa okvira iz pte
    *(desc->pte) &= mask;
    *(desc->pte) |= (block << 10); //umesto fizicke adrese je upisan broj bloka
    desc->referencebits = 0; //resetuje se jer ce nova stranica da se mapira u njega
    uchar data[1024];
    uchar* frameaddr = getframeaddr(desc);
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 1024; j++) {
            data[j] = *frameaddr; //sadrzaj okvira se upisuje u bafer
            frameaddr++;
        }
        write_block(block, data, 0);
        block++;
    }
    sfence_vma(); //TLB se cisti jer vise nije validan OPTIMIZOVATI!!!
}

void
loadpage(framedesc* desc, uint64* pte)
{
    int block = *pte >> 10;
    uchar data[1024];
    uchar* frameaddr = getframeaddr(desc);
    uint64 frame = (uint64)frameaddr; //cuvamo da bismo upisali u pte
    for(int i = 0; i < 4; i++) {
        read_block(block, data, 0);
        for(int j = 0; j < 1024; j++) {
            *frameaddr = data[j]; //sadrzaj okvira se upisuje u bafer
            frameaddr++;
        }
        block++;
    }
    uint64 flags = PTE_FLAGS(*pte);
    *pte = (PA2PTE(frame) | flags | PTE_V) & ~PTE_D; //ostave se isti flagovi samo se postavi V i skloni se D
}

void
handlepagefault(uint64 va)
{
    pagetable_t pagetable = myproc()->pagetable;
    uint64* pte = walk(pagetable, va, 0);
    //OBRADITI GRESKE!!!
    framedesc* victim = choosevictimframe();
    evictpage(victim);
    loadpage(victim, pte);
    victim->pte = pte;

}
