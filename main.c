#include "pf.h"
#include <sys/mman.h>
#include "common/debug.h"
#include <stdlib.h>
#include "common/hex_dump.c"

asm("    .data\n"
    "    .global a\n"
    "    .align 0x1000   /* 4KiB */\n"
    "a:\n"
    "    .word 0x0\n"
    "    .space 0x06   /* 4KiB */\n"
    "b:\n"
    "    .word 0x0\n"
    "    .space 0x06   /* 4KiB */\n"
    "c:\n"
    "    .word 0x0\n"
    "    .space 0x1000   /* 4KiB */");

//void* a, *b, *c;
void check_var(void*);
extern int a,b,c;

void attack_var(void* var)
{
  // Grant read and write for attacked var
  ASSERT(!mprotect(var, 4096, PROT_WRITE | PROT_READ));

  // Cast to byte array and change random (here first) byte
  ((char*) var)[0] = 0x12;

  // Revoke access again
  ASSERT(!mprotect(var, 4096, PROT_NONE)); // Revoke access again
}

int main() {

//  ASSERT(!posix_memalign(&a, 0x1000, sizeof(int)));
//  ASSERT(!posix_memalign(&b, 0x1000, sizeof(int)));
//  ASSERT(!posix_memalign(&c, 0x1000, sizeof(int)));

//  b = malloc(100* sizeof(int));
//  c = malloc(100 * sizeof(int));
//
//  *(int*) a = 5;
//  *(int*) b = 6;
//  *(int*) c = 7;

  a = 5;
  b = 6;
  c = 7;

  void *p = &a;
  void *pb = &b;
  void *pc = &c;

  register_fault_handler();
  ASSERT(!mprotect(&a, 4096, PROT_NONE)); // Remove access

//  *(int*) a = 0;
//  *(int*) b = 6;
//  *(int*) c = 7;
  a = 0;
  check_var(&a); // var still false

  attack_var(&a); // change in encrypted byte array --> change in decrypted result

  check_var(&a); // var !=0 --> true

  return 0;
}

void check_var(void* var)
{
  int control_var = *((int*) var); // SIGSEGV on read
//  int bb = b;
//  int cc = c;
  if (control_var)
  {
    _GREEN info("Variable was considered TRUE: a=%d", control_var);
  }
  else
  {
    _RED info("Variable was considered FALSE: a=%d", control_var);
  }
//  info("b=%d, c=%d", bb, cc);
  _RESET_COL
}