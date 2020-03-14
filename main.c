#include "pf.h"
#include <sys/mman.h>
#include "common/debug.h"
#include <stdlib.h>

//asm("    .data\n"
//    "    .global a\n"
//    "    .align 0x1000   /* 4KiB */\n"
//    "a:\n"
//    "    .word 0x0\n"
//    "    .space 0x1000   /* 4KiB */");

void* a;
void check_var();

int main() {

  ASSERT(!posix_memalign(&a, 0x1000, 4));

  register_fault_handler();
  ASSERT(!mprotect(a, 4096, PROT_NONE)); // Remove access

  *((int*) a) = 0;

  check_var(); // SEGFAULTS

  return 0;
}

void check_var()
{
  int control_var = *((int*) a); // SIGSEGV on read
  if (control_var)
  {
    printf("\033[1;32m");
    info("Variable was considered TRUE: a=%02X", control_var);
  }
  else
  {
    printf("\033[1;31m");
    info("Variable was considered FALSE: a=%02X", control_var);
  }
}