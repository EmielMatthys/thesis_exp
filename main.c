#include "pf.h"
#include <sys/mman.h>
#include "common/debug.h"

asm("    .data\n"
    "    .global a\n"
    "    .align 0x1000   /* 4KiB */\n"
    "a:\n"
    "    .word 0x0\n"
    "    .space 0x1000   /* 4KiB */");

extern int a;
void check_var();

int main() {

  a = 0; // No faults

  register_fault_handler();
  ASSERT(!mprotect(&a, sizeof(a), PROT_NONE)); // Remove access

  a = 5; // SEGFAULT: WRITE
  check_var(); // SEGFAULTS

  return 0;
}

void check_var()
{
  if (a)
  {
    info("Variable was considered true: a=%02X", a);
  }
  else
  {
    info("Variable was considered false: a=%02X", a);
  }
}