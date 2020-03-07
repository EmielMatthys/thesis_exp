#define _GNU_SOURCE 1
#include <debug.h>
#include <pf.h>
#include <cacheutils.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdbool.h>

#define info(msg, ...)                                                  \
    do {                                                                \
        printf("[" __FILE__ "] " msg "\n", ##__VA_ARGS__);              \
        fflush(stdout);                                                 \
    } while(0)

#define ASSERT(cond)                                                    \
    do {                                                                \
        if (!(cond))                                                    \
        {                                                               \
            perror("[" __FILE__ "] assertion '" #cond "' failed");      \
            abort();                                                    \
        }                                                               \
    } while(0)

asm("    .data\n"
    "    .global a\n"
    "    .align 0x1000   /* 4KiB */\n"
    "a:\n"
    "    .word 0x0\n"
    "    .space 0x1000   /* 4KiB */");

extern int a;

void fault_handler(void *base_adr)
{
  info("Page fault handler callback.");
  ASSERT(!mprotect(&a, sizeof(a), PROT_READ | PROT_WRITE));

}

void check_var();

int main() {

  register_fault_handler(fault_handler);

  int test = true;
  check_var();

  ASSERT(!mprotect(&a, sizeof(a), PROT_NONE));
  if(a){
    a=0;
  }
  ASSERT(!mprotect(&a, sizeof(a), PROT_NONE));

  check_var();

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