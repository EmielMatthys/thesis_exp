#ifndef PF_H_INC
#define PF_H_INC

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ucontext.h>

#define PFN_MASK 0xfff
#define GET_PFN(adrs) ((void*) (((uint64_t) adrs) & ~PFN_MASK))

typedef struct info_s {
  enum  {
    STAT_INVALID = 0,
    STAT_INITIALIZED
  } status;
  void* base_addr;
  int is_write;
  ucontext_t* uc;

} info_t;

static const info_t INFO_INVAL = {STAT_INVALID};

typedef void (*fault_handler_t)(void *page_base_adrs);
void register_fault_handler();


#endif
