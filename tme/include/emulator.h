#ifndef PF_H_INC
#define PF_H_INC
#define PAGE_BASEADR(varadr) (void*)( (uint64_t)varadr & ~(unsigned long long)(4096 - 1) )

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ucontext.h>

#define PFN_MASK 0xfff

typedef struct info_s {
    enum  {
        STAT_INVALID = 0,
        STAT_INITIALIZED
    } status;
    void* adr;
    int is_write;
    size_t var_size;
    ucontext_t* uc;

} info_t;

static const info_t INFO_INVAL = {STAT_INVALID};

void tem_init_mem_encr(void*, int);

#endif
