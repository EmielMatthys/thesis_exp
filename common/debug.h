#ifndef DEBUG_H_INC
#define DEBUG_H_INC

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define ASSERT(cond)                                                    \
    do {                                                                \
        if (!(cond))                                                    \
        {                                                               \
            perror("[" __FILE__ "] assertion '" #cond "' failed");      \
            abort();                                                    \
        }                                                               \
    } while(0)

#define SGX_ASSERT(f)  { if ( SGX_SUCCESS != (enclave_rv = (f)) )       \
 {                                                                      \
       printf( "Error calling enclave at %s:%d (rv=0x%x)\n", __FILE__,  \
                                              __LINE__, enclave_rv);    \
        abort();                                                        \
 } }

#define __FILENAME__ (strrchr("/" __FILE__, '/') + 1)

#define info(msg, ...)                                                  \
    do {                                                                \
        printf("[%s] " msg "\n", __FILENAME__, ##__VA_ARGS__);              \
        fflush(stdout);                                                 \
    } while(0)

#define info_event(msg, ...)                                                                        \
do {                                                                                                \
    printf("\n--------------------------------------------------------------------------------\n"); \
    info(msg,##__VA_ARGS__);                                                                        \
    printf("--------------------------------------------------------------------------------\n\n"); \
} while(0)

#define _RED do{printf("\033[1;31m");}while(0);
#define _GREEN do{printf("\033[1;32m");}while(0);
#define _YELLOW do{printf("\033[1;33m");}while(0);
#define _RESET_COL ;do{printf("\033[0m");}while(0);

void hexDump(char*, void*, int);

#endif
