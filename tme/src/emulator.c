#define _GNU_SOURCE 1
#include "emulator.h"
#include "debug.h"
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include "mbedtls/aes.h"
#include <malloc.h>

#define TF_BIT 8u
#define _BV(bit) (1u << (bit))
#define ADD_MASK(var, bit) (var |= 0b1 << bit)
#define CRYPTO_BLOCK_SIZE 64//4096
#define CRYPTO_BLOCK_MASK ~(unsigned long long)(CRYPTO_BLOCK_SIZE - 1)
#define CRYPTO_ADR_TO_BASE(adr) ((uint64_t)adr & CRYPTO_BLOCK_MASK)

info_t curr_info;
const char* key12 = "mLnmNmb3m0dTqYZij7rTgorUnuSXFAJaaa"; // KEY1 + KEY2

void crypt_xts(int mode, void* var_adr)
{
    mbedtls_aes_xts_context xts;
    mbedtls_aes_xts_init(&xts);

    if (mode == MBEDTLS_AES_DECRYPT)
        mbedtls_aes_xts_setkey_dec(&xts, key12, 256);
    else
        mbedtls_aes_xts_setkey_enc(&xts, key12, 256);

    unsigned long long* data_unit = malloc(16);// has to be 16 bytes exactly --> shortcoming of mbed library?
    memset(data_unit, 0x11, 16);

    unsigned long long block_adr = CRYPTO_ADR_TO_BASE(var_adr);

    data_unit[0] = block_adr; // Set lower 8 bytes to address

//  info("Calling mbed crypt with data_unit=%016llX, input=%016llX", *data_unit, *((long long*)curr_info.adr));
    ASSERT(!mbedtls_aes_crypt_xts(&xts, mode, CRYPTO_BLOCK_SIZE,
                                  (const unsigned char *) data_unit, (unsigned char*) block_adr, (unsigned char*) block_adr));
//  info("Crypto output is %016llX", *(long long*)(curr_info.adr));

#ifdef EXP_DEBUG
    char title[128];
  snprintf(title, 128, "%p - %s", (void *) block_adr, mode == MBEDTLS_AES_DECRYPT ? "DECRYPTED" : "ENCRYPTED");
  hexDump(title, (void *) block_adr, CRYPTO_BLOCK_SIZE);
#endif

    mbedtls_aes_xts_free(&xts);
}

void fault_handler_wrapper (int signo, siginfo_t * si, void  *ctx)
{
    void *adrs;
    ucontext_t *uc = (ucontext_t *) ctx;
    adrs = si->si_addr;

    switch ( signo )
    {
        case SIGSEGV:
        {
            curr_info.status = STAT_INITIALIZED;
            curr_info.adr = adrs;
            curr_info.is_write = uc->uc_mcontext.gregs[REG_ERR] & 0x2; // https://wiki.osdev.org/Paging#Handling
            curr_info.uc = uc;

            // Restore access permissions to continue execution
            ASSERT(!mprotect(PAGE_BASEADR(curr_info.adr), 4096, PROT_READ | PROT_WRITE ));

            info("Caught SIGSEGV (address=%p) with IS_WRITE=%d", curr_info.adr, curr_info.is_write ? 1 : 0);

            crypt_xts(MBEDTLS_AES_DECRYPT, curr_info.adr);

            // Set Trap Flag for after memory access
            uc->uc_mcontext.gregs[REG_EFL] |= _BV(TF_BIT);

            break;
        }

        case SIGTRAP:
        {
            info("Caught SIGTRAP (address=%p)", adrs);

            // Remove Trap Flag
            uc->uc_mcontext.gregs[REG_EFL] &= ~_BV(TF_BIT);

            if(curr_info.status == STAT_INVALID)
            {
                info("Current info status was invalid! Aborting...");
                abort();
            }

            crypt_xts(MBEDTLS_AES_ENCRYPT, curr_info.adr);

            // Revoke permissions for last memory access to catch SIGSEGV again
            ASSERT(!mprotect(PAGE_BASEADR(curr_info.adr), 4096, PROT_NONE));

            // Invalidate current info to avoid double processing
            curr_info = INFO_INVAL;
            break;
        }

        default:
            info("Caught unknown signal '%d'", signo);
            abort();
    }

}

void register_fault_handler()
{
    struct sigaction act, old_act;
    memset(&act, 0, sizeof(sigaction));

    /* Specify handler with signinfo arguments */
    act.sa_sigaction = fault_handler_wrapper;
    act.sa_flags = SA_RESTART | SA_SIGINFO;

    /* Block all signals while the signal is being handled */
    sigfillset(&act.sa_mask);

    ASSERT (!sigaction( SIGSEGV, &act, &old_act ));
    ASSERT(!sigaction(SIGTRAP, &act, &old_act));
}

void tem_init_mem_encr(void* base_adr, int block_count)
{
    int i = 0;
    while (i < block_count)
    {
        void* block_adr = CRYPTO_ADR_TO_BASE(base_adr) + i * CRYPTO_BLOCK_SIZE;
        crypt_xts(MBEDTLS_AES_ENCRYPT, block_adr);
        i++;
    }
    register_fault_handler();
}