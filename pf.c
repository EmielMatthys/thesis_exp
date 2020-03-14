#define _GNU_SOURCE 1
#include "common/debug.h"
#include "pf.h"
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <aes.h>
#include <malloc.h>
#include "hex_dump.c"

#define TF_BIT 8
#define _BV(bit) (1 << (bit))
#define ADD_MASK(var, bit) (var |= 0b1 << bit)

info_t curr_info;
const char* key12 = "mLnmNmb3m0dTqYZij7rTgorUnuSXFAJaaa"; // KEY1 + KEY2

//TODO: input size of crypto algo: min. 16 bytes; values to try: {16, 64, 4096} bytes?
// TODO: dynamic input size using malloc_usable_size impossible? because metadata might be encrypted
//  --> would need to keep metadata separate from encrypted block

void crypt_xts(int mode)
{
  mbedtls_aes_xts_context xts;
  mbedtls_aes_xts_init(&xts);

  if (mode == MBEDTLS_AES_DECRYPT)
    mbedtls_aes_xts_setkey_dec(&xts, key12, 256);
  else
    mbedtls_aes_xts_setkey_enc(&xts, key12, 256);

  long long* data_unit = malloc(16);// has to be 16 bytes exactly --> shortcoming of mbed library?
  memset(data_unit, 0x11, 16);
  *data_unit = (long long) curr_info.adr; // Set lower 8 bytes to address

#ifdef EXP_DEBUG
  hexDump("XTS BLOCK PRE", curr_info.adr, 16);
#endif

//  info("Calling mbed crypt with data_unit=%016llX, input=%016llX", *data_unit, *((long long*)curr_info.adr));
  ASSERT(!mbedtls_aes_crypt_xts(&xts, mode, 16,
          (const unsigned char *) data_unit, curr_info.adr, curr_info.adr));
//  info("Crypto output is %016llX", *(long long*)(curr_info.adr));

#ifdef EXP_DEBUG
  hexDump("XTS BLOCK POST", curr_info.adr,16);
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
      curr_info.is_write = uc->uc_mcontext.gregs[REG_ERR] & 0x2; // StackOverflow
      curr_info.uc = uc;

      // Restore access permissions to continue execution
      ASSERT(!mprotect((uint64_t)curr_info.adr & ~0xfff, 4096, PROT_READ | PROT_WRITE ));

      info("Caught SIGSEGV (address=%p) with IS_WRITE=%d", curr_info.adr, curr_info.is_write ? 1 : 0);

      /*
       * SIMULATION STARTS HERE:
       *  1) If READ: decrypt the value before continuing the READ instruction
       *  2) If WRITE: do nothing yet; wait for Trap signal after MEM WRITE instruction executed
       */
      curr_info.var_size = malloc_usable_size(curr_info.adr); // get size, only works for malloc'ed vars!!!
      info("Size of accessed var: %lu", curr_info.var_size);

      if(!curr_info.is_write) // is read
      {
        info("DECRYPTING...");
        crypt_xts(MBEDTLS_AES_DECRYPT);
      }

      // Set Trap Flag for after memory access
      uc->uc_mcontext.gregs[REG_EFL] |= _BV(TF_BIT);

      break;
    }

    case SIGTRAP:
    {
      info("Caught SIGTRAP (address=%p), revoking access permissions.", adrs);

      // Remove Trap Flag
      uc->uc_mcontext.gregs[REG_EFL] &= ~_BV(TF_BIT);

      if(curr_info.status == STAT_INVALID)
      {
        info("Current info status was invalid! Aborting...");
        abort();
      }

      /*
       * SIMULATION ENDS HERE:
       *  1) READ instruction finished with decrypted value, encrypt again
       *  2) WRITE instruction finished, turn into decrypted version
       */
      info("ENCRYPTING...");
      crypt_xts(MBEDTLS_AES_ENCRYPT);

      // Revoke permissions for last memory access to catch SIGSEGV again
      ASSERT(!mprotect((uint64_t)curr_info.adr & ~0xfff, 4096, PROT_NONE));

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