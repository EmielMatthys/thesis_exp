#define _GNU_SOURCE 1
#include "common/debug.h"
#include "pf.h"
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <aes.h>

#define TF_BIT 8
#define _BV(bit) (1 << (bit))
#define ADD_MASK(var, bit) (var |= 0b1 << bit)

info_t curr_info;
mbedtls_aes_xts_context xts;

const char* key12 = "mLnmNmb3m0dTqYZij7rTgorUnuSXFAJ";

void fault_handler_wrapper (int signo, siginfo_t * si, void  *ctx)
{
  void *base_adrs;
  ucontext_t *uc = (ucontext_t *) ctx;
  base_adrs = si->si_addr;

  switch ( signo )
  {
    case SIGSEGV:
    {
      curr_info.status = STAT_INITIALIZED;
      curr_info.base_addr = base_adrs;
      curr_info.is_write = uc->uc_mcontext.gregs[REG_ERR] & 0x2; // StackOverflow
      curr_info.uc = uc;

      info("Caught page fault at base address=%p with IS_WRITE=%d", base_adrs, curr_info.is_write ? 1 : 0);

      /*
       * SIMULATION STARTS HERE:
       *  1) If READ: decrypt the value before continuing the READ instruction
       *  2) If WRITE: do nothing yet; wait for Trap signal after MEM WRITE instruction executed
       */

      if(!curr_info.is_write)
      {
        mbedtls_aes_crypt_xts(&xts, MBEDTLS_AES_DECRYPT, 4, (const unsigned char* ) &curr_info.base_addr, curr_info.base_addr, curr_info.base_addr);
      }

      // Set Trap Flag for after memory access
      uc->uc_mcontext.gregs[REG_EFL] |= _BV(TF_BIT);

      // Restore access permissions to continue execution
      ASSERT(!mprotect(base_adrs, 4096, PROT_READ | PROT_WRITE));

      break;
    }

    case SIGTRAP:
    {
      info("Caught SIGTRAP (address=%p), revoking access permissions.", base_adrs);

      // Remove Trap Flag
      uc->uc_mcontext.gregs[REG_EFL] &= ~_BV(TF_BIT);

      if(curr_info.status == STAT_INVALID)
      {
        info("Current info status was invalid! Aborting...");
        abort();
      }

      /*
       * SIMULATION ENDS HERE:
       *  1) READ instruction finished with decrypted value, revoke access and continue
       *  2) WRITE instruction finished, encrypt written result before continuing
       */

      if (curr_info.is_write)
      {
        mbedtls_aes_crypt_xts(&xts, MBEDTLS_AES_ENCRYPT, 4, (const unsigned char* ) &curr_info.base_addr, curr_info.base_addr, curr_info.base_addr);
      }

      // Revoke permissions for last memory access to catch SIGSEGV again
      ASSERT(!mprotect(curr_info.base_addr, 4096, PROT_NONE));

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

  // Initialize xts context
  mbedtls_aes_xts_init(&xts);
  mbedtls_aes_xts_setkey_enc(&xts, key12, 256);

}