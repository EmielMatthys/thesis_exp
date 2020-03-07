#define _GNU_SOURCE 1
#include "debug.h"
#include "pf.h"
#include <signal.h>
#include <string.h>
#include <ucontext.h>
#include <sys/mman.h>

#define TF_BIT 8
#define _BV(bit) (1 << (bit))
#define ADD_MASK(var, bit) (var |= 0b1 << bit)

void* last_memaccess_addr;

void fault_handler_wrapper (int signo, siginfo_t * si, void  *ctx)
{
  void *base_adrs;
  ucontext_t *uc = (ucontext_t *) ctx;
  base_adrs = si->si_addr;


  switch ( signo )
  {
    case SIGSEGV:
    {
      int err = uc->uc_mcontext.gregs[REG_ERR];
      int is_write = (err & 0x2);
      last_memaccess_addr = base_adrs;

      info("Caught page fault at base address=%p with IS_WRITE=%d", base_adrs, is_write ? 1 : 0);
      /*TODO
       * SIMULATION HERE:
       *  1) READ has to be replaced by DECRYPT + READ
       *  2) WRITE has to be replaced by ENCRYPT + WRITE
       */
      // Set Trap Flag for after memory access
      uc->uc_mcontext.gregs[REG_EFL] |= _BV(TF_BIT);

      // Restore access permissions
      ASSERT(!mprotect(base_adrs, 4096, PROT_READ | PROT_WRITE));

      break;
    }

    case SIGTRAP:
    {
      info("Caught SIGTRAP (address=%p), revoking access permissions.", base_adrs);

      // Remove Trap Flag
      uc->uc_mcontext.gregs[REG_EFL] &= ~_BV(8);

      // Revoke permissions for last memory access to catch SIGSEGV again
      ASSERT(!mprotect(last_memaccess_addr, 4096, PROT_NONE));
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