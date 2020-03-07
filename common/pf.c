#define _GNU_SOURCE 1
#include "debug.h"
#include "pf.h"
#include <signal.h>
#include <string.h>
#include <ucontext.h>

#define TF_BIT 8
#define _BV(bit) (1 << (bit))
#define ADD_MASK(var, bit) (var |= 0b1 << bit)

fault_handler_t __fault_handler_cb = NULL;

void fault_handler_wrapper (int signo, siginfo_t * si, void  *ctx)
{
  void *base_adrs;
  ucontext_t *uc = (ucontext_t *) ctx;
  base_adrs = si->si_addr;


  switch ( signo )
  {
    case SIGSEGV:
      info("Caught page fault (base address=%p)", base_adrs);
      long int err = uc->uc_mcontext.gregs[REG_ERR];
      int is_write = (err & 0x2);
      //SIMULATIE HIER
      uc->uc_mcontext.gregs[REG_EFL] |= _BV(TF_BIT); // Set Trap Flag for after memory access

      if (__fault_handler_cb)
        __fault_handler_cb(base_adrs);
      break;
    case SIGTRAP: // memory access concluded, remove trap flag and continue
      info("SIGTRAP CAUGHT");
      uc->uc_mcontext.gregs[REG_EFL] &= ~_BV(8);
      break;

    default:
      info("Caught unknown signal '%d'", signo);
      abort();
  }

  /* Mask lower PFN bits to simulate clearing by SGX hardware when executing
     the unprotected programs */
//  base_adrs = GET_PFN(base_adrs);


}

void register_fault_handler(fault_handler_t cb)
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

  __fault_handler_cb = cb;


}