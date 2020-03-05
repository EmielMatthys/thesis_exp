#include <stdio.h>
#include <sys/mman.h>
#include <pf.h>

void fault_handler(void *base_adr)
{

}

int main() {

  register_fault_handler(fault_handler);

  return 0;
}