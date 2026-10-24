#ifndef LJB_TXM_TRUST_H
#define LJB_TXM_TRUST_H

#include <stdbool.h>
#include <stdint.h>

bool txm_local_signing_supported(void);
int proc_set_txm_main_local_signing_trust(uint64_t proc);

#endif
