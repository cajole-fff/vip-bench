#ifndef VIP_H
#define VIP_H
#include "datatypes/enc_lib.h"
#include "interface/interface.h"
#include "interface/parameters.h"


void  VIPInit();
void  VIPInit(uint64_t key_upper, uint64_t key_lower, int seed);

#endif
