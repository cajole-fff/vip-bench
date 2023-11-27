#ifndef VIP_CPP
#define VIP_CPP

#include "vip-functional-library.h"


void VIPInit() {
    setParameters(SymmCipher::AES128);
    setRSAParameters();
}

void VIPInit(uint64_t key_upper, uint64_t key_lower, int seed){
    // setParameters(SymmCipher::AES128, 0x0505050505050505, 0x0505050505050505, 3022359314);
    setParameters(SymmCipher::AES128, key_upper, key_lower, seed);
    setRSAParameters();
}
#endif
