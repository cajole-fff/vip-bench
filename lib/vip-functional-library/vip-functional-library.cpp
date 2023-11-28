#ifndef VIP_CPP
#define VIP_CPP

#include "vip-functional-library.h"

void VIPInit() {
    setParameters(SymmCipher::AES128);
    setRSAParameters();
}

#endif