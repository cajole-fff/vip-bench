#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// include build configuration defines
#include "../config.h"

// supported sizes: 256 (default), 512, 1024, 2048
#define DATASET_SIZE 256

// VIP_ENCINT data[DATASET_SIZE];
int data[DATASET_SIZE];

// total swaps executed so far
unsigned long swaps = 0;

void print_data(int *data, unsigned size) {
    fprintf(stdout, "DATA DUMP:\n");
    for (unsigned i = 0; i < size; i++)
        fprintf(stdout, "  data[%u] = %d\n", i, data[i]);
}

void print_enc_data(VIP_ENCINT *data, unsigned size) {
    fprintf(stdout, "DATA DUMP:\n");
    for (unsigned i = 0; i < size; i++)
        fprintf(stdout, "  data[%u] = %d\n", i, VIP_DEC(data[i]));
}

void bubblesort(VIP_ENCINT *data, unsigned size) {
    for (unsigned i = 0; i < size - 1; i++) {
#ifndef VIP_DO_MODE
        bool swapped = false;
#endif /* !VIP_DO_MODE */

        for (unsigned j = 0; j < size - 1; j++) {
#ifndef VIP_DO_MODE
            if (data[j] > data[j + 1]) {
                VIP_ENCINT tmp = data[j];
                data[j] = data[j + 1];
                data[j + 1] = tmp;
                swapped = true;
                swaps++;
            }
#else  /* VIP_DO_MODE */
            VIP_ENCBOOL do_swap = data[j] > data[j + 1];
            VIP_ENCINT tmp = data[j];
            data[j] = VIP_CMOV(do_swap, data[j + 1], data[j]);
            data[j + 1] = VIP_CMOV(do_swap, tmp, data[j + 1]);
            swaps++;
#endif /* VIP_DO_MODE */
        }

#ifndef VIP_DO_MODE
        // done?
        if (!swapped)
            break;
#endif /* !VIP_DO_MODE */
    }
}

int main(void) {
    /* initialize the privacy enhanced execution target */
    /* The data owner acquires the public key (pk_se) of the SE hardware
       from a trusted certificate authority */
    /* The data owner generates a symmetric key (k) that will be used as
       the shared data encryption key. */
    VIP_INIT;

    /* They encrypt k with pk_se according to the RSA protocol. */
    VIP_ENC_AES128KEY;

    /* initialize the pseudo-RNG */
    mysrand(42);

    /* initialize the array to sort */
    for (unsigned i = 0; i < DATASET_SIZE; i++)
        data[i] = myrand();

    VIP_ENCINT enc_data[DATASET_SIZE];
    for (unsigned i = 0; i < DATASET_SIZE; i++)
        enc_data[i] = data[i];

    /* The encrypted key packet and encrypted data is transported to the
       server containing the SE extension */
    /* The server OS receives the packet and issues an expose_key
       instruction */
    VIP_DEC_AES128KEY;

    print_enc_data(enc_data, DATASET_SIZE);

    {
        Stopwatch s("VIP_Bench Runtime");
        bubblesort(enc_data, DATASET_SIZE);
    }
    print_enc_data(enc_data, DATASET_SIZE);

    // check the array
    for (unsigned i = 0; i < DATASET_SIZE - 1; i++) {
        if (VIP_DEC(enc_data[i]) > VIP_DEC(enc_data[i + 1])) {
            fprintf(stdout, "ERROR: data is not properly sorted.\n");
            return -1;
        }
    }
    fprintf(stderr, "INFO: %lu swaps executed.\n", swaps);
    fprintf(stdout, "INFO: data is properly sorted.\n");
    return 0;
}
