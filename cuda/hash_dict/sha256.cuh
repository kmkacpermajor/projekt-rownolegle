#pragma once

extern "C" {
#include "config.h"
void mcm_cuda_sha256_hash_batch(BYTE* in, WORD inlen, BYTE* out, WORD n_batch);
}