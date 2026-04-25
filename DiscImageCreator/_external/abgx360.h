#pragma once

#include "rijndael-alg-fst.h"
#ifdef __cplusplus
extern "C" {
#endif
void decryptChallengeResponse(unsigned char* dcrt, unsigned char* ss);
void printwin32filetime(unsigned long long win32filetime, char* date);
#ifdef __cplusplus
}
#endif