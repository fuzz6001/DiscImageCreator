#pragma once
typedef unsigned char byte;

#ifdef __cplusplus
extern "C" {
#endif
void make_crc16_table(void);
unsigned int update_crc16(int n, byte c[]);
#ifdef __cplusplus
}
#endif
