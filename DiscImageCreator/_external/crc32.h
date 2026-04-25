#pragma once

#ifdef __cplusplus
extern "C" {
#endif
void make_crc_table(void);
unsigned long update_crc(unsigned long crc,	unsigned char* buf,	int len);
#ifdef __cplusplus
}
#endif