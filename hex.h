//
// Created by Sergey Tolmachev on 2019-08-28.
//

#include "stdlib.h"

#ifndef ZIP_HEX_H
#define ZIP_HEX_H

void hex2bin(const char* in, size_t len, unsigned char* out);
char* barray2hexstr(const unsigned char* data, size_t datalen);

#endif // ZIP_HEX_H
