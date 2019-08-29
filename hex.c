//
// Created by Sergey Tolmachev on 2019-08-28.
//

#include "hex.h"

void hex2bin(const char *in, size_t len, unsigned char *out) {

  static const unsigned char TBL[] = {
      0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  58, 59, 60, 61,
      62, 63, 64, 10, 11, 12, 13, 14, 15, 71, 72, 73, 74, 75,
      76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
      90, 91, 92, 93, 94, 95, 96, 10, 11, 12, 13, 14, 15};

  static const unsigned char *LOOKUP = TBL - 48;

  const char *end = in + len;

  while (in < end)
    *(out++) = LOOKUP[*(in++)] << 4 | LOOKUP[*(in++)];
}

char *barray2hexstr(const unsigned char *data, size_t datalen) {
  size_t final_len = datalen * 2;
  char *chrs = (unsigned char *)malloc((final_len + 1) * sizeof(*chrs));
  unsigned int j = 0;
  for (j = 0; j < datalen; j++) {
    chrs[2 * j] = (data[j] >> 4) + 48;
    chrs[2 * j + 1] = (data[j] & 15) + 48;
    if (chrs[2 * j] > 57)
      chrs[2 * j] += 7;
    if (chrs[2 * j + 1] > 57)
      chrs[2 * j + 1] += 7;
  }
  chrs[2 * j] = '\0';
  return chrs;
}