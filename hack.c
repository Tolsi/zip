//#include "crypt.h"
#include "api.h"
#include "crc32.h"
#include "random.h"
#include <stdio.h>
#include <time.h>
#include <zconf.h>

/* The largest number rand will return (same as INT_MAX).  */
//#define	RAND_MAX	2147483647

#define RAND_HEAD_LEN 12

#define CRY_CRC_TAB crc_32_tab
#define CRC32(c, b, crctab) (crctab[((int)(c) ^ (b)) & 0xff] ^ ((c) >> 8))

/* the crc_32_tab array has to be provided externally for the crypt calculus */

/* encode byte c, using temp t.  Warning: c must not have side effects. */
#define zencode(c, t, keys)                                                    \
  (t = decrypt_byte(keys), update_keys(c, keys), t ^ (c))

int update_keys(c, keys) const int c; /* byte of plain text */
z_uint4 *keys;
{
  keys[0] = CRC32(keys[0], c, crc_32_tab);
  keys[1] = (keys[1] + (keys[0] & 0xff)) * 134775813L + 1;
  {
    register int keyshift = (int)(keys[1] >> 24);
    keys[2] = CRC32(keys[2], keyshift, crc_32_tab);
  }
  return c;
}

/***********************************************************************
 * Return the next byte in the pseudo-random sequence
 */
int decrypt_byte(keys) const z_uint4 *keys;
{
  unsigned temp; /* POTENTIAL BUG:  temp*(temp^1) may overflow in an
                  * unpredictable manner on 16-bit systems; not a problem
                  * with any known compiler so far, though */

  temp = ((unsigned)keys[2] & 0xffff) | 2;
  return (int)(((temp * (temp ^ 1)) >> 8) & 0xff);
}

/***********************************************************************
 * Initialize the encryption keys and the random header according to
 * the given password.
 */
void init_keys(keys, passwd) z_uint4 *keys;
const char *passwd; /* password string with which to modify keys */
{
  keys[0] = 305419896L;
  keys[1] = 591751049L;
  keys[2] = 878082192L;
  while (*passwd != '\0') {
    update_keys((int)*passwd, keys);
    passwd++;
  }
}

void btox(char *xp, const char *bb, int n)
{
  const char xx[]= "0123456789ABCDEF";
  xp[n] = 0;
  while (--n >= 0) xp[n] = xx[(bb[n>>1] >> ((1 - (n&1)) << 2)) & 0xF];
}

// original crypthead
// void crypthead(passwd, crc)
//    ZCONST char *passwd;         /* password string */
//    ulg crc;                     /* crc of file being encrypted */
//{
//  int n;                       /* index in random header */
//  int t;                       /* temporary */
//  int c;                       /* random byte */
//  uch header[RAND_HEAD_LEN];   /* random header */
//  static unsigned calls = 0;   /* ensure different random header each time */
//
//  /* First generate RAND_HEAD_LEN-2 random bytes. We encrypt the
//   * output of rand() to get less predictability, since rand() is
//   * often poorly implemented.
//   */
//  if (++calls == 1) {
//    srand((unsigned)time(NULL) ^ ZCR_SEED2);
//  }
//  init_keys(passwd);
//  for (n = 0; n < RAND_HEAD_LEN-2; n++) {
//    c = (rand() >> 7) & 0xff;
//    header[n] = (uch)zencode(c, t);
//  }
//  /* Encrypt random header (last two bytes is high word of crc) */
//  init_keys(passwd);
//  for (n = 0; n < RAND_HEAD_LEN-2; n++) {
//    header[n] = (uch)zencode(header[n], t);
//  }
//  header[RAND_HEAD_LEN-2] = (uch)zencode((int)(crc >> 16) & 0xff, t);
//  header[RAND_HEAD_LEN-1] = (uch)zencode((int)(crc >> 24) & 0xff, t);
//  bfwrite(header, 1, RAND_HEAD_LEN, BFWRITE_DATA);
//}


int main(argc, argv) int argc; /* number of tokens in command line */
char **argv;                   /* command line tokens */
/* Add, update, freshen, or delete zip entries in a zip file.  See the
   command help in help() above. */
{
  crc_32_tab = get_crc_table();

  const unsigned char zip_header[10] = {143, 3,  56,  219, 170,
                                  222, 54, 241, 229, 233}; // 57,217 - crc
  char header_str[21];

  btox(header_str, zip_header, 20);
  printf("Original header: %s\n", header_str);
  time_t u = 1566473567;
  time_t u2 = unix2dostime(&u);
  printf("dos: %d\n", u2);
  printf("2hop: %d\n", dos2unixtime(u2));
  printf("unix: %d\n", u);

  int n;                         /* index in random header */
  int t;                         /* temporary */
  int c;                         /* random byte */
  uch header[RAND_HEAD_LEN - 2]; /* random header minus first 2 CRC bytes */
  z_uint4 keys[3];

  char *pw = "123"; // ???
  // Sunday, 26 June 2016 г., 18:25:00 - Sunday, 26 June 2016 г., 18:35:00
  for (unsigned int ti = 1466965500; ti <= 1466966100; ti++) {
    for (unsigned int p = 100; p <= INT16_MAX; p++) {
      unsigned int seed = p ^ ti;
      printf("Trying ti=%d, p=%d, seed=%d\n", ti, p, seed);

      /* First generate RAND_HEAD_LEN-2 random bytes. We encrypt the
       * output of rand() to get less predictability, since rand() is
       * often poorly implemented.
       */
      srand(seed);
      init_keys(keys, pw);
      for (n = 0; n < RAND_HEAD_LEN - 2; n++) {
        c = (rand() >> 7) & 0xff;
        header[n] = (uch)zencode(c, t, keys);
      }

      // ???
    }
  }

  return 0;
}