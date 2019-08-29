//#include "crypt.h"
#include "api.h"
#include "crc32.h"
#include "hex.h"
#include "random.h"
#include <stdio.h>
#include <time.h>
#include <zconf.h>

/* The largest number rand will return (same as INT_MAX).  */
//#define	RAND_MAX	2147483647

#define RAND_HEAD_LEN 12

//#ifdef IZ_CRC_BE_OPTIMIZ
// local z_uint4 near crycrctab[256];
//   local z_uint4 near *cry_crctb_p = NULL;
//   local z_uint4 near *crytab_init OF((__GPRO));
//#  define CRY_CRC_TAB  cry_crctb_p
//#  undef CRC32
//#  define CRC32(c, b, crctab) (crctab[((int)(c) ^ (b)) & 0xff] ^ ((c) >> 8))
//#else
//#  define CRY_CRC_TAB  CRC_32_TAB
//#endif /* ?IZ_CRC_BE_OPTIMIZ */

#define CRY_CRC_TAB crc_32_tab
#define CRC32(c, b, crctab) (crctab[((int)(c) ^ (b)) & 0xff] ^ ((c) >> 8))

int compareArrays(unsigned char a[], unsigned char b[], int n) {
  int ii;
  for (ii = 1; ii <= n; ii++) {
    if (a[ii] != b[ii])
      return 0;
    // better:
    // if(fabs(a[ii]-b[ii]) < 1e-10 * (fabs(a[ii]) + fabs(b[ii]))) {
    // with the appropriate tolerance
  }
  return 1;
}

int update_keys(c, keys) const int c; /* byte of plain text */
z_uint4 *keys;
{
#ifdef IZ_CRC_BE_OPTIMIZ
  if (cry_crctb_p == NULL) {
    cry_crctb_p = crytab_init(__G);
  }
#endif
  ulg r = CRC32(keys[0], c, crc_32_tab);
  keys[0] = r;
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
#ifdef IZ_CRC_BE_OPTIMIZ
  if (cry_crctb_p == NULL) {
    cry_crctb_p = crytab_init(__G);
  }
#endif
  keys[0] = 305419896L;
  keys[1] = 591751049L;
  keys[2] = 878082192L;
  while (*passwd != '\0') {
    update_keys((int)*passwd, keys);
    passwd++;
  }
}

/* the crc_32_tab array has to be provided externally for the crypt calculus */

/* encode byte c, using temp t.  Warning: c must not have side effects. */
#define zencode(c, t, keys)                                                    \
  (t = decrypt_byte(keys), update_keys(c, keys), t ^ (c))

//#  ifndef ZCR_SEED2
//#    define ZCR_SEED2 (unsigned)3141592654L     /* use PI as default pattern
//*/ #  endif

//#  ifndef ZCR_SEED2
//#    define ZCR_SEED2     (unsigned) getpid()   /* use PID as seed pattern */
//#  endif

int main(argc, argv) int argc; /* number of tokens in command line */
char **argv;                   /* command line tokens */
/* Add, update, freshen, or delete zip entries in a zip file.  See the
   command help in help() above. */
{
  crc_32_tab = get_crc_table();

  unsigned char zip_header[10] = {143, 3,  56,  219, 170,
                                  222, 54, 241, 229, 233}; // 57,217 - crc
  //  srand();
  //  crypthead();
  //  unsigned int ti = time(NULL);
  //  unsigned int p = getpid();

  // Sunday, 26 June 2016 г., 18:25:00 -
  for (unsigned int ti = 1466965500; ti <= 1466966100; ti++) {
    for (unsigned int p = 1; p <= 64000; p++) {
      printf("%d\n", ti);
      printf("%d\n", p);

      unsigned int seed = p ^ ti;
      printf("%d\n", seed);

      int n;                         /* index in random header */
      int t;                         /* temporary */
      int c;                         /* random byte */
      uch header[RAND_HEAD_LEN - 2]; /* random header minus first 2 CRC bytes */
      z_uint4 keys[3];
      char *passwd = "123";

      /* First generate RAND_HEAD_LEN-2 random bytes. We encrypt the
       * output of rand() to get less predictability, since rand() is
       * often poorly implemented.
       */
      srand(seed);
      init_keys(keys, passwd);
      for (n = 0; n < RAND_HEAD_LEN - 2; n++) {
        c = (rand() >> 7) & 0xff;
        header[n] = (uch)zencode(c, t, keys);
      }

      /* Encrypt random header (last two bytes is high word of crc) */
      init_keys(keys, passwd);

      for (n = 0; n < RAND_HEAD_LEN - 2; n++) {
        header[n] = (uch)zencode(header[n], t, keys);
      }

//      char *zip_str = barray2hexstr(zip_header, 10);
//      char *str = barray2hexstr(header, 10);
//      printf("%d", );

      if (compareArrays(header, zip_header, 10) == 1) {
        printf("%s\n", "Found!");
        printf("ti: %d\n", ti);
        printf("p: %d\n", p);
        printf("seed: %d\n", seed);

        printf("k1=%d\n", keys[0]);
        printf("k2=%d\n", keys[1]);
        printf("k3=%d\n", keys[2]);
      }
    }
  }

  //  for (int i = 0; i < 100; i++) {
  //
  //  }

  return 0;
}

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
