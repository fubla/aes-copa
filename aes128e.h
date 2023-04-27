#define Nb 4 //number of columns in State array
#define Nk 4 //number of columns in Key array
#define Nr 10 //number of rounds

/* Add round key to the State array */
void addRoundKey(unsigned char **state, const uint32_t *w, int round);

/* SubBytes routine for a individual byte */
unsigned char subByte(const unsigned char byte);

/* SubBytes routine for State array */
void subBytes(unsigned char **state);

/* ShiftRows routine for State array */
void shiftRows(unsigned char **state);

/* MixColumns routine for State array */
void mixColumns(unsigned char **state);

/* SubWord transformation for a 32-bit word */
uint32_t subWord(const uint32_t word);

/* RotWord transformation that rotates the bytes in a word cyclically */
uint32_t rotWord(const uint32_t word);

/* The key expansion routine */
void expandKey(const unsigned char *key, uint32_t *w);

/* Implement the following API.
 * You can add your own functions, but don't modify below this line.
 */

/* Under the 16-byte key at k, encrypt the 16-byte plaintext at p and store it at c. */
void aes128e(unsigned char *c, const unsigned char *p, const unsigned char *k);

