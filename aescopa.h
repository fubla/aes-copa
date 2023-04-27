


/* Multiply by 2 in GF(2^128) */
void mul2(unsigned char *a);

/* Multiply by 3 in GF(2^128) */
void mul3(unsigned char *a);

/* Multiply by 7 in GF(2^128) */
void mul7(unsigned char *a);

/* XOR two arrays with each other, and save result in the first */
void xorArray(unsigned char *a, const unsigned char *b); 	

/* PMAC1'(N) routine as in specification */
unsigned char *pmac1(const unsigned char *n, const unsigned char *k);

/* ENCRYPT(V, M) routine as in specification */
void encrypt(unsigned char *v, const unsigned char *m, const unsigned int d, unsigned char *c, unsigned char *s, const unsigned char *k);


/* Implement the following API.
 * You can add your own functions, but don't modify below this line.
 */

/* Under the 16-byte key at k and the 16-byte nonce at n, encrypt the plaintext at m and store it at c.
   Store the 16-byte tag in the end of c. The length of the plaintext is a multiple of 16 bytes given at d (e.g., 
   d = 2 for a 32-byte m). */
void aescopa(unsigned char *c, const unsigned char *k, const unsigned char *n, const unsigned char *m, const unsigned int d);
