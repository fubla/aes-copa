#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aescopa.h"
#include "aes128e.h"

/* Universal block size in bytes */
#define NUM_BYTES 16

unsigned char zeroes[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned char L[NUM_BYTES];

/* HELPER FUNCTIONS */

/* Multiplies array "a" by 2 in GF(2^128) */
void mul2(unsigned char *a){
	
	//Check if the product will overflow. If it does, set flag to indicate it.	
	int over = 0;
	if(a[0] & 0x80){
		over = 1;
	}
	
	//Shift the bytes in the array, equivalent to multiplying by 2, treating the whole array as one big polynomial.
	for (int i = 0; i < 15; i++){
		a[i] = (a[i] << 1) ^ (a[i+1] >> 7);
	}
	a[15] = (a[15] << 1); 
	
	//If the result is too big, reduce with the field polynomial.
	if (over){
		a[15] ^= 0x87;
	}
}

/* Multiply array "a" by 3 in GF(2^128). This is equivalent to 2*a + a in GF(2^128) */
void mul3(unsigned char *a){
	
	unsigned char temp[NUM_BYTES];
	
	//Store "a" in temporary variable.
	memcpy(temp, a, NUM_BYTES);
	
	//First multiply by two.
	mul2(a);

	//Then add (XOR) every byte of the previous product with the the bytes of a.
	for (int i = 0; i <= 15; i++){
		a[i] ^= temp[i];
	}
}

/* Multiply array "a" by 7 in GF(2^128). This is equivalent with 4*a + 3*a in GF(2^128) */ 
void mul7(unsigned char	*a){
	unsigned char temp[NUM_BYTES];
	
	//Store "a" in temporary variable.
	memcpy(temp, a, NUM_BYTES);
	
	//First multiply "a" by four.
	mul2(temp);
	mul2(temp);
	
	//Then add (XOR) the previous product to "a" multiplied by three.
	mul3(a);
	for (int i = 0; i <= 15; i++){
		a[i] ^= temp[i];
	}
}

/* XOR the respective elements of both arrays with the elements of each other. */
void xorArray(unsigned char *a, const unsigned char *b){
	for (int i = 0; i < NUM_BYTES; i++){ 
		a[i] ^= b[i];	
	}

}

/* END OF HELPER FUNCTIONS */

/* PMAC1' routine as defined in the specification. Takes as argument the nonce "n" and the encryption key "k". It generates and returns the message authentication code "V". */
unsigned char *pmac1(const unsigned char *n, const unsigned char *k){
	unsigned char Lx[NUM_BYTES];
	unsigned char D0[NUM_BYTES];
	unsigned char *v = malloc(NUM_BYTES*sizeof(unsigned char));
	unsigned char temp[NUM_BYTES];
	memcpy(Lx, L, NUM_BYTES);
	mul3(Lx);
	mul3(Lx);
	mul3(Lx);
	memcpy(D0, Lx, NUM_BYTES);
	mul3(D0);
	memcpy(temp, n, NUM_BYTES);
	xorArray(temp, D0);
	aes128e(v, temp, k);
	return v;
}

/* Encrypt routine as defined in the specification. */
void encrypt(unsigned char *v, const unsigned char *m, const unsigned int d, unsigned char *c, unsigned char *s, const unsigned char *k){
	unsigned char M[d][NUM_BYTES];
	for (int i = 0; i < d; i++){
		for (int j = 0; j < NUM_BYTES; j++){
			M[i][j] = m[i * NUM_BYTES + j];
		}	
	}
	unsigned char C[d][NUM_BYTES];
	unsigned char temp[NUM_BYTES];
	unsigned char Vi[d+1][NUM_BYTES];
	unsigned char D0[NUM_BYTES];
	unsigned char D1[NUM_BYTES];
	for(int i=0;i<NUM_BYTES;i++){
		Vi[0][i] = v[i] ^ L[i];  
	}
	memcpy(D0, L, NUM_BYTES);
	mul3(D0);
	memcpy(D1, L, NUM_BYTES);
	mul2(D1);
	for (int i=0; i<d; i++){
		for (int j=0;j<NUM_BYTES;j++){
			temp[j] = M[i][j] ^ D0[j];
		}
		aes128e(Vi[i+1], temp, k);
		for (int j=0;j<NUM_BYTES;j++){
			Vi[i+1][j] ^=  Vi[i][j];
		}
		aes128e(C[i], Vi[i+1], k);
		for (int j=0;j<NUM_BYTES;j++){
			C[i][j] ^=  D1[j];
		}
		mul2(D0);
		mul2(D1);
	}
	for (int i = 0; i < d; i++){
		for (int j = 0;  j < NUM_BYTES; j++){
			c[i * NUM_BYTES + j] = C[i][j];
		}
	}
	memcpy(s, Vi[d], NUM_BYTES);
}


/* Under the 16-byte key at k and the 16-byte nonce at n, encrypt the plaintext at m and store it at c.
   Store the 16-byte tag in the end of c. The length of the plaintext is a multiple of 16 bytes given at d (e.g., 
   d = 2 for a 32-byte m). */
void aescopa(unsigned char *c, const unsigned char *k, const unsigned char *n, const unsigned char *m, const unsigned int d) {
	unsigned char Ltemp[NUM_BYTES];
	unsigned char V[NUM_BYTES];
	unsigned char S[NUM_BYTES];
	unsigned char sigma[NUM_BYTES] = {0};
	unsigned char T[NUM_BYTES];
	unsigned char temp[NUM_BYTES];
	unsigned char temp1[NUM_BYTES];
	unsigned char M[d][NUM_BYTES];
	unsigned char C[d][NUM_BYTES];
	for (int i = 0; i < d; i++){
		for (int j = 0; j < NUM_BYTES; j++){
			M[i][j] = m[i * NUM_BYTES + j];
		}	
	}
	aes128e(L, zeroes, k);
	memcpy(V, pmac1(n, k), NUM_BYTES);
	encrypt(V, m, d, c, S, k);
	for (int i = 0; i < d; i++){
		for (int j = 0; j < NUM_BYTES; j++){
			C[i][j] = c[i*NUM_BYTES + j]; 
		} 
	}
	for (int i = 0; i < d; i++){
		xorArray(sigma, M[i]);	
	} 
	memcpy(Ltemp, L, NUM_BYTES);
	mul3(Ltemp);
	mul3(Ltemp);
	for (int i = 0; i < (d-1); i++){
		mul2(Ltemp);	
	} 
	xorArray(sigma, Ltemp);
	aes128e(temp, sigma, k);
	xorArray(temp, S);
	aes128e(temp1, temp, k);
	memcpy(Ltemp, L, NUM_BYTES);
	mul7(Ltemp);
	for (int i=0; i<d; i++){
		mul2(Ltemp);
	}
	xorArray(temp1, Ltemp);
	memcpy(T, temp1, NUM_BYTES);
	memcpy(&c[d*NUM_BYTES], T, NUM_BYTES);


}
