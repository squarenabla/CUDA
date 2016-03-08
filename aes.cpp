#include "aes.h"

unsigned char xtime(const unsigned char x){
	return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

unsigned char Multiply(const unsigned char x, const unsigned char y){
	return (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ 
		((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

bool AES::encode(unsigned char (&data) [BLOCK_SIZE], unsigned char (&cipher) [BLOCK_SIZE]){
	//if(size != BLOCK_SIZE){
	//	printf("%d %d \n", (int)sizeof(data), (int)sizeof(cipher));
	//	return false;
	//}

	_generateKey(cipher);

	_addRoundKey(data, 0);
	for(unsigned int i=1; i<ROUND_NUM; i++){
		_subBytes(data);
		_shiftRows(data);
		_mixColumns(data);
		_addRoundKey(data, i);
	}
	_subBytes(data);
	_shiftRows(data);
	_addRoundKey(data, ROUND_NUM);
	return true;	
}

bool AES::decode(unsigned char (&data)[BLOCK_SIZE], unsigned char (&cipher) [BLOCK_SIZE]){
	//if(size != BLOCK_SIZE){
	//	printf("%d %d \n", (int)sizeof(data), (int)sizeof(cipher));
	//	return false;
	//}

	_generateKey(cipher);

	_addRoundKey(data, ROUND_NUM);
	for(unsigned int i=(ROUND_NUM-1); i>0; i--){
		_invShiftRows(data);
		_invSubBytes(data);
		_addRoundKey(data, i);
		_invMixColumns(data);
	}
	_invShiftRows(data);
	_invSubBytes(data);
	_addRoundKey(data, 0);

	return true;
}

bool AES::_generateKey(const unsigned char *cipher){
	unsigned int resWeidth = (ROUND_NUM+1)*BLOCK_DEMEN;

	for(int i=0; i<BLOCK_DEMEN; i++){
		for(int j=0; j<BLOCK_DEMEN; j++){
			keySchedule[resWeidth*i + j] = cipher[BLOCK_DEMEN*i +j];
		}
	}

	for(int k=0; k<ROUND_NUM; k++){
		for(int i=0; i<BLOCK_DEMEN; i++){
			int index = i*resWeidth + (k+1)*BLOCK_DEMEN;

			keySchedule[index] = SBox[keySchedule[((i+1)%BLOCK_DEMEN)*resWeidth + (k+1)*BLOCK_DEMEN - 1]];
			keySchedule[index] ^= (keySchedule[index-4] ^ Rcon[BLOCK_DEMEN*k + i]);
		}
		for(int i=0; i<BLOCK_DEMEN; i++){
			for(int j=1; j<BLOCK_DEMEN; j++){
				int index = i*resWeidth + (k+1)*BLOCK_DEMEN + j;
				keySchedule[index] = keySchedule[index-1] ^ keySchedule[index-4]; 
			}
		}
	}
	return true;
}

void AES::_subBytes(unsigned char *r){
	for(int c=0; c<BLOCK_SIZE; c++){
		r[c] = SBox[r[c]];
	}
}

void AES::_invSubBytes(unsigned char *r){
	for(int c=0; c<BLOCK_SIZE; c++){
		r[c] = InvSbox[r[c]];
	}
}
	

void AES::_shiftRows(unsigned char *r){
	for(int i=0; i<BLOCK_DEMEN; i++){
		for(int k=0; k<i; k++){
			unsigned char buf = r[i*BLOCK_DEMEN];
			for(int j=0; j<BLOCK_DEMEN-1; j++){
				r[i*BLOCK_DEMEN + j] = r[i*BLOCK_DEMEN + j + 1];
			}
			r[(i+1)*BLOCK_DEMEN - 1] = buf;
		}
	}
}

void AES::_invShiftRows(unsigned char *r){
	for(int i=0; i<BLOCK_DEMEN; i++){
		for(int k=0; k<i; k++){
			unsigned char buf = r[(i + 1) * BLOCK_DEMEN - 1];
			for(int j=BLOCK_DEMEN-1; j>0; j--){
				r[i * BLOCK_DEMEN + j] = r[i * BLOCK_DEMEN + j - 1];
			}
			r[i * BLOCK_DEMEN] = buf;
		}
	}
}

void AES::_mixColumns(unsigned char *r){
	for(int i=0; i<BLOCK_DEMEN; i++){
		unsigned char a[4];
		unsigned char b[4];
		//  unsigned char c;
		unsigned char h;
		/* The array 'a' is simply a copy of the input array 'r'
		* The array 'b' is each element of the array 'a' multiplied by 2
		* in Rijndael's Galois field
		* a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */ 
		for(int c=0; c<4; c++) {
			a[c] = r[i + BLOCK_DEMEN * c];
			/* h is 0xff if the high bit of r[c] is set, 0 otherwise */
			h = (unsigned char)((signed char)r[i + BLOCK_DEMEN * c] >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
			b[c] = r[i + BLOCK_DEMEN * c] << 1; /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
			b[c] ^= 0x1B & h; /* Rijndael's Galois field */
		}
		r[i + BLOCK_DEMEN * 0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
		r[i + BLOCK_DEMEN * 1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
		r[i + BLOCK_DEMEN * 2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
		r[i + BLOCK_DEMEN * 3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
	}
}

void AES::_invMixColumns(unsigned char *r){
	for(int i=0; i<BLOCK_DEMEN; i++){
		unsigned char a = r[i + BLOCK_DEMEN * 0];
		unsigned char b = r[i + BLOCK_DEMEN * 1];
		unsigned char c = r[i + BLOCK_DEMEN * 2];
		unsigned char d = r[i + BLOCK_DEMEN * 3];

		r[i + BLOCK_DEMEN * 0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		r[i + BLOCK_DEMEN * 1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		r[i + BLOCK_DEMEN * 2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		r[i + BLOCK_DEMEN * 3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
}

void AES::_addRoundKey(unsigned char *r, const unsigned int &_roundID){
	unsigned char key[BLOCK_SIZE];
	_fetchKey(key, _roundID);

	for(int i=0; i<BLOCK_DEMEN; i++){
		for(int j=0; j<BLOCK_DEMEN; j++){
			r[i * BLOCK_DEMEN + j] ^= key[i * BLOCK_DEMEN + j];  
		}
	}
}

void AES::_fetchKey(unsigned char *key, const unsigned int &_roundID){
	for(int i=0; i<BLOCK_DEMEN; i++){
		for(int j=0; j<BLOCK_DEMEN; j++){
			key[i * BLOCK_DEMEN + j] = keySchedule[i * (ROUND_NUM + 1) * BLOCK_DEMEN + _roundID * BLOCK_DEMEN + j];
		}
	}
}