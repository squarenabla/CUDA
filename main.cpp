#include <stdio.h>

#include <algorithm> 
#include <iostream>

#include "aes.h"

// #define SBOX_SIZE 256
// #define BLOCK_SIZE 16
// #define BLOCK_DEMEN 4
// #define ROUND_NUM 10

// const unsigned char SBox[SBOX_SIZE] = 
// {
//   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
//   0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
//   0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
//   0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
//   0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
//   0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
//   0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
//   0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
//   0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
//   0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
//   0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
//   0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
//   0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
//   0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
//   0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
//   0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
// };

// const unsigned char Rcon[ROUND_NUM*BLOCK_DEMEN] = 
// {
//         0x01, 0x00, 0x00, 0x00,
//         0x02, 0x00, 0x00, 0x00,
//         0x04, 0x00, 0x00, 0x00,
//         0x08, 0x00, 0x00, 0x00,
//         0x10, 0x00, 0x00, 0x00,
//         0x20, 0x00, 0x00, 0x00,
//         0x40, 0x00, 0x00, 0x00,
//         0x80, 0x00, 0x00, 0x00,
//         0x1b, 0x00, 0x00, 0x00,
//         0x36, 0x00, 0x00, 0x00
// };

// void sub_bytes(unsigned char *r){
//   for(int c=0; c<BLOCK_SIZE; c++){
//     r[c] = SBox[r[c]];
//   }
// }

// // void sub_bytes_column(unsigned char *r){
// //   for(int c=0; c<BLOCK_DEMEN; c++){
// //     r[c] = SBox[r[c]];
// //   }
// // }

// void shit_rows(unsigned char *r){
//   for(int i=0; i<BLOCK_DEMEN; i++){
//     for(int k=0; k<i; k++){
//       unsigned char buf = r[i*BLOCK_DEMEN];
//       for(int j=0; j<BLOCK_DEMEN-1; j++){
//         r[i*BLOCK_DEMEN + j] = r[i*BLOCK_DEMEN + j + 1];
//       }
//       r[(i+1)*BLOCK_DEMEN - 1] = buf;
//     }
//   }
// }

// void mix_columns(unsigned char *r) {
//   for(int i=0; i<BLOCK_DEMEN; i++){
//     unsigned char a[4];
//     unsigned char b[4];
//   //  unsigned char c;
//     unsigned char h;
//     /* The array 'a' is simply a copy of the input array 'r'
//      * The array 'b' is each element of the array 'a' multiplied by 2
//      * in Rijndael's Galois field
//      * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */ 
//     for(int c=0; c<4; c++) {
//             a[c] = r[i + BLOCK_DEMEN * c];
//             /* h is 0xff if the high bit of r[c] is set, 0 otherwise */
//             h = (unsigned char)((signed char)r[i + BLOCK_DEMEN * c] >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
//             b[c] = r[i + BLOCK_DEMEN * c] << 1; /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
//             b[c] ^= 0x1B & h; /* Rijndael's Galois field */
//     }
//     r[i + BLOCK_DEMEN * 0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
//     r[i + BLOCK_DEMEN * 1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
//     r[i + BLOCK_DEMEN * 2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
//     r[i + BLOCK_DEMEN * 3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
//   }
// }

// void add_roundkey(unsigned  char *r, unsigned char *key){
//   for(int i=0; i<BLOCK_DEMEN; i++){
//     for(int j=0; j<BLOCK_DEMEN; j++){
//       r[i*BLOCK_DEMEN + j] ^= key[i*BLOCK_DEMEN + j];  
//     }
//   }
// }

// // __global__ void axpy(float a, float* x, float* y) {
// //   y[threadIdx.x] = a * x[threadIdx.x];
// // }

// void generate_key(unsigned char *cipher, unsigned char *result){
//   unsigned int resWeidth = (ROUND_NUM+1)*BLOCK_DEMEN;

//   for(int i=0; i<BLOCK_DEMEN; i++){
//     for(int j=0; j<BLOCK_DEMEN; j++){
//       result[resWeidth*i + j] = cipher[BLOCK_DEMEN*i +j];
//     }
//   }

//   for(int k=0; k<ROUND_NUM; k++){
//     for(int i=0; i<BLOCK_DEMEN; i++){
//       int index = i*resWeidth + (k+1)*BLOCK_DEMEN;

//       result[index] = SBox[result[((i+1)%BLOCK_DEMEN)*resWeidth + (k+1)*BLOCK_DEMEN - 1]];
//       result[index] ^= (result[index-4] ^ Rcon[BLOCK_DEMEN*k + i]);
//     }
//     for(int i=0; i<BLOCK_DEMEN; i++){
//       for(int j=1; j<BLOCK_DEMEN; j++){
//         int index = i*resWeidth + (k+1)*BLOCK_DEMEN + j;
//         result[index] = result[index-1] ^ result[index-4]; 
//       }
//     }

//   }

// }

int main(int argc, char* argv[]) {
  
  AES aes;
  unsigned char input[BLOCK_SIZE] = {0x32, 0x88, 0x31, 0xe0,
                                     0x43, 0x5a, 0x31, 0x37,
                                     0xf6, 0x30, 0x98, 0x07, 
                                     0xa8, 0x8d, 0xa2, 0x34
                                    };

  unsigned char cipherKey[BLOCK_SIZE] = {0x2b, 0x28, 0xab, 0x09,
                                         0x7e, 0xae, 0xf7, 0xcf,
                                         0x15, 0xd2, 0x15, 0x4f, 
                                         0x16, 0xa6, 0x88, 0x3c
                                        };
  
  // unsigned char key[16] = {0xa0, 0x88, 0x23, 0x2a,
  //                          0xfa, 0x54, 0xa3, 0x6c,
  //                          0xfe, 0x2c, 0x39, 0x76, 
  //                          0x17, 0xb1, 0x39, 0x05
  //                         };
  //printf("%d %d \n", (int)sizeof(input), (int)sizeof(input[0]));

  //aes.generateKey(cipherKey);
  aes.encode(input, cipherKey);
  // unsigned char keySchedule[(ROUND_NUM+1)*BLOCK_SIZE];
  // generate_key(cipherKey, keySchedule);

  // shit_rows(input);
  // mix_columns(input);
  // add_roundkey(input, key);

  for(int i=0; i<4; i++){
    for(int j=0; j<4; j++){
      printf("0x%x ",input[i*BLOCK_DEMEN + j]);  
    }
    printf("\n");
  }
  printf("\n");

  aes.decode(input, cipherKey);
  

  for(int i=0; i<4; i++){
    for(int j=0; j<4; j++){
      printf("0x%x ",input[i*BLOCK_DEMEN + j]);  
    }
    printf("\n");
  }
  // printf("\n");
  // for(int i=0; i<BLOCK_DEMEN; i++){
  //   for(int j=0; j<(ROUND_NUM+1)*BLOCK_DEMEN; j++){
  //     printf("0x%x ", keySchedule[i*(ROUND_NUM+1)*BLOCK_DEMEN + j]);
  //   }
  //   printf("\n");
  // }

  // const int kDataLen = 4;

  // float a = 2.0f;
  // float host_x[kDataLen] = {1.0f, 2.0f, 3.0f, 4.0f};
  // float host_y[kDataLen];

  // // Copy input data to device.
  // float* device_x;
  // float* device_y;
  // cudaMalloc(&device_x, kDataLen * sizeof(float));
  // cudaMalloc(&device_y, kDataLen * sizeof(float));
  // cudaMemcpy(device_x, host_x, kDataLen * sizeof(float),
  //            cudaMemcpyHostToDevice);

  // // Launch the kernel.
  // axpy<<<1, kDataLen>>>(a, device_x, device_y);

  // // Copy output data to host.
  // cudaDeviceSynchronize();
  // cudaMemcpy(host_y, device_y, kDataLen * sizeof(float),
  //            cudaMemcpyDeviceToHost);

  // // Print the results.
  // for (int i = 0; i < kDataLen; ++i) {
  //   std::cout << "y[" << i << "] = " << host_y[i] << "\n";
  // }

  // cudaDeviceReset();
  return 0;
}

