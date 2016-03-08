#include <stdio.h>
#include <stdlib.h>   
#include <time.h> 

#include <algorithm> 
#include <iostream>
#include <fstream>
#include <vector>

#include "aes.h"
#include "GPUaes.h"

const char *encoded = "encoded";
const char *decoded = "decoded";
const char *CUDAencoded = "CUDAencoded";
const char *CUDAdecoded = "CUDAdecoded";




const unsigned char cipherKey[BLOCK_SIZE] = {0x2b, 0x28, 0xab, 0x09,
                                             0x7e, 0xae, 0xf7, 0xcf,
                                             0x15, 0xd2, 0x15, 0x4f, 
                                             0x16, 0xa6, 0x88, 0x3c
                                            };



bool readFile(std::vector<std::vector<unsigned char> > &target, char *fileName){
  std::ifstream input(fileName);

  char c;

  while(!input.eof()){
    std::vector<unsigned char> buffer(BLOCK_SIZE, 0);
    for(int j=0; j<BLOCK_SIZE; j++){
//      i = j;
      if(!input.get(c))
        break;
      buffer[j] = (unsigned char) c;
//      std::cout<<buffer[j];
    }
    target.push_back(buffer);
  }
  
  input.close();

  return true;
}

void writeFile(const std::vector<std::vector<unsigned char> > &target, const char* fileName){
  std::ofstream output(fileName);
//  printf("\n");

  for(unsigned int i=0; i<target.size(); i++){
    for(int j=0; j<target[i].size(); j++){
      output.put((char)(target[i][j]));
  //    std::cout<<((char)(target[i][j]));
    }
  }

  //printf("\n");
  
  output.close();

  return;
}

time_t cudaEncode(std::vector<std::vector<unsigned char> > &text, const unsigned char* key){
  time_t t1, t2;

  unsigned char *d_text;
  cudaMalloc((void**)&d_text, sizeof(unsigned char)*text.size()*text[0].size());

  //printf("Data size: %d\n", sizeof(unsigned char)*text.size()*text[0].size());

  unsigned char *dst = d_text;
  for(std::vector<std::vector<unsigned char> >::iterator it = text.begin(); it != text.end(); ++it){
    unsigned char *src = &((*it)[0]);
    size_t sz = it->size();

    cudaMemcpy(dst, src, sizeof(unsigned char)*sz, cudaMemcpyHostToDevice);
    dst += sz;
  }

  unsigned char *d_key;
  cudaMalloc((void**)&d_key, sizeof(unsigned char)*BLOCK_SIZE);
  cudaMemcpy(d_key, key, sizeof(unsigned char)*BLOCK_SIZE, cudaMemcpyHostToDevice);

  int threadsPerBlock = std::min((int)text.size(), 256);
  int blocksPerGrid = (text.size() + threadsPerBlock - 1) / threadsPerBlock;

  //printf("%d blocks %d threads \n", blocksPerGrid, threadsPerBlock);

  t1 = clock();

  encode <<<blocksPerGrid, threadsPerBlock>>> (d_text, d_key); 


  cudaError_t err = cudaGetLastError();
  if (err != cudaSuccess){
    printf("Error: %s\n", cudaGetErrorString(err));
  }
  
  cudaDeviceSynchronize();

  t2 = clock();
  
  dst = d_text;
  for(std::vector<std::vector<unsigned char> >::iterator it = text.begin(); it != text.end(); ++it){
    unsigned char *src = &((*it)[0]);
    size_t sz = it->size();

    cudaMemcpy(src, dst, sizeof(unsigned char)*sz, cudaMemcpyDeviceToHost);
    dst += sz;
  }

  cudaFree(d_text);
  cudaFree(d_key);

  return t2 - t1;
}

time_t cudaDecode(std::vector<std::vector<unsigned char> > &text, const unsigned char* key){
  time_t t1, t2;

  unsigned char *d_text;
  cudaMalloc((void**)&d_text, sizeof(unsigned char)*text.size()*text[0].size());

  //printf("Data size: %d\n", sizeof(unsigned char)*text.size()*text[0].size());

  unsigned char *dst = d_text;
  for(std::vector<std::vector<unsigned char> >::iterator it = text.begin(); it != text.end(); ++it){
    unsigned char *src = &((*it)[0]);
    size_t sz = it->size();

    cudaMemcpy(dst, src, sizeof(unsigned char)*sz, cudaMemcpyHostToDevice);
    dst += sz;
  }

  unsigned char *d_key;
  cudaMalloc((void**)&d_key, sizeof(unsigned char)*BLOCK_SIZE);
  cudaMemcpy(d_key, key, sizeof(unsigned char)*BLOCK_SIZE, cudaMemcpyHostToDevice);

  int threadsPerBlock = std::min((int)text.size(), 256);
  int blocksPerGrid = (text.size() + threadsPerBlock - 1) / threadsPerBlock;

  //printf("%d blocks %d threads \n", blocksPerGrid, threadsPerBlock);

  t1 = clock();

  decode <<<blocksPerGrid, threadsPerBlock>>> (d_text, d_key); 


  cudaError_t err = cudaGetLastError();
  if (err != cudaSuccess){
    printf("Error: %s\n", cudaGetErrorString(err));
  }
  
  cudaDeviceSynchronize();

  t2 = clock();
  
  dst = d_text;
  for(std::vector<std::vector<unsigned char> >::iterator it = text.begin(); it != text.end(); ++it){
    unsigned char *src = &((*it)[0]);
    size_t sz = it->size();

    cudaMemcpy(src, dst, sizeof(unsigned char)*sz, cudaMemcpyDeviceToHost);
    dst += sz;
  }

  cudaFree(d_text);
  cudaFree(d_key);

  return t2 - t1;
}



int main(int argc, char* argv[]) {
  
  if(argc!=3){
    printf("Usage: main <inputfile> <key>\n");
    return 1;
  }

  std::vector<std::vector<unsigned char> > text;
  time_t t1, t2;
  AES aes;

  readFile(text, argv[1]);
  
  //CPU encoding ->
  t1 = clock();

  for(unsigned int i=0; i<text.size(); i++){
    aes.encode(text[i].data(), cipherKey);
  }

  t2 = clock();
  double tNormal =  1000*((double)(t2-t1))/CLOCKS_PER_SEC;
  printf("CPU encoding %f ms\n", tNormal);

  writeFile(text, encoded);
  //<- CPU encoding

  //CPU decoding ->
  t1 = clock();
  for(unsigned int i=0; i<text.size(); i++){
    aes.decode(text[i].data(), cipherKey);
  }

  t2 = clock();
  tNormal =  1000*((double)(t2-t1))/CLOCKS_PER_SEC;
  printf("CPU decoding %f ms\n", tNormal);

  writeFile(text, decoded);
  //<- CPU decoding

  //GPU coding ->
  time_t cudaEncodeTime = cudaEncode(text, cipherKey);

  tNormal =  1000*(double)cudaEncodeTime/CLOCKS_PER_SEC;
  printf("GPU encoding %f ms\n", tNormal);

  writeFile(text, CUDAencoded);
  //<-GPU coding

  //GPU decoding ->
  time_t cudaDecodeTime = cudaDecode(text, cipherKey);

  tNormal =  1000*(double)cudaDecodeTime/CLOCKS_PER_SEC;
  printf("GPU decoding %f ms\n", tNormal);

  writeFile(text, CUDAdecoded);
  //<- GPU decoding 
  cudaDeviceReset();
  return 0;
}

