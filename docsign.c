/* docsign.c -- All functions related the Simplified DES Cipher.
 * Copyright (C) 2019 Ioannis Sophocleous
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/** @file docsign.c
 *  @brief All functions related to the Digital Sign of a document and it's
 *         verification using SHA256 and RSA as provided by OpenSSL.
 *
 *  @autor Ioannis Sophocleous
 *  @bug No bugs, we used a good spray to kill them.
 */

/* Libraries */
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

/* Define Macros */
#define PUBLIC          // Visible out of file
#define PRIVATE static  // Visible only in file

/* Declarations */
#define PAGE_SIZE 1024
#define PRIVATE_KEY "private.pem"
#define PUBLIC_KEY "public.pem"

/* Function Prototypes */
PRIVATE int verifySignature(char*);
PRIVATE int signFile(char*);
PRIVATE void digestMessage(char**, int, unsigned char**, int);
#ifdef DEBUG
PRIVATE int generateKeys();
#endif
PRIVATE char *readFile(const char*);
PRIVATE void writeFile(const char*, const char*, const unsigned char*);
PRIVATE char *getFileName(const char*);
PRIVATE void handleErrors(void);
PUBLIC int main(int, char**);

/** @brief Verifies the File given using the Public Key.
 *
 *  @return Returns 1 if all successfull and 0 if not
 */
PRIVATE int verifySignature(char *filePath) {
  /* Variables */
  char *data = NULL, *text = NULL;
  unsigned char *signature, *digest;
  unsigned int digest_length = 0;
  RSA *publicKey = NULL;
  FILE *fp = NULL;
  long dataSize = 0;

  // Read Public Key
  fp = fopen(PUBLIC_KEY, "r");
  if(fp == NULL) {
    printf("Can't open public.pem.\n");
    exit(1);
  }
  publicKey = RSA_new();
  if(PEM_read_RSA_PUBKEY(fp, &publicKey, NULL, NULL) == NULL) {
    printf("Error reading public.pem.\n");
    exit(1);
  }
  fclose(fp);

  // Read Signature and File data
  if((fp = fopen(filePath, "rb")) == NULL) {
    printf("Can't open %s.\n", filePath);
    exit(1);
  }
  fseek(fp, 0, SEEK_END);
  dataSize = ftell(fp);
  rewind(fp);
  data = (char*)malloc(dataSize);
  fread(data, dataSize, 1, fp);
  fclose(fp);

  text = (char*)malloc(dataSize * sizeof(char));
  memcpy(text, data, dataSize - 256);
  signature = (unsigned char*)malloc(256 * sizeof(unsigned char));
  memcpy(signature, &data[dataSize - 256], 256);

  //***********************************************************
#ifdef DEBUG
  fp = fopen("s2.txt", "w+");
  if(fp != NULL) {
    //fwrite(text, sizeof(char), dataSize - 256, fp);
    fwrite(signature, sizeof(unsigned char), 256, fp);
    fclose(fp);
  }
#endif
  //***********************************************************

  // Digest Message  
  digestMessage(&text, dataSize - 256, &digest, digest_length);

  // Check Verification
  return RSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature, 256, publicKey);
}

/** @brief Signs the File given with a Signature that it Generates using RSA 
 *         keys and the SHA256 Hash Function
 *
 *  @return Returns 1 if all successfull and 0 if not
 */
PRIVATE int signFile(char *filePath) {
  /* Variables */
  char *message = NULL, *temp = NULL;
  unsigned char *digest = NULL, *sign = NULL;
  unsigned int digest_length = 0, sign_length;
  RSA *privateKey = NULL;
  FILE *fp = NULL;
  
  // Read File with message
  message = readFile(filePath);
  if(message == NULL) {
    ERR_free_strings();
    return 0;
  }
  
  // Try to generate Keys
#ifdef DEBUG
  if(!generateKeys())
    handleErrors();
#endif
  
  // Read Private Key
  fp = fopen(PRIVATE_KEY, "r");
  if(fp == NULL) {
    printf("Can't open private.pem.\n");
    exit(1);
  }

  privateKey = RSA_new();
  if(PEM_read_RSAPrivateKey(fp, &privateKey, NULL, NULL) == NULL) {
    printf("Error reading private.pem.\n");
    exit(1);
  }
  fclose(fp);
  
  // Digest Message  
  digestMessage(&message, strlen(message), &digest, digest_length);
  
  // Sign Message
  sign = (unsigned char*)malloc(sizeof(unsigned char) * PAGE_SIZE);
  if(!RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH, sign, &sign_length, 
                privateKey))
    handleErrors();

  // Write new File with Signature
  temp = getFileName(filePath);
  writeFile(strcat(temp, ".signed"), message, sign);

  //***********************************************************
#ifdef DEBUG
  fp = fopen("s1.txt", "w+");
  if(fp != NULL) {
    fwrite(sign, sizeof(unsigned char), 256, fp);
    fclose(fp);
  } else {
    printf("Can't open file.\n");
    exit(1);
  }
#endif
  //***********************************************************
  
  free(sign);
  free(message);
  free(digest);
  free(temp);
  return 1;
}

/** @brief Generate the Digest for the Message to Sign using SHA256 
 *         Hash Functions
 *
 *  @return Should not return
 */
PRIVATE void digestMessage(char **message, int message_length,   
                    unsigned char **digest, int digest_length) {
  /* Variables */
  SHA256_CTX ctx;
  
  // Allocate memory
  *digest = (unsigned char*)malloc(sizeof(unsigned char)*SHA256_DIGEST_LENGTH);
  if(*digest == NULL) {
    handleErrors();
  }
  
  // Digest Message
  if(!SHA256_Init(&ctx))
    handleErrors();
  if(!SHA256_Update(&ctx, *message, message_length))
    handleErrors();
  if(!SHA256_Final(*digest, &ctx))
    handleErrors();
  digest_length = (unsigned int)SHA256_DIGEST_LENGTH;
  
}

#ifdef DEBUG
/** @brief Generate Private and Public keys using RSA of 2048 bits
 *
 *  @return Returns 1 if all successfull and 0 if not
 */
PRIVATE int generateKeys() {
  /* Variables */
  int ret = 0;
  RSA *rsa = NULL;
  BIGNUM *bne = NULL;
  BIO *bp_public = NULL, *bp_private = NULL;
  int bits = 2048;
  unsigned long e = RSA_F4;
 
  // Create Big Number to calculate big Prime Numbers
  bne = BN_new();
  ret = BN_set_word(bne, e);
  if(ret != 1){
    BN_free(bne);
    
    return 0;
  }

  // Generate rsa key
  rsa = RSA_new();
  ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
  if(ret != 1){
    RSA_free(rsa);
    BN_free(bne);
    
    return 0;
  }
 
  // Save public key
  bp_public = BIO_new_file(PUBLIC_KEY, "w+");
  ret = PEM_write_bio_RSA_PUBKEY(bp_public, rsa);
  if(ret != 1){
    BIO_free_all(bp_public);
    RSA_free(rsa);
    BN_free(bne);
    return 0;
  }
 
  // Save private key
  bp_private = BIO_new_file(PRIVATE_KEY, "w+");
  ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);
 
  BIO_free_all(bp_public);
  BIO_free_all(bp_private);
  RSA_free(rsa);
  BN_free(bne);
 
  return (ret == 1);
}
#endif

/** @brief Reads content from a File
 *
 *  @return The content of the File as a String
 */
PRIVATE char *readFile(const char *filename) {
  /* Variables */
  char *fcontent = NULL;
  int fsize = 0;
  FILE *fp;

  fp = fopen(filename, "r");
  if(fp) {
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    
    rewind(fp);
    
    fcontent = (char*) malloc(sizeof(char) * (fsize+1));
    fread(fcontent, 1, fsize, fp);
    fcontent[fsize]='\0';
    
    fclose(fp);
  } else {
    printf("Can't open %s.\n", filename);
    exit(1);
  }
  
  return fcontent;
}

/** @brief Write given String in new File
 *
 *  @return Should not return
 */
PRIVATE void writeFile(const char *filepath, const char *data, 
                        const unsigned char *signature) {
  /* Variables */
  FILE *fp = fopen(filepath, "w+");
  
  if(fp != NULL) {
    fwrite(data, sizeof(char), strlen(data), fp);
    fwrite(signature, sizeof(unsigned char), 256, fp);
    fclose(fp);
  } else {
    printf("Can't open %s.\n", filepath);
    exit(1);
  }
}

/** @brief Get Path to File without full Path
 *
 *  @return The Path to File without the full Path
 */
PRIVATE char *getFileName(const char* path) {
  /* Variables */
  char *result, *ssc;
  int l = 0;

  result = (char*) malloc(sizeof(char) * strlen(path) + 1);
  strcpy(result, path);
  ssc = strstr(result, "/");
  
  while(ssc) {
    l = strlen(ssc) + 1;
    result = &result[strlen(result)-l+2];
    ssc = strstr(result, "/");
  };
  
  return result;
}

/** @brief Handles Error Messages
 *
 *  @return Should not return
 */
PRIVATE void handleErrors(void) {
  unsigned long errCode;

  printf("An error occurred\n");
  while((errCode = ERR_get_error())) {
    char *err = ERR_error_string(errCode, NULL);
    printf("%s\n", err);
  }
  
  abort();
}

/** @brief The main function of the program.
 *
 *  @param argc The size of the arguments Array
 *  @param argv The arguments Array
 *  @return Should not return
 */
PUBLIC int main(int argc, char **argv) {

  // Load OpenSSL
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  ERR_load_crypto_strings();
  
  // Check arguments
  if((argc == 3) && !(strcmp(argv[1], "-s"))) {
    if(signFile(argv[2]))
      printf("Document %s was just signed. Signed document: %s.\n", argv[2], 
              strcat(getFileName(argv[2]), ".signed"));
  } else if((argc == 3) && !(strcmp(argv[1], "-v"))) {
	  if(verifySignature(argv[2]))
		  printf("Digital signature is valid.\n");
	  else
		  printf("Digital signature is invalid.\n");
  } else {
    printf("Usage: docsign -sv \n");
    printf("-s sign document \n");
    printf("-v validate signature \n");
  }
  
  ERR_free_strings();
  
  return 1;
}

