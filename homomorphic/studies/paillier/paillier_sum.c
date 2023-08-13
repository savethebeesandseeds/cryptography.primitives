/*
 * File: paillier_sum.c
 * 
 *    result = A + B
 * 
 * Description:
 * This file contains an implementation of the Paillier cryptosystem in C language. The Paillier cryptosystem is a public-key
 * cryptosystem with homomorphic properties, which means the sum of the plaintexts equals the decryption of the sum of their 
 * ciphertexts. The cryptosystem relies on OpenSSL for arbitrary precision arithmetic and random prime generation. This implementation
 * includes the following functionalities: system initialization, encryption, decryption, ciphertext addition, and printing utilities.
 * 
 * Definitions:
 * - BIGNUM: An OpenSSL structure for arbitrary precision integer arithmetic.
 * - BN_CTX: An OpenSSL structure for efficient BIGNUM calculations.
 * - PRIME_SIZE: The size of the random prime numbers to be generated.
 * 
 * Functions:
 * - PaillierInitialize: Initializes the Paillier cryptosystem by generating random primes and calculating n, g, lambda, and mu.
 * - PaillierEncrypt: Encrypts a given plaintext with the Paillier cryptosystem.
 * - PaillierDecrypt: Decrypts a given ciphertext with the Paillier cryptosystem.
 * - PaillierAddCiphertexts: Adds two ciphertexts in the Paillier cryptosystem.
 * - print_BN: Prints a given BIGNUM in hexadecimal or decimal format.
 * - main: Driver function that demonstrates the encryption, decryption and addition of plaintexts and ciphertexts.
 * 
 * Usage:
 * Compile the code using gcc or any compatible compiler. Run the generated executable file. The output will display the initial keys,
 * encrypted values of two sample plaintexts (5 and 6), the result of their ciphertext addition, and the decrypted result which should 
 * be equal to the sum of the original plaintexts.
 * 
 * Note:
 * Please ensure that OpenSSL is properly installed and linked during compilation.
 * 
 * Dependencies:
 * - OpenSSL library
 *
 * Compiler:
 * - GCC
 * 
 * Compile with:
 * - gcc -o paillier_sum paillier_sum.c -lcrypto
 * 
 * Author: [waajacu.com & chat.openai.com]
 * Date: [07 June 2023]
 */
#include <openssl/bn.h>
#define PRIME_SIZE 100 // Size of the random prime numbers generated

// Initialize
void PaillierInitialize(BIGNUM* n, BIGNUM* g, BIGNUM* lambda, BIGNUM* mu, BN_CTX* ctx);
// Encryption
void PaillierEncrypt(BIGNUM* result, BIGNUM* plaintext, BIGNUM* n, BIGNUM* g, BN_CTX* ctx);
// Decryption
void PaillierDecrypt(BIGNUM* result, BIGNUM* ciphertext, BIGNUM* n, BIGNUM* lambda, BIGNUM* mu, BN_CTX* ctx);
// Sum
void PaillierAddCiphertexts(BIGNUM* result, BIGNUM* ciphertextA, BIGNUM* ciphertextB, BIGNUM* n, BN_CTX* ctx);
// Print utility
void print_BN(BIGNUM *bn, const char *label, int hex);
// Main
int main() {
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* plaintextA = BN_new();
  BIGNUM* plaintextB = BN_new();
  BIGNUM* ciphertextA = BN_new();
  BIGNUM* ciphertextB = BN_new();

  BN_set_word(plaintextA, 5); // Set value A
  BN_set_word(plaintextB, 6); // Set value B

  BIGNUM* n = BN_new(); // n = p * q : paillier public key
  BIGNUM* g = BN_new(); // g = n + 1
  BIGNUM* lambda = BN_new(); // lambda = abs((p - 1) * (q - 1)) / gcd(p - 1, q - 1)
  BIGNUM* mu = BN_new(); // mu = ((g^lambda mod n^2 - 1) / n)^-1 mod n
  
  // Assign some values
  PaillierInitialize(n, g, lambda, mu, ctx);

  // At this point the keys of the schema should be initialized
  print_BN(n,"n",0x1);
  print_BN(g,"g",0x1);
  print_BN(lambda,"lambda",0x1);
  print_BN(mu,"mu",0x1);

  // Encrypt the plaintexts
  PaillierEncrypt(ciphertextA, plaintextA, n, g, ctx);
  PaillierEncrypt(ciphertextB, plaintextB, n, g, ctx);

  // Add the ciphertexts
  BIGNUM* sum_ciphertext = BN_new();
  PaillierAddCiphertexts(sum_ciphertext, ciphertextA, ciphertextB, n, ctx);

  // Decrypt the sum
  BIGNUM* decrypted_sum = BN_new();
  PaillierDecrypt(decrypted_sum, sum_ciphertext, n, lambda, mu, ctx);

  // At this point, decrypted_sum should contain the sum of plaintextA and plaintextB
  print_BN(plaintextA,"plaintextA",0x0);
  print_BN(plaintextB,"plaintextB",0x0);
  print_BN(ciphertextA,"ciphertextA",0x1);
  print_BN(ciphertextB,"ciphertextB",0x1);
  print_BN(sum_ciphertext,"sum_ciphertext",0x1);
  print_BN(decrypted_sum,"decrypted_sum",0x0);

  // Clean up
  BN_free(n);
  BN_free(g);
  BN_free(lambda);
  BN_free(mu);
  BN_free(plaintextA);
  BN_free(plaintextB);
  BN_free(ciphertextA);
  BN_free(ciphertextB);
  BN_free(sum_ciphertext);
  BN_free(decrypted_sum);
  BN_CTX_free(ctx);

  return 0;
}
void PaillierInitialize(BIGNUM* n, BIGNUM* g, BIGNUM* lambda, BIGNUM* mu, BN_CTX* ctx){
  BIGNUM* p = BN_new();
  BIGNUM* q = BN_new();
  BIGNUM *p_minus_1 = BN_new();
  BIGNUM *q_minus_1 = BN_new();
  BIGNUM *gcd = BN_new();
  BIGNUM *temp = BN_new();
  BIGNUM *L = BN_new();

  BN_generate_prime_ex(p, PRIME_SIZE, 0, NULL, NULL, NULL); // large random prime number
  BN_generate_prime_ex(q, PRIME_SIZE, 0, NULL, NULL, NULL); // large random prime number
  BN_mul(n, p, q, ctx); // n = p * q
  BN_add(g, n, BN_value_one()); // g = n + 1

  // Calculate p - 1 and q - 1
  BN_sub(p_minus_1, p, BN_value_one());
  BN_sub(q_minus_1, q, BN_value_one());

  // Calculate gcd(p - 1, q - 1)
  BN_gcd(gcd, p_minus_1, q_minus_1, ctx);

  // Calculate lambda = abs((p - 1) * (q - 1)) / gcd(p - 1, q - 1)
  BN_mul(temp, p_minus_1, q_minus_1, ctx);
  BN_div(lambda, NULL, temp, gcd, ctx);

  // Calculate g^lambda mod n^2
  BIGNUM *n_square = BN_new();
  BN_mul(n_square, n, n, ctx); // n_square = n * n
  BN_mod_exp(temp, g, lambda, n_square, ctx); // temp = g^lambda mod n^2

  // Calculate L(g^lambda mod n^2) = (g^lambda mod n^2 - 1) / n
  BN_sub(temp, temp, BN_value_one()); // temp = g^lambda mod n^2 - 1
  BN_div(L, NULL, temp, n, ctx); // L = (g^lambda mod n^2 - 1) / n

  // Calculate mu, which is the modular inverse of L mod n
  BN_mod_inverse(mu, L, n, ctx); // mu = L^-1 mod n

  BN_free(p);
  BN_free(q);
  BN_free(p_minus_1);
  BN_free(q_minus_1);
  BN_free(gcd);
  BN_free(temp);
  BN_free(L);
  BN_free(n_square);
}

// Encryption
void PaillierEncrypt(BIGNUM* result, BIGNUM* plaintext, BIGNUM* n, BIGNUM* g, BN_CTX* ctx) {
  BIGNUM* r = BN_new();
  BIGNUM* n_square = BN_new();

  BN_CTX_start(ctx);

  BN_mul(n_square, n, n, ctx); // n^2

  // choose random r where 1 < r < n
  BN_rand_range(r, n);

  // ensure 1 < r < n
  if (BN_cmp(r, BN_value_one()) <= 0) {
    BN_add_word(r, 2);
  }

  // result = g^plaintext * r^n mod n^2
  BN_mod_exp(result, g, plaintext, n_square, ctx);
  BN_mod_exp(r, r, n, n_square, ctx);
  BN_mul(result, result, r, ctx);
  BN_mod(result, result, n_square, ctx);

  BN_free(r);
  BN_free(n_square);
  BN_CTX_end(ctx);
}

// Decryption
void PaillierDecrypt(BIGNUM* result, BIGNUM* ciphertext, BIGNUM* n, BIGNUM* lambda, BIGNUM* mu, BN_CTX* ctx) {
  BIGNUM* n_square = BN_new();
  BIGNUM* temp = BN_new();

  BN_CTX_start(ctx);

  BN_mul(n_square, n, n, ctx); // n^2

  // temp = ciphertext^lambda mod n^2 - 1
  BN_mod_exp(temp, ciphertext, lambda, n_square, ctx);
  BN_sub_word(temp, 1);

  // result = (temp / n) * mu mod n
  BN_div(temp, NULL, temp, n, ctx);
  BN_mul(result, temp, mu, ctx);
  BN_mod(result, result, n, ctx);

  BN_free(n_square);
  BN_free(temp);
  BN_CTX_end(ctx);
}

// Sum
void PaillierAddCiphertexts(BIGNUM* result, BIGNUM* ciphertextA, BIGNUM* ciphertextB, BIGNUM* n, BN_CTX* ctx) {
  BIGNUM* n_square = BN_new();

  BN_CTX_start(ctx);

  BN_mul(n_square, n, n, ctx); // n^2

  // result = (ciphertextA * ciphertextB) mod n^2
  BN_mul(result, ciphertextA, ciphertextB, ctx);
  BN_mod(result, result, n_square, ctx);

  BN_free(n_square);
  BN_CTX_end(ctx);
}
// Print utility
void print_BN(BIGNUM *bn, const char *label, int hex) {
  char *char_temp;
  if(hex) {
    fprintf(stdout,"%s:\t 0x%s\n", label, (char_temp = (char*)BN_bn2hex(bn)));
  } else {
    fprintf(stdout,"%s:\t %s\n", label, (char_temp = (char*)BN_bn2dec(bn)));
  }
  OPENSSL_free(char_temp);
}