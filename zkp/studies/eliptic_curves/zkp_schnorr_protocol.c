/*  
    Implementing the non interactive Schnorr protocol, 
    with the Fiat-Shamir heuristic on eliptic curves.

    "Schnorr Non-interactive Zero-Knowledge Proof"

    https://www.potaroo.net/ietf/rfc/rfc8235.html
 */
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#define SECRET 1234
#define CURVE NID_X9_62_prime256v1

void sha256_bn(BIGNUM *bn, unsigned char *digest) {
  // Convert bn to bytes
  int len = BN_num_bytes(bn);
  unsigned char *bytes = malloc(len);
  BN_bn2bin(bn, bytes);
  // Create a message digest context
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  // Initialize the digest operation with SHA256
  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
  // Provide the message to be digested
  EVP_DigestUpdate(ctx, bytes, len);
  // Finalize the digest
  EVP_DigestFinal_ex(ctx, digest, NULL);
  // Clean up
  EVP_MD_CTX_free(ctx);
  free(bytes);
}
void print_EC_POINT_hex(EC_GROUP *curve, const EC_POINT *ec_point, const char *label) {
  char *char_temp;
  fprintf(stdout,"%s:\t %s\n",label, (char_temp = (char*)EC_POINT_point2hex(curve, ec_point, 2, NULL)));
  OPENSSL_free(char_temp);
}
void print_BN_hex(BIGNUM *bn, const char *label) {
  char *char_temp;
  fprintf(stdout,"%s:\t %s\n", label, (char_temp = (char*)BN_bn2hex(bn)));
  OPENSSL_free(char_temp);
}
// Commitment and response are now ready to be used by the verifier
// ...  Given the commitment C, the response r, the generator g, 
//      the challenge h, and the public key P, 
//      the verifier can check whether: 
//          C = r * g + h * P

// If this equation holds, then the verifier accepts the proof. 
// Otherwise, the verifier rejects it. This equation basically 
// checks whether the prover knows the secret that was used to 
// generate P, without revealing the actual secret.
void verifier(EC_POINT **publicKey, BIGNUM **response, BIGNUM **challenge, EC_POINT **commitment){
  /* validate the inputs */
  if(*publicKey == NULL){
    fprintf(stderr, "ERROR: publicKey should not be NULL in the verifier function. \n");
    return;
  }
  if(*response == NULL){
    fprintf(stderr, "ERROR: response should not be NULL in the verifier function. \n");
    return;
  }
  if(*challenge == NULL){
    fprintf(stderr, "ERROR: challenge should not be NULL in the verifier function. \n");
    return;
  }
  if(*commitment == NULL){
    fprintf(stderr, "ERROR: commitment should not be NULL in the verifier function. \n");
    return;
  }

  EC_GROUP *curve = EC_GROUP_new_by_curve_name(CURVE);
  const EC_POINT *generator = EC_GROUP_get0_generator(curve);

  EC_POINT *rg = EC_POINT_new(curve);
  EC_POINT *hP = EC_POINT_new(curve);
  EC_POINT *rghP = EC_POINT_new(curve);
  BN_CTX *ctx = BN_CTX_new();
  int out;
  int equal;

  /* build r * g part */
  out = EC_POINT_mul(curve, rg, NULL, generator, *response, ctx);
  if(!out) fprintf(stderr, "rg failed. \n");

  /* build h * P part */
  out = EC_POINT_mul(curve, hP, NULL, *publicKey, *challenge, ctx);
  if(!out) fprintf(stderr, "hP failed. \n");

  /* build (r * g + h * P) part */
  out = EC_POINT_add(curve, rghP, hP, rg, ctx);
  if(!out) fprintf(stderr, "rghP failed. \n");
  
  /* evaluate the comparizon r * g = C + h * P */
  equal = EC_POINT_cmp(curve, *commitment, rghP, ctx);

  print_EC_POINT_hex(curve, rg, "rg");
  print_EC_POINT_hex(curve, hP, "hP");
  print_EC_POINT_hex(curve, rghP, "rghP");
  fprintf(stdout,"C = r * g + h * P. [equal]: %d==0\n",equal);
  
  /* Display the verifier results */
  if (equal == 0) {
    // The verifier equation r * g = C + h * P holds.
    printf("The verifier equation holds.\n");
  } else if (equal == -1) {
    fprintf(stderr,"Error perfoming the verifier equation.\n");
  } else {
    // The verifier equation r * g = C + h * P does not hold.
    printf("The verifier equation does not hold.\n");
  }

  /* Free the verifier variables */
  EC_POINT_free(rg);
  EC_POINT_free(hP);
  EC_POINT_free(rghP);
  BN_CTX_free(ctx);
  EC_GROUP_free(curve);
}

//  This function simulates the operations performed by the "prover" 
//  in a Zero-Knowledge Proof (ZKP), in this case using the Schnorr protocol. 
//    The prover's task is to prove possession of a secret without revealing that secret.
void prover(EC_POINT **publicKey, BIGNUM **response, BIGNUM **challenge, EC_POINT **commitment){
  /* validate the inputs */
  if(*publicKey != NULL){
    fprintf(stderr, "ERROR: publicKey should be initialized to NULL in the prover function. \n");
    return;
  }
  if(*response != NULL){
    fprintf(stderr, "ERROR: response should be initialized to NULL in the prover function. \n");
    return;
  }
  if(*challenge != NULL){
    fprintf(stderr, "ERROR: challenge should be initialized to NULL in the prover function. \n");
    return;
  }
  if(*commitment != NULL){
    fprintf(stderr, "ERROR: commitment should be initialized to NULL in the prover function. \n");
    return;
  }

  /* make the group in the eliptic curve and get the generator */
  EC_GROUP *curve = EC_GROUP_new_by_curve_name(CURVE);
  const EC_POINT *generator = EC_GROUP_get0_generator(curve);

  /* allocate space for the shared variables */
  *challenge = NULL;
  *response = BN_new();
  *publicKey = EC_POINT_new(curve);
  *commitment = EC_POINT_new(curve);

  /* allocate space for the local variables */
  BIGNUM *secret = BN_new();
  BIGNUM *order = BN_new();
  BIGNUM *random = BN_new();
  BIGNUM *tmp = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  unsigned char commitment_digest[SHA256_DIGEST_LENGTH];

  // get the group order
  EC_GROUP_get_order(curve, order, NULL);
  if (BN_is_zero(order)) {
    fprintf(stderr, "Error: unable to get GRUOP orver. Order is zero.\n");
    // Handle error...
    return;
  }

  // Generate a random number
  BN_rand_range(random, order);

  // Compute commitment: commitment = random * g
  EC_POINT_mul(curve, *commitment, NULL, generator, random, NULL);

  // Hash secret to create challenge
  BN_set_word(secret, SECRET);
  sha256_bn(secret, commitment_digest);
  *challenge = BN_bin2bn(commitment_digest, SHA256_DIGEST_LENGTH, NULL);

  // Compute response: response = (random - challenge * secret) mod order
  BN_mod_mul(tmp, *challenge, secret, order, ctx);
  BN_mod_sub(*response, random, tmp, order, ctx);

  // Calculate the public key: P = secret * g
  EC_POINT_mul(curve, *publicKey, NULL, generator, secret, NULL);

  // print the variables
  print_BN_hex(order, "order");
  print_BN_hex(secret, "secret");
  print_BN_hex(*challenge, "challenge");
  print_BN_hex(*response, "response");
  print_EC_POINT_hex(curve, generator, "generator");
  print_EC_POINT_hex(curve, *commitment, "commitment");
  print_EC_POINT_hex(curve, *publicKey, "publicKey");

  // Free the Prover variables
  BN_free(secret);
  BN_free(order);
  BN_free(random);
  BN_free(tmp);
  BN_CTX_free(ctx);
  EC_GROUP_free(curve);
}


// Main function
int main() {
  BIGNUM *response = NULL;
  BIGNUM *challenge = NULL;
  EC_POINT *publicKey = NULL;
  EC_POINT *commitment = NULL;
  
  // Prove the ZKP
  prover(&publicKey, &response, &challenge, &commitment);

  // Validate the ZKP
  verifier(&publicKey, &response, &challenge, &commitment);

  // Clean up
  BN_free(response);
  BN_free(challenge);
  EC_POINT_free(commitment);
  EC_POINT_free(publicKey);
  // EC_POINT_free(generator);

  return 0;
}
