/*
 * 1D_DCT.c
 *
 * This program implements 1-dimensional Discrete Cosine Transformation (DCT) 
 * and Inverse Discrete Cosine Transformation (IDCT). DCT and IDCT are widely 
 * used in signal and image processing domains, including steganography.
 *
 * Moreover, the program demonstrates a simple form of steganography where a secret
 * value is hidden into the high-frequency components of a DCT-transformed array.
 *
 * Program flow:
 * - The program first defines a 1D array of data.
 * - It then hides a secret value in this data using DCT.
 * - The secret is hidden in the high-frequency component of the data.
 * - It subsequently retrieves this secret value from the data.
 * - The secret hiding and retrieval is done using the steganography_encrypt and 
 *   steganography_decrypt functions respectively.
 *
 * This is a basic implementation and should not be used for any serious cryptographic
 * purposes. It is for illustrative purposes only.
 *
 * This program uses the math library, remember to link it during the compilation: 
 *  gcc 1D_DCT.c -lm
 *
 * Author: [waajacu.com & chat.openai.com]
 * 
 * Date: [07 June 2023]
 */
#include <stdio.h>
#include <math.h>

#define PI 3.14159265
#define N 8 // Change the size according to your requirement.
#define SECRET 0.072 // Value to be incerted

// Normalization constant
double c(int index);
// Inverse Discrete Cosine Transformation
void dct(double matrix[N]);
// Inverse Discrete Cosine Transformation
void idct(double matrix[N]);
// Stegganography insertion function
void steganography_insertion(double matrix[N], double secret);
// Stegganography extraction function
double steganography_extraction(double matrix[N]);
// Hide
void steganography_encrypt(double matrix[N], double secret);
// Reveal
double steganography_decrypt(double matrix[N]);
// Print utility
void display(double matrix[N], const char *label);

int main() {
  // Define the matrix
  double matrix[N] = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}; // Data
  
  // Hide the secret in the vector
  steganography_encrypt(matrix, SECRET);
  
  // Retrive the secret from the vector
  double secret = steganography_decrypt(matrix);
  fprintf(stdout,"Secret recovered: \n\t%f\n", secret);

  return 0;
}

// Normalization constant
double c(int index) {
  if (index == 0)
    return sqrt(1.0 / N);
  else
    return sqrt(2.0 / N);
}

// Inverse Discrete Cosine Transformation
void dct(double matrix[N]) {
  double transformed[N];
      
  for (int k = 0; k < N; k++) {
    double sum = 0.0;
    for (int n = 0; n < N; n++)
      sum += matrix[n] * cos((PI / N) * (n + 0.5) * k);
    
    transformed[k] = c(k) * sum;
  }

  for (int i = 0; i < N; i++) // Copy back to original array
    matrix[i] = transformed[i];
}

// Inverse Discrete Cosine Transformation
void idct(double matrix[N]) {
  double transformed[N];
      
  for (int n = 0; n < N; n++) {
    double sum = 0.0;
    for (int k = 0; k < N; k++)
      sum += c(k) * matrix[k] * cos((PI / N) * (n + 0.5) * k);
    
    transformed[n] = sum;
  }

  for (int i = 0; i < N; i++) // Copy back to original array
    matrix[i] = transformed[i];
}
// Stegganography insertion function
void steganography_insertion(double matrix[N], double secret){
  matrix[N-1] = secret;
}
// Stegganography extraction function
double steganography_extraction(double matrix[N]){
  return matrix[N-1];
}
// Hide
void steganography_encrypt(double matrix[N], double secret){
  display(matrix,"Original data");
  
  // Transform to Frequency
  dct(matrix);
  display(matrix,"Original frequency");

  // The Steganography operations
  steganography_insertion(matrix, SECRET);
  display(matrix,"Alterated frequency");
  
  // Back to Data
  idct(matrix);
  display(matrix,"Alterated data");
}
// Reveal
double steganography_decrypt(double matrix[N]){
  // Transform to Frequency
  dct(matrix);
  
  // Extract the secret
  double secret = steganography_extraction(matrix);
  
  // Back to data
  idct(matrix);

  return secret;
}
// Print utility
void display(double matrix[N], const char *label){
  fprintf(stdout,"%s: \t{", label);
  for (int i = 0; i < N; i++)
    fprintf(stdout,"%f ", matrix[i]);
  fprintf(stdout,"}\n");
}