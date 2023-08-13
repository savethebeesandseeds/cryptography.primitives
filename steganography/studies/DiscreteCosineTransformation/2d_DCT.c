#include <stdio.h>
#include <math.h>

#define PI 3.14159265
#define N 8 // Change the size according to your requirement.
#define SECRET 0.072 // Value to be inserted

// Normalization constant
double c(int index);
// 1 dimensional Discrete Cosine Transform
void dct_1d(double matrix[N]);
// 1 dimensional Inverse Discrete Cosine Transform
void idct_1d(double matrix[N]);
// 2 dimensional Discrete Cosine Transform
void dct_2d(double matrix[N][N]);
// 2 dimensional Inverse Discrete Cosine Transform
void idct_2d(double matrix[N][N]);
// Stegganography insertion function
void steganography_insertion_2d(double matrix[N][N], double secret);
// Stegganography extraction function
double steganography_extraction_2d(double matrix[N][N]);
// Stegganography encryption function
void steganography_encrypt_2d(double matrix[N][N], double secret);
// Stegganography decryption function
double steganography_decrypt_2d(double matrix[N][N]);
// Print utility
void display_2d(double matrix[N][N], const char *label);

int main() {
  double matrix[N][N] = {
    {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}, 
    {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}, 
    {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}, 
    {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}, 
    {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}, 
    {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}, 
    {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}, 
    {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}}; // Initialize 2D data

  steganography_encrypt_2d(matrix, SECRET);
  double secret = steganography_decrypt_2d(matrix);
  printf("Secret recovered: %f\n", secret);

  return 0;
}
// Normalization constant
double c(int index) {
  if (index == 0)
    return sqrt(1.0 / N);
  else
    return sqrt(2.0 / N);
}
// 1 dimensional Discrete Cosine Transform
void dct_1d(double matrix[N]) {
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
// 1 dimensional Inverse Discrete Cosine Transform
void idct_1d(double matrix[N]) {
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
// 2 dimensional Discrete Cosine Transform
void dct_2d(double matrix[N][N]) {
  double row[N];
  for (int i = 0; i < N; i++) {
    for (int j = 0; j < N; j++)
      row[j] = matrix[i][j];
    dct_1d(row);
    for (int j = 0; j < N; j++)
      matrix[i][j] = row[j];
  }
  double col[N];
  for (int i = 0; i < N; i++) {
    for (int j = 0; j < N; j++)
      col[j] = matrix[j][i];
    dct_1d(col);
    for (int j = 0; j < N; j++)
      matrix[j][i] = col[j];
  }
}
// 2 dimensional Inverse Discrete Cosine Transform
void idct_2d(double matrix[N][N]) {
  double row[N];
  for (int i = 0; i < N; i++) {
    for (int j = 0; j < N; j++)
      row[j] = matrix[i][j];
    idct_1d(row);
    for (int j = 0; j < N; j++)
      matrix[i][j] = row[j];
  }
  double col[N];
  for (int i = 0; i < N; i++) {
    for (int j = 0; j < N; j++)
      col[j] = matrix[j][i];
    idct_1d(col);
    for (int j = 0; j < N; j++)
      matrix[j][i] = col[j];
  }
}
// Stegganography insertion function
void steganography_insertion_2d(double matrix[N][N], double secret) {
  matrix[N-1][N-1] = secret;
}
// Stegganography extraction function
double steganography_extraction_2d(double matrix[N][N]) {
  return matrix[N-1][N-1];
}
// Stegganography encryption function
void steganography_encrypt_2d(double matrix[N][N], double secret) {
  display_2d(matrix, "Original data");
  
  dct_2d(matrix);
  display_2d(matrix, "Original frequency");
  
  steganography_insertion_2d(matrix, SECRET);
  display_2d(matrix, "Altered data");
  
  idct_2d(matrix);
  display_2d(matrix, "Altered frequency");
}
// Stegganography decryption function
double steganography_decrypt_2d(double matrix[N][N]) {
  dct_2d(matrix);
  
  double secret = steganography_extraction_2d(matrix);
  
  idct_2d(matrix);

  return secret;
}
// Print utility
void display_2d(double matrix[N][N], const char *label) {
  fprintf(stdout,"%s: \n\t[\n\t", label);
  for (int i = 0; i < N; i++){
    fprintf(stdout,"{");
    for (int j = 0; j < N; j++)
        fprintf(stdout,"%f ", matrix[i][j]);
    fprintf(stdout,"}\n\t");
  }
  fprintf(stdout,"]\n");
}
