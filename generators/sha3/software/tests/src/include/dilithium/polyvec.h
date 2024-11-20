#ifndef POLYVEC_H
#define POLYVEC_H

/* Vectors of polynomials of length L */
typedef struct {
  poly vec[L];
} polyvecl;

/* Vectors of polynomials of length K */
typedef struct {
  poly vec[K];
} polyveck;

#endif