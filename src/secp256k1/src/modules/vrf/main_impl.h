/**********************************************************************
 * Copyright (c) 2020 Aergo Foundation                                *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#define VRF_SUITE 0xFE  /* for compatibility with witnet/vrf-rs */

#define memzero(ptr,size) memset(ptr,0,size);

#define VRF_DEBUG_PRINT(X)

static void sha256(unsigned char *result, const void *data, const unsigned int len) {
    secp256k1_sha256 sha256;
    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, data, len);
    secp256k1_sha256_finalize(&sha256, result);
}

/******************************************************************************/
/** CALCULATIONS **************************************************************/
/******************************************************************************/

/*
** result = a*b+c (modulo the group order)
**
** Implemented using secp256k1_scalar
*/
static int secp256k1_scalar32_muladd(
  unsigned char *result,
  const unsigned char *a,
  const unsigned char *b,
  const unsigned char *c
){
  secp256k1_scalar r_scalar, a_scalar, b_scalar, c_scalar, t_scalar;
  int overflow = 0, ret = 0;

  /* Parse a */
  secp256k1_scalar_set_b32(&a_scalar, a, &overflow);
  if (overflow || secp256k1_scalar_is_zero(&a_scalar)) goto loc_exit;
  /* Parse b */
  secp256k1_scalar_set_b32(&b_scalar, b, &overflow);
  if (overflow || secp256k1_scalar_is_zero(&b_scalar)) goto loc_exit;
  /* Parse c */
  secp256k1_scalar_set_b32(&c_scalar, c, &overflow);
  if (overflow || secp256k1_scalar_is_zero(&c_scalar)) goto loc_exit;

  /* r=a*b+c (mod q) */
  secp256k1_scalar_mul(&t_scalar, &a_scalar, &b_scalar);
  secp256k1_scalar_add(&r_scalar, &t_scalar, &c_scalar);

  secp256k1_scalar_get_b32(result, &r_scalar);
  ret = 1;

loc_exit:
  secp256k1_scalar_clear(&a_scalar);
  secp256k1_scalar_clear(&b_scalar);
  secp256k1_scalar_clear(&c_scalar);
  secp256k1_scalar_clear(&t_scalar);
  secp256k1_scalar_clear(&r_scalar);
  return ret;
}

#ifdef VRF_UNUSED_FUNCTIONS
/*
** result = a*b+c (modulo the group order)
**
** Implemented using bignum
*/
static int secp256k1_scalar32_muladd(
  unsigned char *result,
  const unsigned char a[32],
  const unsigned char b[32],
  const unsigned char c[32]
){
  secp256k1_num r_num, a_num, b_num, c_num, order;
  unsigned char zero[1] = "";
  int ret = 0;

  /* Parse a */
  secp256k1_num_set_bin(&a_num, a, 32);
  secp256k1_num_set_bin(&b_num, b, 32);
  secp256k1_num_set_bin(&c_num, c, 32);

  /* r=a*b+c (mod q) */
  secp256k1_num_mul(&r_num, &a_num, &b_num);
  secp256k1_num_add(&r_num, &r_num, &c_num);
  secp256k1_scalar_order_get_num(&order);
  secp256k1_num_mod(&r_num, &order);

  memset(result, 0, 32);
  secp256k1_num_get_bin(result, 32, &r_num);
  ret = 1;

loc_exit:
  secp256k1_num_set_bin(&a_num, zero, 1);
  secp256k1_num_set_bin(&b_num, zero, 1);
  secp256k1_num_set_bin(&c_num, zero, 1);
  secp256k1_num_set_bin(&r_num, zero, 1);
  secp256k1_num_set_bin(&order, zero, 1);
  return ret;
}
#endif

/*
** Multiply a scalar by a point.
** Accepts a raw scalar as an unsigned 32 bytes octet.
** Returns the result as a ge point.
*/
static int secp256k1_vrf_ecmult(secp256k1_ge *result, const unsigned char scalar32[32], const secp256k1_ge *point) {
  secp256k1_gej result_gej;
  secp256k1_scalar scalar;
  int overflow = 0, ret = 0;

  secp256k1_scalar_set_b32(&scalar, scalar32, &overflow);
  if (overflow || secp256k1_scalar_is_zero(&scalar)) goto loc_exit;

  secp256k1_ecmult_const(&result_gej, point, &scalar);

  secp256k1_ge_set_gej(result, &result_gej);
  secp256k1_gej_clear(&result_gej);
  ret = 1;
loc_exit:
  secp256k1_scalar_clear(&scalar);
  return ret;
}

/*
** Multiply a scalar by the base point.
** Accepts a raw scalar as an unsigned 32 bytes octet.
** Returns the result as a ge point.
*/
static int secp256k1_vrf_ecmult_base(secp256k1_ge *result, const unsigned char scalar32[32]) {
  return secp256k1_vrf_ecmult(result, scalar32, &secp256k1_ge_const_g);
}

#ifdef VRF_UNUSED_FUNCTIONS

/*
** These 2 functions do not use the constant time ecmul functions.
** They require a secp256k1_context to be supplied.
*/

/*
** Multiply a scalar by a point.
** Accepts a raw scalar as an unsigned 32 bytes octet.
** Returns the result as a ge point.
*/
static int secp256k1_vrf_ecmult(const secp256k1_ecmult_gen_context* ctx, secp256k1_ge *result, const unsigned char scalar32[32], secp256k1_ge *point) {
  secp256k1_gej result_gej, point_gej;
  secp256k1_scalar scalar;
  int overflow = 0, ret = 0;

  secp256k1_scalar_set_b32(&scalar, scalar32, &overflow);
  if (overflow || secp256k1_scalar_is_zero(&scalar)) goto loc_exit;

  secp256k1_gej_set_ge(&point_gej, point);

  secp256k1_ecmult(ctx, &result_gej, &point_gej, &scalar, &zero);

  secp256k1_ge_set_gej(result, &result_gej);
  secp256k1_gej_clear(&result_gej);
  secp256k1_gej_clear(&point_gej);
  ret = 1;
loc_exit:
  secp256k1_scalar_clear(&scalar);
  return ret;
}

/*
** Multiply a scalar by a point.
** Accepts a raw scalar as an unsigned 32 bytes octet.
** Returns the result as a ge point.
*/
static int secp256k1_vrf_ecmult_base(const secp256k1_ecmult_gen_context* ctx, secp256k1_ge *result, const unsigned char scalar32[32]) {
  secp256k1_gej result_gej;
  secp256k1_scalar scalar;
  int overflow = 0, ret = 0;

  secp256k1_scalar_set_b32(&scalar, scalar32, &overflow);
  if (overflow || secp256k1_scalar_is_zero(&scalar)) goto loc_exit;

  secp256k1_ecmult_gen(ctx, &result_gej, &scalar);

  secp256k1_ge_set_gej(result, &result_gej);
  secp256k1_gej_clear(&result_gej);
  ret = 1;
loc_exit:
  secp256k1_scalar_clear(&scalar);
  return ret;
}

#endif

/*
** Subtract one point from another by adding one to the other negated (flip sign on Y coordinate)
*/
static void secp256k1_vrf_ecsub(secp256k1_ge *result, secp256k1_ge *a, secp256k1_ge *b) {
  secp256k1_gej result_gej, a_gej;
  secp256k1_ge b_neg;
  /* get negated point b */
  secp256k1_ge_neg(&b_neg, b);
  /* add the points */
  secp256k1_gej_set_ge(&a_gej, a);
  secp256k1_gej_add_ge(&result_gej, &a_gej, &b_neg);
  secp256k1_ge_set_gej(result, &result_gej);
  /* clear used variables */
  secp256k1_ge_clear(&b_neg);
  secp256k1_gej_clear(&a_gej);
  secp256k1_gej_clear(&result_gej);
}

/******************************************************************************/
/** ECVRF FUNCTIONS ***********************************************************/
/******************************************************************************/

static int point_to_string(unsigned char *output, const secp256k1_ge *P) {
    size_t len = 33;
    if (!output || !P) return 0;
    memset(output, 0, len);
    return secp256k1_eckey_pubkey_serialize(P, output, &len, 1);
}

static int string_to_point(secp256k1_ge *P, const unsigned char input[33]) {
    if (!P || !input) return 0;
    return secp256k1_eckey_pubkey_parse(P, input, 33);
}

/*
** Hash to curve by the try and increment method
*/
static int vrf_hash_to_curve_tai(secp256k1_ge *point, const secp256k1_ge *Y_point, const unsigned char *alpha_string, unsigned int alpha_len) {
    unsigned char ctr = 0;
    unsigned char pk_string[33];
    unsigned char *full_string;
    unsigned int pk_len, full_len;
    unsigned int offset = 0;

    if (!point || !Y_point || !alpha_string) return 0;

    point_to_string(pk_string, Y_point);
    pk_len = 33;

    full_len = 1 + 1 + pk_len + alpha_len + 1;
    full_string = malloc(full_len);
    if (!full_string) return 0;

    full_string[0] = VRF_SUITE;
    full_string[1] = 0x01;
    offset = 2;
    buffer_append(full_string, &offset, pk_string, pk_len);
    buffer_append(full_string, &offset, alpha_string, alpha_len);

    for (;; ctr++) {
        /* the first byte used by the inplace arbitrary_string_to_point() */
        unsigned char hash_string[33];
        /* update the ctr directly on the string */
        full_string[offset] = ctr;
        /* calculate the hash_string */
        sha256(&hash_string[1], full_string, full_len);
        /* arbitrary_string_to_point (inplace) */
        hash_string[0] = 0x02;
        if (string_to_point(point, hash_string) && !secp256k1_ge_is_infinity(point)) {
          VRF_DEBUG_PRINT(("try_and_increment succeded on ctr = %d\n", ctr));
          free(full_string);
          return 1;
        }
    }
}

static void vrf_hash_points(
    unsigned char ret[16],
    const secp256k1_ge *P1,
    const secp256k1_ge *P2,
    const secp256k1_ge *P3,
    const secp256k1_ge *P4
){
    unsigned char str[2+33*4], hash32[32];
    str[0] = VRF_SUITE;
    str[1] = 0x02;
    point_to_string(str+2+33*0, P1);
    point_to_string(str+2+33*1, P2);
    point_to_string(str+2+33*2, P3);
    point_to_string(str+2+33*3, P4);
    sha256(hash32, str, sizeof str);
    memcpy(ret, hash32, 16);
    memset(hash32, 0, 32);
}

static void vrf_nonce_generation(unsigned char nonce32[32], const unsigned char seckey[32], const unsigned char *msg, const unsigned int msglen) {
  unsigned char msg32[32];
  int count = 0, overflow = 0;
  sha256(msg32, msg, msglen);
  while (1) {
      secp256k1_scalar non;
      int ret = nonce_function_rfc6979(nonce32, msg32, seckey, NULL, NULL, count);
      if (!ret) {
          secp256k1_scalar_clear(&non);
          break;
      }
      secp256k1_scalar_set_b32(&non, nonce32, &overflow);
      if (!overflow && !secp256k1_scalar_is_zero(&non)) {
          secp256k1_scalar_clear(&non);
          break;
      }
      count++;
  }
}

static int vrf_decode_proof(
    secp256k1_ge *Gamma,
    unsigned char c[16],
    unsigned char s[32],
    const unsigned char pi[81]
){
    /* gamma = decode_point(pi[0:32]) */
    if (string_to_point(Gamma, pi) == 0) {
        return 0;
    }
    memcpy(c, pi+33, 16); /* c = pi[33:48] */
    memcpy(s, pi+49, 32); /* s = pi[49:80] */
    return 1;
}

int secp256k1_vrf_proof_to_hash(
    unsigned char beta[32],
    const unsigned char pi[81]
){
    unsigned char c_scalar[16], s_scalar[32];
    unsigned char hash_input[2+33];
    secp256k1_ge Gamma_point;
    /* (Gamma, c, s) = ECVRF_decode_proof(pi_string) */
    if (!vrf_decode_proof(&Gamma_point, c_scalar, s_scalar, pi)) {
        return 0;
    }
    /* beta_string = Hash(suite_string || three_string || point_to_string(Gamma)) */
    hash_input[0] = VRF_SUITE;
    hash_input[1] = 0x03;
    /* no need to multiply by a cofactor because it is 1 for secp256k1 curve */
    point_to_string(hash_input+2, &Gamma_point);
    sha256(beta, hash_input, sizeof hash_input);
    return 1;
}

/******************************************************************************/
/** PROVE *********************************************************************/
/******************************************************************************/

static int vrf_prove(
    unsigned char pi[81],
    const secp256k1_ge *Y_point,
    const unsigned char x_scalar[32],
    const unsigned char *alpha, unsigned int alphalen
){
    unsigned char h_string[33], k_scalar[32], c_scalar[32];
    secp256k1_ge  H_point, Gamma_point, kB_point, kH_point;
    int ret = 0;

    /* hash to the curve using the try and increment approach */
    if (!vrf_hash_to_curve_tai(&H_point, Y_point, alpha, alphalen)) goto loc_cleanup;
    point_to_string(h_string, &H_point);

    /* generate the nonce value k in a deterministic pseudorandom fashion */
    vrf_nonce_generation(k_scalar, x_scalar, h_string, 33);

    /* Gamma = x*H */
    if (!secp256k1_vrf_ecmult(&Gamma_point, x_scalar, &H_point)) goto loc_cleanup;
    /* compute k*B */
    if (!secp256k1_vrf_ecmult_base(&kB_point, k_scalar)) goto loc_cleanup;
    /* compute k*H */
    if (!secp256k1_vrf_ecmult(&kH_point, k_scalar, &H_point)) goto loc_cleanup;

    /* c = ECVRF_hash_points(h, gamma, k*B, k*H) */
    vrf_hash_points(c_scalar+16, &H_point, &Gamma_point, &kB_point, &kH_point);
    /* zero the first 16 bytes of c_scalar */
    memset(c_scalar, 0, 16);

    /* output pi */
    /* pi[0:32] = point_to_string(Gamma) */
    point_to_string(pi, &Gamma_point);
    /* pi[33:48] = c (16 bytes) */
    memmove(pi+33, c_scalar+16, 16);
    /* pi[49:80] = s = c*x + k (mod q) */
    secp256k1_scalar32_muladd(pi+49, c_scalar, x_scalar, k_scalar);

    /* everything is OK */
    ret = 1;

loc_cleanup:

    /* k must remain secret */
    memzero(k_scalar, sizeof k_scalar);

    /* erase other non-sensitive intermediate state for good measure */
    memzero(h_string, sizeof h_string);
    memzero(c_scalar, sizeof c_scalar);
    memzero(&H_point, sizeof H_point);
    memzero(&Gamma_point, sizeof Gamma_point);
    memzero(&kB_point, sizeof kB_point);
    memzero(&kH_point, sizeof kH_point);

    return ret;
}

int secp256k1_vrf_prove(
    unsigned char proof[81],
    const unsigned char *seckey,
    secp256k1_pubkey* pubkey,
    const void *msg,
    const unsigned int msglen
){
    secp256k1_ge Q;
    int ret;
    if (!secp256k1_pubkey_load(NULL, &Q, pubkey)) {
        secp256k1_ge_clear(&Q);
        return 0;
    }
    ret = vrf_prove(proof, &Q, seckey, msg, msglen);
    secp256k1_ge_clear(&Q);
    return ret;
}

/******************************************************************************/
/** VERIFICATION **************************************************************/
/******************************************************************************/

static int vrf_validate_key(secp256k1_ge *Y_point, const unsigned char pk_string[33]) {
    if (string_to_point(Y_point, pk_string) == 0 || secp256k1_ge_is_infinity(Y_point)) {
        return 0;
    }
    return 1;
}

static int vrf_verify(
    const secp256k1_ge *Y_point,
    const unsigned char pi[81],
    const unsigned char *alpha, const unsigned int alphalen
){
    unsigned char c_scalar[32], s_scalar[32], cprime[16];
    secp256k1_ge H_point, Gamma_point, U_point, V_point;
    secp256k1_ge sB_point, cY_point, sH_point, cGamma_point;

    if (!vrf_decode_proof(&Gamma_point, c_scalar+16, s_scalar, pi)) {
        return 0;
    }

    /* zero the first 16 bytes of c_scalar */
    memset(c_scalar, 0, 16);

    /* hash to the curve using the try and increment approach */
    if (!vrf_hash_to_curve_tai(&H_point, Y_point, alpha, alphalen)) return 0;

    /* calculate U = s*B - c*Y */
    secp256k1_vrf_ecmult_base(&sB_point, s_scalar);      /* compute s*B */
    secp256k1_vrf_ecmult(&cY_point, c_scalar, Y_point);  /* compute c*Y */
    secp256k1_vrf_ecsub(&U_point, &sB_point, &cY_point); /* U = s*B - c*Y */

    /* calculate V = s*H -  c*Gamma */
    secp256k1_vrf_ecmult(&sH_point, s_scalar, &H_point);         /* compute s*H */
    secp256k1_vrf_ecmult(&cGamma_point, c_scalar, &Gamma_point); /* compute c*Gamma */
    secp256k1_vrf_ecsub(&V_point, &sH_point, &cGamma_point);     /* V = s*H - c*Gamma */

    /* c = ECVRF_hash_points(h, gamma, U, V) */
    vrf_hash_points(cprime, &H_point, &Gamma_point, &U_point, &V_point);

    return memcmp(c_scalar+16, cprime, 16) == 0;
}

int secp256k1_vrf_verify(
    unsigned char output[32],
    const unsigned char proof[81],
    const unsigned char pk[33],
    const void *msg, const unsigned int msglen
){
    secp256k1_ge Y;
    if ( vrf_validate_key(&Y, pk) && vrf_verify(&Y, proof, msg, msglen)) {
        return secp256k1_vrf_proof_to_hash(output, proof);
    } else {
        return 0;
    }
}
