/**********************************************************************
 * Copyright (c) 2020 Aergo Foundation                                *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

unsigned char HexToInt(int h){
  CHECK( (h>='0' && h<='9') ||  (h>='a' && h<='f') ||  (h>='A' && h<='F') );
  h += 9*(1&(h>>6));
  return (unsigned char)(h & 0xf);
}

void from_hex(char *source, int size, unsigned char *dest){
  char *end = source + size;
  while( source<end ){
    unsigned char c1 = *(source++);
    unsigned char c2 = *(source++);
    *(dest++) = (HexToInt(c1)<<4) | HexToInt(c2);
  }
}

void print_hex(char *desc, unsigned char *data, int size){
  int i;
  printf("%s=", desc);
  for(i=0; i<size; i++){
    printf("%02X", data[i]);
  }
  puts("");
}

void run_vrf_tests(void) {
    secp256k1_context *sender;
    secp256k1_context *receiver;
    unsigned char proof[81] = {0};
    unsigned char seckey[32];
    secp256k1_pubkey pubkey;
    unsigned char pk[33];
    size_t pklen = 33;
    char *msg;
    unsigned int msglen;
    unsigned char output[32];
    int i;

    sender   = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    receiver = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    msg = "sample";
    msglen = strlen(msg);


    {  /* test nonce generation */

    unsigned char gen_nonce[32], exp_nonce[32];

    from_hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", 64, seckey);

    vrf_nonce_generation(gen_nonce, seckey, (unsigned char *)msg, msglen);

    from_hex("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60", 64, exp_nonce);

    print_hex("exp=", exp_nonce, 32);
    print_hex("gen=", gen_nonce, 32);

    CHECK(memcmp(exp_nonce, gen_nonce, 32) == 0);

    }


    {  /* test prove */
  
    unsigned char expected_proof[81] = {0};
    
    from_hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", 64, seckey);

    CHECK(secp256k1_ec_pubkey_create(sender, &pubkey, seckey) == 1);
    CHECK(secp256k1_ec_pubkey_serialize(sender, pk, &pklen, &pubkey, SECP256K1_EC_COMPRESSED) == 1);

    CHECK(secp256k1_vrf_prove(proof, seckey, &pubkey, msg, msglen) == 1);

    from_hex("031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d08748c9fbe6b95d17359707bfb8e8ab0c93ba0c515333adcb8b64f372c535e115ccf66ebf5abe6fadb01b5efb37c0a0ec9", 162, expected_proof);

    print_hex("expec=", expected_proof, 81);
    print_hex("proof=", proof, 81);

    CHECK(memcmp(proof, expected_proof, 81) == 0);

    }


    /* test verify on invalid and valid proofs */

    for(i=0; i<81; i++){
      unsigned char temp = proof[i];
      if (proof[i] == 0x00) proof[i] = 0x01; else proof[i] = 0x00;
      CHECK(secp256k1_vrf_verify(output, proof, pk, msg, msglen) == 0);
      proof[i] = temp;
      CHECK(secp256k1_vrf_verify(output, proof, pk, msg, msglen) == 1);
    }

    print_hex("output=", output, 32);


    /* test the same message with different provers */

    for(i=0; i<10; i++){

      secp256k1_rand256(seckey);

      CHECK(secp256k1_ec_pubkey_create(sender, &pubkey, seckey) == 1);
      CHECK(secp256k1_ec_pubkey_serialize(sender, pk, &pklen, &pubkey, SECP256K1_EC_COMPRESSED) == 1);

      CHECK(secp256k1_vrf_prove(proof, seckey, &pubkey, msg, msglen) == 1);
      print_hex("proof=", proof, 81);

      CHECK(secp256k1_vrf_verify(output, proof, pk, msg, msglen) == 1);
      print_hex("output=", output, 32);

    }


    /* test different messages with the same prover */

    for(i=0; i<10; i++){
      char buf[128];

      sprintf(buf, "message%d", i);
      msg = buf;
      msglen = strlen(msg);

      CHECK(secp256k1_vrf_prove(proof, seckey, &pubkey, msg, msglen) == 1);
      print_hex("proof=", proof, 81);

      CHECK(secp256k1_vrf_verify(output, proof, pk, msg, msglen) == 1);
      print_hex("output=", output, 32);

    }


    {  /* test verify */

    unsigned char expected_output[32] = {0};

    msg = "sample";
    msglen = strlen(msg);

    from_hex("032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645", 66, pk);
    from_hex("031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d0814faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4b2c31b5ef6997a585a9f1a72517b6f", 162, proof);

    CHECK(secp256k1_vrf_verify(output, proof, pk, msg, msglen) == 1);

    from_hex("612065e309e937ef46c2ef04d5886b9c6efd2991ac484ec64a9b014366fc5d81", 64, expected_output);

    print_hex("expect=", expected_output, 32);
    print_hex("output=", output, 32);

    CHECK(memcmp(output, expected_output, 32) == 0);

    }

}
