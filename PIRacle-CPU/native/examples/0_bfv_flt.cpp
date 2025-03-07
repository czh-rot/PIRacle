// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include "seal/seal.h"
#include "seal/util/polyarithsmallmod.h"
#include <chrono>
#include <bitset>
#include <boost/multiprecision/cpp_int.hpp>
#include <gmpxx.h>


using namespace std;
using namespace seal;
using namespace seal::util;


void example_bfv_flt()
{   
    print_example_banner("Example: BFV Basics");
    EncryptionParameters parms(scheme_type::bfv);
    size_t N = 32768; // BFV degree
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 17)); // 65537
    SEALContext context(parms);
    print_line(__LINE__);
    print_parameters(context);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    BatchEncoder encoder_(context);
    Decryptor decryptor(context, secret_key);

    // Obtain the I: FLT
    vector<uint64_t > mm(N);
    vector<uint64_t > one(N);
    for (uint64_t  i = 0; i < N; i++) {
      mm[i] = uint64_t(5);
      one[i] = 1;
    }
    Plaintext plain_m, plain_one;
    encoder_.encode(mm, plain_m);
    encoder_.encode(one, plain_one);

    Ciphertext ciphertext_m, ciphertext_one;
    encryptor.encrypt(plain_m, ciphertext_m);
    encryptor.encrypt(plain_one, ciphertext_one);

    vector<uint64_t> a(N);
    vector<uint64_t> b(N);

    for (uint64_t  i = 0; i < N; i++) {
        a[i] = i;
        b[i] = i+1;
    }
    b[0] = 0;

    Ciphertext ax, bx;
    Plaintext plain_a, plain_b;
    encoder_.encode(a, plain_a);
    encoder_.encode(b, plain_b);
    encryptor.encrypt(plain_a, ax);
    encryptor.encrypt(plain_b, bx);

    cout << "INFO: BFV EQ using FLT." << endl;

    Ciphertext substract;
    cout << "INFO: Noise budget of ax: " << decryptor.invariant_noise_budget(ax) << endl;
    evaluator.sub(bx, ax, substract);
    Ciphertext I;
    for (uint64_t j = 0; j < 16; j++) {
        evaluator.square(substract, substract);
        evaluator.relinearize_inplace(substract, relin_keys);
        cout << "INFO: Noise budget of I: " << decryptor.invariant_noise_budget(substract) << endl;
    }
    evaluator.sub(ciphertext_one, substract, I); // sum[i] contains the I
    cout << "INFO: Noise budget of I: " << decryptor.invariant_noise_budget(I) << endl;
    for (   uint64_t j = 0; j < 16; j++) {
        evaluator.multiply(I, ax, I);
        evaluator.relinearize_inplace(I, relin_keys);
        cout << "INFO: Noise budget of I: " << decryptor.invariant_noise_budget(I) << endl;
    }
    // Plaintext plain_result;
    // vector<uint64_t> result(32768);
    // decryptor.decrypt(I, plain_result);
    // encoder_.decode(plain_result, result);
    // int count = 10;
    // for (size_t i = 0; i < count; i++)
    // {
    //     cout << result[i] << endl;
    //     if (count > 10) {
    //         break;
    //     }   
    // }

    return;
}
