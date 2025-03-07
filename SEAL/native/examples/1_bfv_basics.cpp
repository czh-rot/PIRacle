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
namespace mp = boost::multiprecision;

mp::cpp_int binomial_coefficient(uint64_t n, uint64_t k) {
    mp::cpp_int result = 1;
    if (k > n - k)
        k = n - k;
    for (int i = 0; i < k; ++i) {
        result *= (n - i);
        result /= (i + 1);
    }
    return result;
}

std::vector<uint64_t> perfect_mapping(uint64_t x, uint64_t m, uint64_t k) {
    if (m < k || k < 0 || x < 0) {
        throw std::invalid_argument("Invalid values for m, k, or x.");
    }

    std::vector<uint64_t> y(m, 0); // Initialize vector of m zeros
    uint64_t h = k;
    mp::cpp_int r = mp::cpp_int(x);

    for (int i = m - 1; i >= 0; --i) {
        if (h > 0) {
            mp::cpp_int c = binomial_coefficient(i, h);
            if (r >= c) {
                y[i] = 1;
                r -= c;
                --h;
            }
        }
    }

    if (h != 0) throw std::runtime_error("Inconsistency detected in the mapping logic.");

    return y;
}


// The workflow of the SmartPIR example is as follows:
void example_bfv_basics()
{   

  // {
  //   std::random_device rd;  
  //   std::mt19937_64 gen(rd()); 
  //   std::uniform_int_distribution<uint64_t> dist(0, (1ULL << 55) - 1);
  //   for (uint64_t j = 0; j < 10; ++j) {
  //     // uint64_t k = j;
  //     uint64_t k = dist(gen);
  //     cout << k << endl;
  //     auto a = perfect_mapping(k, 66, 33);
  //     for (auto i : a) {
  //       cout << i << " ";
  //     }
  //     cout << endl;
  //   }
  //   cout << endl;
  // }
  // return;

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

    std::random_device rd;  
    std::mt19937_64 gen(rd()); 
    std::uniform_int_distribution<uint64_t> dist;

    cout << "INFO: Pepare Setup phase: Init the Key-Value Store." << endl;
    cout << "INFO: Input the number of items (e.g., 2^15 (32768)):" << endl;
    size_t num;
    cin >> num;

    // To simply, we generate N key-value pairs, and each key and value is 64 bits with random value
    cout << "INFO: we generate " << num <<" key-value pairs, and each key and value is 64 bits." << endl;
    size_t dim1 = num/N;
    cout << "INFO: They are divided into " << dim1 << "(i.e., num/N) partitions." << endl;
    vector<uint64_t > key(num);
    vector<vector<vector<uint64_t >>> value(dim1, vector<vector<uint64_t >>(4, vector<uint64_t >(N)));

    // assum is dense
    for (uint64_t  i = 0; i < num; ++i) {
        key[i] = dist(gen);
    }

    for (uint64_t  i = 0; i < dim1; ++i) {
        for (uint64_t  j = 0; j < 4; ++j) {
            for (uint64_t  k = 0; k < N; ++k) {
                value[i][j][k] = 1;
            }
        }
    }

    // In fact, it's not necessary for this example (capcity N)
    // sort(key.begin(), key.end());

    // define the CWC parameter, where m = 66, k = 33, ensure that C(66,33) > N
    cout << "INFO: Input the CWC parameter m and k (e.g., m=66, k=33):" << endl;
    uint64_t m, k;
    cin >> m;
    cin >> k;

    cout << "INFO: The server generates Sparse CWC for all keys." << endl;
    vector<vector<vector<uint64_t >>> cwc_vector_3d(dim1, vector<vector<uint64_t >>(m, vector<uint64_t >(N))); // 1-d paartiton, 2-d m, 3-d N;
    vector<vector<uint64_t >> cwc(num, vector<uint64_t >(m));

    // Generate all possible CWCs of keys and adjust the layout
    for (uint64_t  i = 0; i < num; ++i) {
      cwc[i] = perfect_mapping(key[i],m, k);
    }

    for (uint64_t  i = 0; i < dim1; ++i) {
      for (uint64_t  j = 0; j < m; ++j) {
        for (uint64_t  k = 0; k < N; ++k) {
            cwc_vector_3d[i][j][k] = cwc[i * N + k][j];
        }
      }
    }

    cout << "INFO: The server then encodes all CWC key and values into plaintexts." << endl;
    
    vector<vector<Plaintext>> PCWCkey(dim1, vector<Plaintext>(m));
    vector<vector<Plaintext>> PValue(dim1, vector<Plaintext>(4));

    // Encode Key-Value into plaintexts
    for (uint64_t  i = 0; i < dim1; i++) {
      Plaintext c;
        for (uint64_t  j = 0; j < m; j++) {
          encoder_.encode(cwc_vector_3d[i][j], PCWCkey[i][j]);
        }
        for (uint64_t  k = 0; k < 4; k++) {
          encoder_.encode(value[i][k], PValue[i][k]);
        }
    }

    vector<int> temp(N);

    // Client: we assume the client wanna query the cwc[0];
    cout << "INFO: The client encrypts the cwc[0] and sends it to the server." << endl;
    vector<Ciphertext> q(m);
    for (uint64_t i = 0; i < m; i++) {
        vector<uint64_t> temp(N);
        fill(temp.begin(), temp.end(), cwc[0][i]); // assume the client wanna query the cwc[0];
        // for (std::vector<uint64_t >::iterator it = temp.begin(); it != temp.end(); ++it) {
        // std::cout << *it << " ";
        // }
        Plaintext p;
        encoder_.encode(temp, p);
        encryptor.encrypt(p, q[i]);
    }

    // cout << "INFO: Noise budget of q: " << decryptor.invariant_noise_budget(q[0]) << endl;
    // Obtain the I: HMult
    cout << "INFO: The server receives the encrypted query, and compute the I." << endl;
    cout << "INFO: Step I." << endl;
    vector<vector<Ciphertext>> pk(dim1, vector<Ciphertext>(m));
    for (uint64_t  i = 0; i < dim1; i++) {
      for ( uint64_t  j = 0; j < m; j++) {
        evaluator.multiply_plain(q[j], PCWCkey[i][j], pk[i][j]);
      }
    }
    cout << "INFO: Noise budget of pk[0][0]: " << decryptor.invariant_noise_budget(pk[0][0]) << endl;

    // Obtain the I: Add
    cout << "INFO: Step II." << endl;
    vector<Ciphertext> sum(dim1); 
    for (uint64_t  i = 0; i < dim1; i++) {
      evaluator.add_many(pk[i], sum[i]);
    }
    // cout << "INFO: Noise budget of sum[i]: " << decryptor.invariant_noise_budget(sum[0]) << endl;
    // Obtain the I: FLT
    vector<uint64_t > mm(N);
    vector<uint64_t > one(N);
    for (uint64_t  i = 0; i < N; i++) {
      mm[i] = uint64_t(m);
      one[i] = 1;
    }
    Plaintext plain_m, plain_one;
    encoder_.encode(mm, plain_m);
    encoder_.encode(one, plain_one);

    Ciphertext ciphertext_m, ciphertext_one;
    encryptor.encrypt(plain_m, ciphertext_m);
    encryptor.encrypt(plain_one, ciphertext_one);

    cout << "INFO: Step III." << endl;
    vector<Ciphertext> I(dim1);
    for (uint64_t  i = 0; i < dim1; i++) {
      evaluator.sub(ciphertext_m, sum[i], sum[i]);
      for (uint64_t  j = 0; j < 16; j++) {
        evaluator.square(sum[i], sum[i]);
        evaluator.relinearize_inplace(sum[i], relin_keys);
      }
      evaluator.sub(ciphertext_one, sum[i], I[i]); // sum[i] contains the I
    }

    // cout << "INFO: Noise budget of sum[i]: " << decryptor.invariant_noise_budget(sum[0]) << endl;
    // Extract the Value
    cout << "INFO: The server use the I to extract the target value." << endl;
    vector<vector<Ciphertext>> CValue(dim1, vector<Ciphertext>(4));
    for (uint64_t  i = 0; i < dim1; i++) {
      for (uint64_t  j = 0; j < 4; j++) {
        evaluator.multiply_plain(sum[i], PValue[i][j], CValue[i][j]);
      }
    }

    // cout << "INFO: Noise budget of CValue: " << decryptor.invariant_noise_budget(CValue[0][0]) << endl;

    vector<vector<Ciphertext>> CValueTransposed(4, vector<Ciphertext>(dim1));
    // T CValue
    for (uint64_t  i = 0; i < dim1; i++) {
        for (uint64_t  j = 0; j < 4; j++) {
            CValueTransposed[j][i] = CValue[i][j];
        }
    }

    vector<Ciphertext> Value(4);
    for (uint64_t  j = 0; j < 4; j++) {
        evaluator.add_many(CValueTransposed[j], Value[j]);  // Ensure Value[j] is a vector
    }


    // Ciphertext a1 =  Value[0];
    // cout << "INFO: Noise budget of a1: " << decryptor.invariant_noise_budget(a1) << endl;
    // evaluator.add_inplace(a1, a1);
    // cout << "INFO: Noise budget of a1: " << decryptor.invariant_noise_budget(a1) << endl;

    // cout << "INFO: Noise budget of Value: " << decryptor.invariant_noise_budget(Value[0]) << endl;

    for (uint64_t  i = 1; i < 4; i++) {
      evaluator.rotate_rows_inplace(Value[i], i, gal_keys);
    }

    // cout << "INFO: Noise budget of Value: " << decryptor.invariant_noise_budget(Value[0]) << endl;

    Ciphertext Ans;
    evaluator.add_many(Value, Ans);

    Plaintext ans;
    decryptor.decrypt(Ans, ans);
    vector<uint64_t > ans_plain;
    encoder_.decode(ans, ans_plain);
    cout << ans_plain[0] << endl;
    cout << value[0][0][0] << endl;
    
    cout << "INFO: Noise budget of Ans: " << decryptor.invariant_noise_budget(Ans) << endl;
    cout << "INFO: The server obtain the Ans and send it back to the client." << endl;
    cout << "INFO: A private query is finished." << endl;


    // Plaintext P2;
    // Ciphertext C1, C2, C3;
    // encoder_.encode(p, P2);
    // encryptor.encrypt(P2, C1);

    // uint64_t  iterations = 1;
    // std::chrono::duration<double, std::milli> multiply_plain_time1(0);
    // std::chrono::duration<double, std::milli> multiply_plain_time2(0);

    // Plaintext pt(parms.poly_modulus_degree());
    // pt.set_zero();
    // for (uint64_t  i = 0; i < N; i++) {
    //   pt[i] = i;
    // }
    // Ciphertext dest;
    // encryptor.encrypt(pt, dest);
    // evaluator.transform_to_ntt_inplace(dest);
    // evaluator.transform_to_ntt_inplace(pt, context.first_parms_id());

    // cout << dest.is_ntt_form() << endl;
    // cout << C1.is_ntt_form() << endl;

    // for (uint64_t  i = 0; i < iterations; i++) {

    //   auto start1 = std::chrono::high_resolution_clock::now();
    //   evaluator.multiply_plain_inplace(C1, P1);
    //   auto end1 = std::chrono::high_resolution_clock::now();
    //   multiply_plain_time1 += end1 - start1; 

    //   auto start2 = std::chrono::high_resolution_clock::now();
    //   evaluator.multiply_plain_inplace(dest, pt);
    //   auto end2 = std::chrono::high_resolution_clock::now();
    //   multiply_plain_time2 += end2 - start2;       
    // }

    // evaluator.transform_to_ntt_inplace(P1, context.first_parms_id());
    // cout << P1.is_ntt_form() << endl;
    // evaluator.multiply_plain_inplace(dest, P1);

    // // Calculate the average time
    // double average_time1 = multiply_plain_time1.count() / iterations;
    // double average_time2 = multiply_plain_time2.count() / iterations;

    // std::cout << "Average time for first multiply_plain: " << average_time1 << " ms\n";
    // std::cout << "Average time for second multiply_plain_inplace: " << average_time2 << " ms\n";
    return;


}
