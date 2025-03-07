// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
// Developer: Alişah Özcan

#include "heongpu.cuh"

#include <string>
#include <iomanip>
#include <omp.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <random>

std::vector<std::vector<int>> generateConstantWeightVectors(int N, int m, int w) {
    std::vector<std::vector<int>> vectors(N, std::vector<int>(m, 0));  // ✅ 预分配
    std::random_device rd;  
    std::mt19937 gen(rd());

    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < w; ++j) {
            vectors[i][j] = 1;  
        }
        std::shuffle(vectors[i].begin(), vectors[i].end(), gen);
    }
    
    return vectors;
}

int main(int argc, char* argv[])
{
    cudaSetDevice(0);

    std::size_t poly_modulus_degrees = 32768;
    std::size_t plain_modulus = 65537;

    heongpu::Parameters context(
        heongpu::scheme_type::bfv,
        heongpu::keyswitching_type::KEYSWITCHING_METHOD_I);
    context.set_poly_modulus_degree(poly_modulus_degrees);
    context.set_default_coeff_modulus(1);
    context.set_plain_modulus(plain_modulus);
    context.generate();

    heongpu::HEKeyGenerator keygen(context);
    heongpu::Secretkey secret_key(context);
    keygen.generate_secret_key(secret_key);

    heongpu::Publickey public_key(context);
    keygen.generate_public_key(public_key, secret_key);

    heongpu::Relinkey relin_key(context);
    keygen.generate_relin_key(relin_key, secret_key);

    std::vector<int> custom_key_index = {1};
    heongpu::Galoiskey galois_key(context, custom_key_index);
    keygen.generate_galois_key(galois_key, secret_key);

    heongpu::HEEncoder encoder(context);
    heongpu::HEEncryptor encryptor(context, public_key);
    heongpu::HEDecryptor decryptor(context, secret_key);
    heongpu::HEArithmeticOperator operators(context, encoder);

    // Easily, e assume the database contain N key-value items
    int m = 60;
    int w = 30;
    int t = 40;
    int n = poly_modulus_degrees;
    int dim1 = n / poly_modulus_degrees;
    heongpu::HostVector<heongpu::Plaintext> Key(dim1 * m);
    heongpu::HostVector<heongpu::Plaintext> Value(t);
    auto mm = generateConstantWeightVectors(n, m, w); //m[n][m]

    heongpu::HostVector<uint64_t> messagek(poly_modulus_degrees, 0);
    for (int i = 0; i < m; i++) {
        for (int j = 0; j < n; j++) {
            messagek[j] = static_cast<uint64_t>(mm[i][j]);
        }
        encoder.encode(Key[i], messagek);
    }
    
    for (int i = 0; i < t; i++) {
        heongpu::HostVector<uint64_t> messagev(poly_modulus_degrees, 1);
        encoder.encode(Value[i], messagev);
    }
    
    // Client: we assume the client wanna query the cwc[0];
    std::cout << "INFO: The client encrypts the key 0 and sends it to the server." << std::endl;
    heongpu::HostVector<heongpu::Plaintext> pQ(m);
    heongpu::HostVector<heongpu::Ciphertext> cQ(m); // encrypted query
    for (int i = 0; i < m; i++) {
        heongpu::HostVector<uint64_t> temp(poly_modulus_degrees, 0);
        fill(temp.begin(), temp.end(), mm[0][i]);
        encoder.encode(pQ[i], temp);
        encryptor.encrypt(cQ[i], pQ[i]);
    }

    std::cout << "INFO: The server receives the encrypted query, and compute the I." << std::endl;
    heongpu::HostVector<heongpu::Ciphertext> res(m);
    for (int i = 0; i < m; i++) {
        operators.multiply_plain_inplace(cQ[i], Key[i]);
    }
    heongpu::Ciphertext sum(context);
    for (int i = 0; i < m; i++) {
        operators.add_inplace(sum, cQ[i]);
    }
    heongpu::Ciphertext One(context);
    heongpu::Ciphertext W(context);
    heongpu::Ciphertext Dif(context);
    heongpu::Plaintext p_One(context);
    heongpu::Plaintext p_W(context);
    heongpu::HostVector<uint64_t> cone(poly_modulus_degrees, 1);
    heongpu::HostVector<uint64_t> cw(poly_modulus_degrees, w);
    encoder.encode(p_One, cone);
    encoder.encode(p_W, cw);
    encryptor.encrypt(One, p_One);
    encryptor.encrypt(W, p_W);
    operators.sub(One, W, Dif);
    
    for (int i = 0; i < 16; i++) {
        operators.multiply_inplace(Dif, Dif);
        operators.relinearize_inplace(Dif, relin_key);
    }
    operators.sub(Dif, One, Dif);

    std::cout << "INFO: The server use the I to extract the target value." << std::endl;
    heongpu::HostVector<heongpu::Ciphertext> cV(t);
    for (int i = 0; i < t; i++) {
        operators.multiply_plain(Dif, Value[i], cV[i]);
    }
    heongpu::Ciphertext Ans(context);
    for (int i = 0; i < t; i++) {
        operators.rotate_rows(cV[i], cV[i], galois_key, 1);
        operators.add(Ans, cV[i], Ans);
    }
    
    return EXIT_SUCCESS;
}