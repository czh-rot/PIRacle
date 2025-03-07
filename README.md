

# **PIRacle: High-Performance Private Retrieval using Homomorphic Encryption**

**PIRacle** is an efficient and high-performance **private information retrieval (PIR)** system designed for key-value stores. It leverages **homomorphic encryption (HE)** to enable private queries while preserving data confidentiality.

We provide two versions of **PIRacle**:

- **CPU-based PIRacle** (built on [Microsoft SEAL](https://github.com/microsoft/SEAL))
- **GPU-based PIRacle** (built on [HEonGPU](https://github.com/Alisah-Ozcan/HEonGPU))

------

## **CPU-Based PIRacle**

The CPU-based implementation of PIRacle is built on **Microsoft SEAL**. Follow the steps below to configure and build the environment:

### **Installation & Setup**

```sh
cmake -S . -B build
cmake --build build
sudo cmake --install build
```

### **Running PIRacle (CPU version)**

```sh
cd ./native/examples
cmake -S . -B build
cmake --build build
cd build/bin
./sealexamples
0
```

------

## **GPU-Based PIRacle**

The GPU-based PIRacle implementation builds upon **HEonGPU**, providing significant acceleration for PIR queries on CUDA-enabled devices.

### **Installation & Setup**

```sh
cmake -S . -D CMAKE_CUDA_ARCHITECTURES=89 -B build
cmake --build build
sudo cmake --install build
```

### **Running PIRacle (GPU version)**

```sh
cmake -S . -D HEonGPU_BUILD_BENCHMARKS=ON -D CMAKE_CUDA_ARCHITECTURES=89 -B build
cmake --build build
```

### **Benchmarking PIRacle (GPU)**

Run the benchmark to evaluate performance:

```sh
./build/bin/benchmark/<benchmark_executable>
```

Example:

```sh
./build/bin/benchmark/PIRacle_benchmark
```

------

## **System Requirements**

- **CPU-Based PIRacle:**
  - GCC 9+ or Clang 10+
  - CMake 3.16+
  - Microsoft SEAL Library
- **GPU-Based PIRacle:**
  - NVIDIA GPU with **CUDA Compute Capability 8.9+**
  - CUDA Toolkit 11.0+
  - CMake 3.16+
  - HEonGPU

