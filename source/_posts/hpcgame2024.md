---
title: 2024 PKU HPCGame WP
date: 2024-01-30 18:02:04
updated: 2024-01-30 18:02:04
tags: [HPC,超算,HPCgame]
categories: [笔记]
thumbnail: /images/hpc/pcgame2024/hpcgame-2024.webp
cover: /images/hpc/hpcgame2024/hpcgame-2024.webp
toc: true
---

今年参加了第一届[PKU HPCGame](https://hpcgame.pku.edu.cn/org/2df8f692-0316-4682-80cd-591732b1eda6/contest/7250a2f0-3c1e-4aaf-91a1-ccc4339ef00d)，这是一场由北京大学计算中心等组织举办的个人超算竞赛。
<!-- more -->
题解情况如下：AC题目 A,B,C,D,F,I,L ; E,G,H 拿到部分分数；J,K,M,N 无解。这篇WriteUp主要是对我解决的题目的记录，以及一些解题思路的总结。

## A. 欢迎参赛！
签到

## B. 流量席卷土豆
小 X 为了让你学习超算知识，要求你必须使用 4 个计算节点，每个节点 4 个 tshark 进程同时从 16 个 PCAP 文件中提取 SSH 流量。为此，他要求你使用集群上的 Slurm 调度器运行这一步骤，同时把进行这一计算的 Slurm JobID 和最终使用 quantum-cracker 获得的密码同时交付给他。他会检查这一 JobID 对应的 Slurm Job 是否使用了 4 个计算节点，每个节点 4 个进程。否则他不会动用他的量子纠缠能力。

```bash
#!/bin/bash

PCAP_DIR=/lustre/shared_data/potato_kingdom_univ_trad_cluster/pcaps
OUT_DIR=$HOME

for i in $(seq 0 15); do
    srun -N4 --ntasks-per-node=4 tshark -r $PCAP_DIR/$i.pcap -Y ssh -w $OUT_DIR/$i.ssh.pcap
done

wait

mergecap -w $OUT_DIR/merged.pcap $OUT_DIR/*.ssh.pcap

/usr/bin/quantum-cracker $OUT_DIR/merged.pcap > $OUT_DIR/cracked_password.txt

echo "Slurm JobID: $SLURM_JOB_ID" >> $OUT_DIR/result.txt
echo "Cracked Password: $(cat $OUT_DIR/cracked_password.txt)" >> $OUT_DIR/result.txt
```

此题只需要满足两个要求：
1. 写slurm脚本在一个进程中调用4个节点，每个节点上4个核，一共十六个进程提流量
2. 使用给出的quantum-cracker破解流量中的ssh密码

判定较为宽松，不是严格要求必须分配进程，所以只需要调用到足够的核就能满足第一个条件。

## C. 简单的编译
在本题中，你需要写一个简单的Makefile文件，和一个简单的CMakeLists.txt文件，来编译 Handout 中所提供的三个简单程序。


```Makefile
CC=g++
NVCC=nvcc
MPICC=mpic++
CFLAGS=-fopenmp

all: hello_cuda hello_mpi hello_omp

hello_cuda: hello_cuda.cu
	$(NVCC) -o hello_cuda hello_cuda.cu

hello_mpi: hello_mpi.cpp
	$(MPICC) -o hello_mpi hello_mpi.cpp

hello_omp: hello_omp.cpp
	$(CC) $(CFLAGS) -o hello_omp hello_omp.cpp

clean:
	rm -f hello_cuda hello_mpi hello_omp
```

```Makefile
#CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(HelloWorld)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")

find_package(MPI REQUIRED)
find_package(CUDA REQUIRED)

enable_language(CUDA)

add_executable(hello_cuda hello_cuda.cu)
add_executable(hello_mpi hello_mpi.cpp)
add_executable(hello_omp hello_omp.cpp)

target_link_libraries(hello_mpi MPI::MPI_CXX)
target_link_libraries(hello_cuda ${CUDA_LIBRARIES})
```

makefile和cmakefile编写，套模板即可。

## D. 小北问答CLASSIC
非常棒的知识问答，爱来自Neur0_5ama。

<div style="text-align: center;">
  <img src="/images/others/neuro_1.webp" alt="neuro" style="width: 50%;">
</div>
&nbsp;

~参赛昵称为Neur0_5ama,尝试作为Neuro单推人混入其中~

最有意思的选项： 

在高性能计算集群中，哪个工具通常用于作业调度和资源管理？ -- ~Slurm~ ~微信群~ 蜂群（确信）

## E. 齐心协力
对于一百个(200, 40000)的矩阵 x ，计算如下结果，其中 A 、B 、C 和 D 都是 (40000, 40000) 的矩阵。其中四个矩阵需要被放置在四个不同的节点上，每个节点有4个核心、16G内存。你需要对于输入的每一个 x ，计算得出最终的 output 。

y1=ReLU(x A)  
y2=ReLU(y1 B)  
y3=ReLU(y2 C)  
output=ReLU(y3 D)  

```python
import os
import numpy as np
import ray

def relu(x):
    return np.maximum(0, x)

@ray.remote
def compute(input, weight):
    return relu(np.dot(input, np.load(weight)))

ray.init(address=f"{os.environ['RAY_CLUSTER_ADDR']}")

tasks = []
for i in range(100):
    input = f"inputs/input_{i}.npy"
    task = compute.remote(np.load(input), "weights/weight_0.npy")
    for j in range(1, 4):
        task = compute.remote(task, f"weights/weight_{j}.npy")
    tasks.append(task)

outputs = ray.get(tasks)

os.makedirs("outputs", exist_ok=True)
for i, output in enumerate(outputs):
    np.save(f"outputs/output_{i}.npy", output)
```

根据题意，需要使用Ray来进行分布式计算

这道题测评易出问题，后续需要排队测评，本地调试配环境比较困难，因此到最后一天才做出来，而且写的非常粗糙。题干说明了输入输出文件有高速io，但是权重文件没有，因此AC答案应该是 O(weight+100input) ，而我的答案是 O(100(weight+input))，因此只拿到了部分分数，解答仅作为参考。

补充了ray的相关知识，是一道很有新意的题，题目本身不算困难。关于[Ray核心介绍](https://docs.ray.io/en/latest/ray-core/walkthrough.html)。

## F. 高性能数据校验
本题使用一种基于 SHA512 算法的可并行数据校验算法对数据进行分块校验。（SHA512 是一种高度安全的校验码实现，具体算法不需关心）

算法的流程如下（对算法的具体解释见 baseline 代码）：
1. 对数据进行分块，每一块的大小为 M=1MB，记划分的块数为 n。如果文件剩余内容不足一块的大小，则补二进制0至一个块大小。
2. 对于第 i 个块，在其末尾连接上第 i-1 个块的 SHA512 校验码的二进制值，将所得到的 M + 64 大小的数据进行 SHA512 校验，得到第 i 个块的校验码。（i 从 0 开始） *注，第 -1 个块的校验码为空文件的校验码*
3. 最后一个块的校验码，即为文件的校验码 *注，大小为0的文件的校验码定义为空文件的 SHA512 校验码*

```c++
#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mpi.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

namespace fs = std::filesystem;

constexpr size_t BLOCK_SIZE = 1024 * 1024;

EVP_MD_CTX* ctx[16384];


int main(int argc, char *argv[]) {

    MPI_Init(&argc, &argv);

    int rank, nprocs;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nprocs);

    fs::path input_path = argv[1];
    fs::path output_path = argv[2];

    auto file_size = fs::file_size(input_path);

    int num_block = (file_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    int blocks_per_proc = (num_block + nprocs - 1) / nprocs;

    //MPI_File file;
auto start = std::chrono::high_resolution_clock::now();

    //MPI_File_open(MPI_COMM_WORLD, input_path.c_str(), MPI_MODE_RDONLY, MPI_INFO_NULL, &file);

    int fd = open(input_path.c_str(), O_RDONLY);
if (fd == -1) {
    perror("Error opening file for reading");
    MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
}

struct stat sb;
if (fstat(fd, &sb) == -1) {
    perror("fstat");
    MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
}

// Each process maps its part of the file
uint64_t offset = rank * blocks_per_proc * BLOCK_SIZE;
long int sizes = blocks_per_proc * BLOCK_SIZE;


uint8_t *buffer = static_cast<uint8_t*>(mmap(0, sizes, PROT_READ, MAP_SHARED, fd, offset));
if (buffer == MAP_FAILED) {
    close(fd);
    perror("Error mmapping the file");
    MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
}


    //uint8_t *buffer = new uint8_t[blocks_per_proc * BLOCK_SIZE];

// Each process reads its part of the file
//uint64_t offset = rank * blocks_per_proc * BLOCK_SIZE;
//long int sizes = blocks_per_proc * BLOCK_SIZE;
//if (sizes == 2147483648){
//    sizes = sizes/2;
//}
//
//offset
//MPI_File_read_at(file, offset, buffer, sizes, MPI_BYTE, MPI_STATUS_IGNORE);

//if (sizes == blocks_per_proc * BLOCK_SIZE/2){
//    MPI_File_read_at(file, offset+sizes, buffer+sizes, sizes, MPI_BYTE, MPI_STATUS_IGNORE);
//}
//    MPI_File_close(&file);

    for (int i = 0; i < blocks_per_proc; i++) {
    ctx[i] = EVP_MD_CTX_new();
    }
    EVP_MD *sha512 = EVP_MD_fetch(nullptr, "SHA512", nullptr);

    for (int i = 0; i < blocks_per_proc; i++) {
    EVP_DigestInit_ex(ctx[i], sha512, nullptr);
    EVP_DigestUpdate(ctx[i], buffer + i * BLOCK_SIZE, BLOCK_SIZE);
    }
auto end = std::chrono::high_resolution_clock::now();
auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
std::cout << "File reading took " << duration.count() << " milliseconds\n";

    //delete[] buffer;
  if (rank == 0) {
    // calculate the checksum
    uint8_t obuf[SHA512_DIGEST_LENGTH];
      uint8_t prev_md[SHA512_DIGEST_LENGTH] = {
      0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50,
      0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
      0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c,
      0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
      0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a,
      0xf9, 0x27, 0xda, 0x3e};

// 3 串行
  for (int i = 0; i < blocks_per_proc; i++) {
    unsigned int len_out = 0;
    EVP_DigestUpdate(ctx[i], prev_md, SHA512_DIGEST_LENGTH);
    EVP_DigestFinal_ex(ctx[i], prev_md, &len_out);
    ////EVP_MD_CTX_free(ctx[i]);
  }
 //将prev_md发送给rank1
    MPI_Send(prev_md, SHA512_DIGEST_LENGTH, MPI_BYTE, 1, 0, MPI_COMM_WORLD);
    }
    if (rank == 1) {
        //接收rank0的结果当做prev_md
        uint8_t prev_md[SHA512_DIGEST_LENGTH];
        MPI_Recv(prev_md, SHA512_DIGEST_LENGTH, MPI_BYTE, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        
        for (int i = 0; i < blocks_per_proc; i++) {
        unsigned int len_out = 0;
        EVP_DigestUpdate(ctx[i], prev_md, SHA512_DIGEST_LENGTH);
        EVP_DigestFinal_ex(ctx[i], prev_md, &len_out);
        //EVP_MD_CTX_free(ctx[i]);
        }
        //
        MPI_Send(prev_md, SHA512_DIGEST_LENGTH, MPI_BYTE, 2, 0, MPI_COMM_WORLD);
    }
    if (rank == 2) {
        uint8_t prev_md[SHA512_DIGEST_LENGTH];
        MPI_Recv(prev_md, SHA512_DIGEST_LENGTH, MPI_BYTE, 1, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        
        for (int i = 0; i < blocks_per_proc; i++) {
        unsigned int len_out = 0;
        EVP_DigestUpdate(ctx[i], prev_md, SHA512_DIGEST_LENGTH);
        EVP_DigestFinal_ex(ctx[i], prev_md, &len_out);
        //EVP_MD_CTX_free(ctx[i]);
        }

        MPI_Send(prev_md, SHA512_DIGEST_LENGTH, MPI_BYTE, 3, 0, MPI_COMM_WORLD);
    }
    if (rank == 3) {
        uint8_t prev_md[SHA512_DIGEST_LENGTH];
        MPI_Recv(prev_md, SHA512_DIGEST_LENGTH, MPI_BYTE, 2, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        
        for (int i = 0; i < blocks_per_proc; i++) {
        unsigned int len_out = 0;
        EVP_DigestUpdate(ctx[i], prev_md, SHA512_DIGEST_LENGTH);
        EVP_DigestFinal_ex(ctx[i], prev_md, &len_out);
        //EVP_MD_CTX_free(ctx[i]);
        }

        MPI_Send(prev_md, SHA512_DIGEST_LENGTH, MPI_BYTE, 4, 0, MPI_COMM_WORLD);
    }
    if (rank == 4) {
        uint8_t prev_md[SHA512_DIGEST_LENGTH];
        MPI_Recv(prev_md, SHA512_DIGEST_LENGTH, MPI_BYTE, 3, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        
        for (int i = 0; i < blocks_per_proc; i++) {
        unsigned int len_out = 0;
        EVP_DigestUpdate(ctx[i], prev_md, SHA512_DIGEST_LENGTH);
        EVP_DigestFinal_ex(ctx[i], prev_md, &len_out);
        //EVP_MD_CTX_free(ctx[i]);
        }

        MPI_Send(prev_md, SHA512_DIGEST_LENGTH, MPI_BYTE, 5, 0, MPI_COMM_WORLD);
    }
    if (rank == 5) {
        uint8_t prev_md[SHA512_DIGEST_LENGTH];
        MPI_Recv(prev_md, SHA512_DIGEST_LENGTH, MPI_BYTE, 4, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        
        for (int i = 0; i < blocks_per_proc; i++) {
        unsigned int len_out = 0;
        EVP_DigestUpdate(ctx[i], prev_md, SHA512_DIGEST_LENGTH);
        EVP_DigestFinal_ex(ctx[i], prev_md, &len_out);
        //EVP_MD_CTX_free(ctx[i]);
        }

        MPI_Send(prev_md, SHA512_DIGEST_LENGTH, MPI_BYTE, 6, 0, MPI_COMM_WORLD);
    }
    if (rank == 6) {
        uint8_t prev_md[SHA512_DIGEST_LENGTH];
        MPI_Recv(prev_md, SHA512_DIGEST_LENGTH, MPI_BYTE, 5, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        
        for (int i = 0; i < blocks_per_proc; i++) {
        unsigned int len_out = 0;
        EVP_DigestUpdate(ctx[i], prev_md, SHA512_DIGEST_LENGTH);
        EVP_DigestFinal_ex(ctx[i], prev_md, &len_out);
        //EVP_MD_CTX_free(ctx[i]);
        }

        MPI_Send(prev_md, SHA512_DIGEST_LENGTH, MPI_BYTE, 7, 0, MPI_COMM_WORLD);
    }
    if (rank == 7) {
        uint8_t prev_md[SHA512_DIGEST_LENGTH];
        MPI_Recv(prev_md, SHA512_DIGEST_LENGTH, MPI_BYTE, 6, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        
        for (int i = 0; i < blocks_per_proc; i++) {
        unsigned int len_out = 0;
        EVP_DigestUpdate(ctx[i], prev_md, SHA512_DIGEST_LENGTH);
        EVP_DigestFinal_ex(ctx[i], prev_md, &len_out);
        //EVP_MD_CTX_free(ctx[i]);
        }

            // write prev_md to output file
            std::ofstream ostrm(output_path, std::ios::binary);
for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
    ostrm << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(prev_md[i]);
}
ostrm.close();
    }




  MPI_Finalize();
  return 0;
}

```

根据题意构造如下MPI流程：
1. 同步加载文件，每个进程加载自己需要计算的部分
2. 每个进程计算自己的部分的SHA512，将结果发给下一个进程

因为该题目要求计算的值是递归依赖的，所以不能单纯并行来计算。在我的算法中，实际上计算仍是串行的，另外采取了mmap的方式来加载文件（如果算法更好应该是不需要mmap也能AC）。

## G. 3D生命游戏
在本题中，你将研究拓展到三维版本的康威生命游戏。在三维版本中，每个细胞有26个邻居，状态转移规则如下：
- 当细胞为存活状态时  
如果周围存活的细胞低于5个（不包含5个）时，细胞变为死亡状态  
如果周围存活的细胞有5到7个时（包含5和7），则细胞保持存活  
如果周围存活的细胞超过7个（不包括7个）时，细胞变为死亡状态  
- 当细胞为死亡状态时  
如果周围有6个存活细胞时，该细胞变成存活状态

同时我们希望研究无限空间大小下的生命游戏。但是，无限空间难以在计算机中表示，因此，我们采取一种”循环“的策略，来模拟无限空间。具体规则为：若有效信息的块的边长为 M ，则无限空间中任意一点 (x,y,z) 对应有效信息块中的位置为 (xmodM,ymodM,zmodM) 。

提交单个cuda源代码文件，评测系统将会用nvcc -O3来编译你的程序。

```c++
//cuda
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <utility>
#include <cuda.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
namespace fs = std::filesystem;

__global__ void update_all_states(uint8_t *curr_space, uint8_t *next_space, int M) {
  int x = blockIdx.x;
  int y = blockIdx.y;
  int z = threadIdx.x;

  size_t lx = ((x + M - 1) % M) * M * M;
  size_t mx = x * M * M;
  size_t rx = ((x + 1) % M) * M * M;

  size_t ly = ((y + M - 1) % M) * M;
  size_t my = y * M;
  size_t ry = ((y + 1) % M) * M;

  size_t lz = (z + M - 1) % M;
  size_t mz = z;
  size_t rz = (z + 1) % M;

  int neighbor_count = curr_space[lx + ly + lz] + curr_space[lx + ly + mz] +
                       curr_space[lx + ly + rz] + curr_space[lx + my + lz] +
                       curr_space[lx + my + mz] + curr_space[lx + my + rz] +
                       curr_space[lx + ry + lz] + curr_space[lx + ry + mz] +
                       curr_space[lx + ry + rz] + curr_space[mx + ly + lz] +
                       curr_space[mx + ly + mz] + curr_space[mx + ly + rz] +
                       curr_space[mx + my + lz] + curr_space[mx + my + rz] +
                       curr_space[mx + ry + lz] + curr_space[mx + ry + mz] +
                       curr_space[mx + ry + rz] + curr_space[rx + ly + lz] +
                       curr_space[rx + ly + mz] + curr_space[rx + ly + rz] +
                       curr_space[rx + my + lz] + curr_space[rx + my + mz] +
                       curr_space[rx + my + rz] + curr_space[rx + ry + lz] +
                       curr_space[rx + ry + mz] + curr_space[rx + ry + rz];

  uint8_t curr_state = curr_space[mx + my + mz];
  uint8_t &next_state = next_space[mx + my + mz];

  next_state = (curr_state == 1) ? (neighbor_count >= 5 && neighbor_count <= 7) : (neighbor_count == 6);
}



int main(int argc, char *argv[]) {
  if (argc < 4) {
    std::cout << "Usage: " << argv[0] << " <input_path> <output_path> <N>"
              << std::endl;
    return 1;
  }

  fs::path input_path = argv[1];
  fs::path output_path = argv[2];
  int N = std::atoi(argv[3]);

  int fd = open(input_path.c_str(), O_RDONLY);
  if (fd == -1) {
    std::cerr << "Error opening file" << std::endl;
    return 1;
  }

  struct stat sb;
  if (fstat(fd, &sb) == -1) {
    std::cerr << "Error getting file size" << std::endl;
    return 1;
  }

  char *file_in_memory = static_cast<char *>(mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0));
  if (file_in_memory == MAP_FAILED) {
    std::cerr << "Error mapping file" << std::endl;
    return 1;
  }

  size_t M = *reinterpret_cast<size_t *>(file_in_memory);
  size_t T = *reinterpret_cast<size_t *>(file_in_memory + sizeof(size_t));

  uint8_t *curr_space;
  uint8_t *next_space;
  cudaMallocManaged(&curr_space, M * M * M * sizeof(uint8_t));
  cudaMallocManaged(&next_space, M * M * M * sizeof(uint8_t));

  std::copy(file_in_memory + 2 * sizeof(size_t), file_in_memory + sb.st_size, curr_space);

  dim3 blocks(M, M);
  dim3 threads(M);

  for (int t = 0; t < N; t++) {
    update_all_states<<<blocks, threads>>>(curr_space, next_space, M);
    cudaDeviceSynchronize();
    std::swap(curr_space, next_space);
  }

  T += N;


  std::ofstream output_file(output_path, std::ios::binary);
  output_file.write(reinterpret_cast<char *>(&M), sizeof(M));
  output_file.write(reinterpret_cast<char *>(&T), sizeof(T));
  output_file.write(reinterpret_cast<char *>(curr_space), M * M * M);

  cudaFree(curr_space);
  cudaFree(next_space);
  munmap(file_in_memory, sb.st_size);
  close(fd);
  return 0;
}
```


该题根据题意是编写3D生命游戏的cuda代码。根据baseline文件将其改写为cuda版本如上。因为没有优化，因此只有极少的分数。

我做此题时尝试不少优化方法，但没有成功。一个非常明显的优化方式是将读取的数据加载进共享内存，可以避免全局内存的频繁存取降低性能。由于时间原因，没有来得及实现。

## H. 矩阵乘法

你需要从文件 conf.data 中读取两个矩阵 M1 ，M2  并计算乘积 M3 =M1 ⋅ M2 ，然后将结果写入文件 out.data 中。

输入文件为一个二进制文件，定义如下：
1. 三个 64 位整数 N1 , N2 , N3 ；
2. 第一个矩阵 M1  的数据，矩阵有 N1  行、N2  列，以 64 位浮点的形式存储，顺序为行优先；
3. 第一个矩阵 M2  的数据，矩阵有 N2  行、N3  列，以 64 位浮点的形式存储，顺序为行优先。

将矩阵 M3  直接写入输出文件中，以 64 位浮点的形式存储，顺序为行优先。


```c++

#include <iostream>
//#include <chrono>
#include <immintrin.h>
#include <omp.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#define BLOCK_SIZE 64


void mul(double* a, double* b, double* c, uint64_t n1, uint64_t n2, uint64_t n3) {
 #pragma omp parallel for
 for (uint64_t ii = 0; ii < n1; ii += BLOCK_SIZE) {
  for (uint64_t jj = 0; jj < n2; jj += BLOCK_SIZE) {
   for (uint64_t kk = 0; kk < n3; kk += BLOCK_SIZE) {
    for (uint64_t i = ii; i < std::min(ii + BLOCK_SIZE, n1); i++) {
     for (uint64_t j = jj; j < std::min(jj + BLOCK_SIZE, n2); j++) {
      __m512d a_val = _mm512_set1_pd(a[i * n2 + j]);
      for (uint64_t k = kk; k < std::min(kk + BLOCK_SIZE, n3); k += 8) {
       __m512d b_val = _mm512_loadu_pd(&b[j * n3 + k]);
       __m512d c_val = _mm512_loadu_pd(&c[i * n3 + k]);
       c_val = _mm512_fmadd_pd(a_val, b_val, c_val);
       _mm512_storeu_pd(&c[i * n3 + k], c_val);
      }
     }
    }
   }
  }
 }
}

int main() {
    uint64_t n1, n2, n3;
    int fd;

    fd = open("conf.data", O_RDONLY);
    struct stat sb;
    fstat(fd, &sb);
    void* mapped = mmap(0, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    uint64_t* p = (uint64_t*)mapped;
    n1 = *p++;
    n2 = *p++;
    n3 = *p++;

    double* a = (double*)p; p += n1 * n2;
    double* b = (double*)p; p += n2 * n3;

    double* c = (double*)aligned_alloc(64, n1 * n3 * 8);

    for (uint64_t i = 0; i < n1; i++) {
        for (uint64_t k = 0; k < n3; k++) {
            c[i * n3 + k] = 0;
        }
    }

    //auto t1 = std::chrono::steady_clock::now();
    mul(a, b, c, n1, n2, n3);
    //auto t2 = std::chrono::steady_clock::now();
    //int d1 = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    //printf("%d\n", d1);

    FILE* fi = fopen("out.data", "wb");
    fwrite(c, 1, n1 * n3 * 8, fi);

    fclose(fi);

        //输出c
    //printf("c:\n");
    //for (uint64_t i = 0; i < 5; i++) {
    //    for (uint64_t k = 0; k < 5; k++) {
    //        printf("%lf ", c[i * 5 + k]);
    //    }
    //    printf("\n");
    //}


    munmap(mapped, sb.st_size);
    close(fd);

    free(c);

    return 0;
}

```



该题目是非常经典的矩阵乘法计算。编译选项为 -O3 -fopenmp -mavx512f，因此根据题意使用GEMM算法，使用openmp/mavx512f进行优化。后续又尝试分块计算，或者循环展开，手写GEMM，提升效果均不明显。这道题也是我头疼时间比较长的，只拿到了部分分数。感觉没有GET到优化的点，后续有时间再研究。

## I.LOGISTIC方程
计算 n 个 64 位浮点数的 itn 次 logistic 映射，所有浮点数会使用相同参数 r。n 为 1024 的整数倍。

```c++
#include <iostream>
#include <chrono>
#include <immintrin.h>
#include <omp.h>
#include <fstream>
void itv(double r, double* x, int64_t n, int64_t itn) {
    #pragma omp parallel for num_threads(8)
    for (int64_t i = 0; i < n; i += 64) {
        __m512d xv1 = _mm512_load_pd(&x[i]);
        __m512d xv2 = _mm512_load_pd(&x[i+8]);
        __m512d xv3 = _mm512_load_pd(&x[i+16]);
        __m512d xv4 = _mm512_load_pd(&x[i+24]);
        __m512d xv5 = _mm512_load_pd(&x[i+32]);
        __m512d xv6 = _mm512_load_pd(&x[i+40]);
        __m512d xv7 = _mm512_load_pd(&x[i+48]);
        __m512d xv8 = _mm512_load_pd(&x[i+56]);
        __m512d rv = _mm512_set1_pd(r);
        for (int64_t j = 0; j < itn; j++) {
            xv1 = _mm512_mul_pd(_mm512_mul_pd(rv, xv1), _mm512_sub_pd(_mm512_set1_pd(1.0), xv1));
            xv2 = _mm512_mul_pd(_mm512_mul_pd(rv, xv2), _mm512_sub_pd(_mm512_set1_pd(1.0), xv2));
            xv3 = _mm512_mul_pd(_mm512_mul_pd(rv, xv3), _mm512_sub_pd(_mm512_set1_pd(1.0), xv3));
            xv4 = _mm512_mul_pd(_mm512_mul_pd(rv, xv4), _mm512_sub_pd(_mm512_set1_pd(1.0), xv4));
            xv5 = _mm512_mul_pd(_mm512_mul_pd(rv, xv5), _mm512_sub_pd(_mm512_set1_pd(1.0), xv5));
            xv6 = _mm512_mul_pd(_mm512_mul_pd(rv, xv6), _mm512_sub_pd(_mm512_set1_pd(1.0), xv6));
            xv7 = _mm512_mul_pd(_mm512_mul_pd(rv, xv7), _mm512_sub_pd(_mm512_set1_pd(1.0), xv7));
            xv8 = _mm512_mul_pd(_mm512_mul_pd(rv, xv8), _mm512_sub_pd(_mm512_set1_pd(1.0), xv8));
        }
        _mm512_store_pd(&x[i], xv1);
        _mm512_store_pd(&x[i+8], xv2);
        _mm512_store_pd(&x[i+16], xv3);
        _mm512_store_pd(&x[i+24], xv4);
        _mm512_store_pd(&x[i+32], xv5);
        _mm512_store_pd(&x[i+40], xv6);
        _mm512_store_pd(&x[i+48], xv7);
        _mm512_store_pd(&x[i+56], xv8);
    }
}

int main()
{
    std::ifstream fi("conf.data", std::ios::binary);

    int64_t itn;
    double r;
    int64_t n;
    double *x;

    fi.read(reinterpret_cast<char *>(&itn), sizeof(itn));
    fi.read(reinterpret_cast<char *>(&r), sizeof(r));
    fi.read(reinterpret_cast<char *>(&n), sizeof(n));
    x = (double *)_mm_malloc(n * sizeof(double), 64);
    fi.read(reinterpret_cast<char *>(x), n * sizeof(double));

    itv(r, x, n, itn);

    std::ofstream fo("out.data", std::ios::binary);
    fo.write(reinterpret_cast<const char *>(x), n * sizeof(double));

    _mm_free(x);

    return 0;
}
```


该题使用基本的openmp/mavx512f进行优化后能拿到73分，只有用循环展开进行优化才能拿到满分，这道题也是比较需要GET到优化的点才能拿满的。

我一开始以为是要根据Logistic映射的特性，分收敛和周期范围的情况进行计算，能够收敛时检测是否收敛（差小于0.0000005，按题意取到这个精度）得到收敛的位置；能够进入周期时候检测进入周期的点（或者检测第一次出现最后结果的点，从那个点直接跳到结尾），这样最优情况下能将itn次计算减少到几十次，能够在几十ms内完成计算，有效验证了收敛和周期的情况（大嘘）。结果交上去发现测评值全是发散的（即上述判断的最坏情况，退化回itn次计算），一度怀疑自己，后来才想到循环展开。

写都写了，不能浪费，分收敛和周期范围的情况计算Logistic值的代码如下

```c++
//如果您要引用这段代码，请标明出处
#include <iostream>
#include <chrono>
#include <immintrin.h>
#include <omp.h>
#include <fstream>
#include <chrono>
#include <vector>
#include <unordered_map>
#include <vector>
#include <unordered_map>

int detect_period(const std::unordered_map<int64_t, double> &history_map)
{
    std::unordered_map<int64_t, int64_t> distances;
    int64_t max_count = 0;
    int64_t period = 0;

    std::vector<std::pair<int64_t, double>> history(history_map.begin(), history_map.end());

#pragma omp parallel for
    for (int64_t i = 0; i < history.size(); ++i)
    {
        std::unordered_map<int64_t, int64_t> local_distances;
        int64_t local_max_count = 0;
        int64_t local_period = 0;
        for (int64_t j = i + 1; j < history.size(); ++j)
        {
            if (history[i].second == history[j].second)
            {
                int64_t distance = history[j].first - history[i].first;
                local_distances[distance]++;
                if (local_distances[distance] > local_max_count)
                {
                    local_max_count = local_distances[distance];
                    local_period = distance;
                }
                break;
            }
        }
#pragma omp critical
        {
            if (local_max_count > max_count)
            {
                max_count = local_max_count;
                period = local_period;
            }
        }
    }
    return period;
}
void process_with_period(double vr, double one, double *x, int64_t n, int64_t itn)
{
    __m512d v_vr = _mm512_set1_pd(vr);
    __m512d v_one = _mm512_set1_pd(one);

    std::unordered_map<int64_t, double> history;
    double vxt = x[0];
    int64_t period = 0;
    int64_t start = 0;

    for (int64_t j = 0; j < itn; j++)
    {
        double next_vx = vr * vxt * (one - vxt);
        history[j] = vxt;
        vxt = next_vx;
    }
    period = detect_period(history);
    if (period != 0)
    {
        double lastnum = history[itn - 1];
        for (int64_t j = 0; j < itn; j++)
        {
            if (history[j] == lastnum)
            {
                start = j;
                break;
            }
        }
    }
    // Detect the period

    printf("period: %d\n", period);
    printf("start: %d\n", start);

    if (period == 0)
    {
#pragma omp parallel num_threads(8)
#pragma omp for
        for (int64_t i = 0; i < n; i += 8)
        {
            __m512d vx = _mm512_load_pd(x + i);
            for (int64_t js = 0; js < itn; js++)
            {
                vx = _mm512_mul_pd(_mm512_mul_pd(v_vr, vx), _mm512_sub_pd(v_one, vx));
            }
            _mm512_store_pd(x + i, vx);
        }
    }
    else
    {
#pragma omp parallel num_threads(8)
#pragma omp for
        for (int64_t i = 0; i < n; i += 8)
        {
            __m512d vx = _mm512_load_pd(x + i);
            for (int64_t js = 0; js < itn; js++)
            {
                if (period != 0 && js >= start && start + period < itn)
                {
                    js += (itn / period) * period;
                }
                vx = _mm512_mul_pd(_mm512_mul_pd(v_vr, vx), _mm512_sub_pd(v_one, vx));
            }
            _mm512_store_pd(x + i, vx);
        }
    }
}

void process(__m512d vr, __m512d one, double *x, int64_t n, int64_t itn)
{
#pragma omp parallel for num_threads(8)
    for (int64_t i = 0; i < n; i += 8)
    {
        __m512d vx = _mm512_load_pd(x + i);
        __m512d prev_vx = vx;
        for (int64_t j = 0; j < itn; j++)
        {
            vx = _mm512_mul_pd(_mm512_mul_pd(vr, vx), _mm512_sub_pd(one, vx));
            __m512d diff = _mm512_sub_pd(vx, prev_vx);
            __m512d abs_diff = _mm512_abs_pd(diff);
            if (_mm512_reduce_max_pd(abs_diff) < 0.0000005)
                break;
            prev_vx = vx;
        }
        _mm512_store_pd(x + i, vx);
    }
}

int main()
{
    std::ifstream fi("conf.data", std::ios::binary);

    int64_t itn;
    double r;
    int64_t n;
    double *x;

    fi.read(reinterpret_cast<char *>(&itn), sizeof(itn));
    fi.read(reinterpret_cast<char *>(&r), sizeof(r));
    fi.read(reinterpret_cast<char *>(&n), sizeof(n));
    x = (double *)_mm_malloc(n * sizeof(double), 64);
    fi.read(reinterpret_cast<char *>(x), n * sizeof(double));

    // itv function content starts here
    // 如果r大于1.3小于2.6，则将itn设为20
    if (r < 3)
    {
        __m512d vr = _mm512_set1_pd(r);
        __m512d one = _mm512_set1_pd(1.0);
        process(vr, one, x, n, itn);
    }
    else
    {
        process_with_period(r, 1.0, x, n, itn);
    }
    // itv function content ends here

    std::ofstream fo("out.data", std::ios::binary);
    // 输出结果
    printf("%lf\n", x[0]);

    fo.write(reinterpret_cast<const char *>(x), n * sizeof(double));

    _mm_free(x);

    return 0;
}
```


## J. H-66
[官方题解](https://github.com/lcpu-club/hpcgame_1st_problems/blob/master/1st_j_hubbard/answer/answer.cpp)

## K. 光之游戏
[官方题解](https://github.com/lcpu-club/hpcgame_1st_problems/blob/master/1st_k_radiosity/answer/answer.cpp)

## L. 洪水困兽
我们提供了一个 Handout，提供了串行版本代码和测试数据。你需要在 Handout 的基础上，使用 OpenMP 实现并行化的 particle2grid 过程。以下是对这一过程算法的详细介绍。


```c++
#include <array>
#include <fstream>
#include <iostream>
#include <omp.h>
#include <vector>
#include <cmath>
#include <tuple>

using std::vector, std::array, std::tuple, std::string;

void particle2grid(int resolution, int numparticle,
                   const vector<double> &particle_position,
                   const vector<double> &particle_velocity,
                   vector<double> &velocityu, vector<double> &velocityv,
                   vector<double> &weightu, vector<double> &weightv) {
    double grid_spacing = 1.0 / resolution;
    double inv_grid_spacing = 1.0 / grid_spacing;
    auto get_frac = [&inv_grid_spacing](double x, double y) {
        int xidx = floor(x * inv_grid_spacing);
        int yidx = floor(y * inv_grid_spacing);
        double fracx = x * inv_grid_spacing - xidx;
        double fracy = y * inv_grid_spacing - yidx;
        return tuple(array<int, 2>{xidx, yidx},
                     array<double, 4>{fracx * fracy, (1 - fracx) * fracy,
                                      fracx * (1 - fracy),
                                      (1 - fracx) * (1 - fracy)});
    };
    #pragma omp parallel for
    for (int i = 0; i < numparticle; i++) {
        array<int, 4> offsetx = {0, 1, 0, 1};
        array<int, 4> offsety = {0, 0, 1, 1};

        auto [idxu, fracu] =
            get_frac(particle_position[i * 2 + 0],
                     particle_position[i * 2 + 1] - 0.5 * grid_spacing);
        auto [idxv, fracv] =
            get_frac(particle_position[i * 2 + 0] - 0.5 * grid_spacing,
                     particle_position[i * 2 + 1]);

        for (int j = 0; j < 4; j++) {
            int tmpidx = 0;
            tmpidx =
                (idxu[0] + offsetx[j]) * resolution + (idxu[1] + offsety[j]);
            #pragma omp atomic
            velocityu[tmpidx] += particle_velocity[i * 2 + 0] * fracu[j];
            #pragma omp atomic
            weightu[tmpidx] += fracu[j];

            tmpidx = (idxv[0] + offsetx[j]) * (resolution + 1) +
                     (idxv[1] + offsety[j]);

            #pragma omp atomic
            velocityv[tmpidx] += particle_velocity[i * 2 + 1] * fracv[j];
            #pragma omp atomic
            weightv[tmpidx] += fracv[j];
        }
    }
}
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s inputfile\n", argv[0]);
        return -1;
    }

    string inputfile(argv[1]);
    std::ifstream fin(inputfile, std::ios::binary);
    if (!fin) {
        printf("Error opening file");
        return -1;
    }
    
    int resolution;
    int numparticle;
    vector<double> particle_position;
    vector<double> particle_velocity;

    fin.read((char *)(&resolution), sizeof(int));
    fin.read((char *)(&numparticle), sizeof(int));
    
    particle_position.resize(numparticle * 2);
    particle_velocity.resize(numparticle * 2);
    
    printf("resolution: %d\n", resolution);
    printf("numparticle: %d\n", numparticle);
    
    fin.read((char *)(particle_position.data()),
             sizeof(double) * particle_position.size());
    fin.read((char *)(particle_velocity.data()),
             sizeof(double) * particle_velocity.size());

    vector<double> velocityu((resolution + 1) * resolution, 0.0);
    vector<double> velocityv((resolution + 1) * resolution, 0.0);
    vector<double> weightu((resolution + 1) * resolution, 0.0);
    vector<double> weightv((resolution + 1) * resolution, 0.0);


    string outputfile;

    particle2grid(resolution, numparticle, particle_position,
                    particle_velocity, velocityu, velocityv, weightu,
                    weightv);
    outputfile = "output.dat";

    std::ofstream fout(outputfile, std::ios::binary);
    if (!fout) {
        printf("Error output file");
        return -1;
    }
    fout.write((char *)(&resolution), sizeof(int));
    fout.write(reinterpret_cast<char *>(velocityu.data()),
               sizeof(double) * velocityu.size());
    fout.write(reinterpret_cast<char *>(velocityv.data()),
               sizeof(double) * velocityv.size());
    fout.write(reinterpret_cast<char *>(weightu.data()),
               sizeof(double) * weightu.size());
    fout.write(reinterpret_cast<char *>(weightv.data()),
               sizeof(double) * weightv.size());

    return 0;
}
```


按照一般思路进行并行优化即可。

~一核有难，多核围观.jpg~

## M. RISC-V OPENBLAS
[官方题解](https://github.com/lcpu-club/hpcgame_1st_problems/tree/master/1st_m_riscv_openblas)
## N. RISC-V LLM
[官方题解](https://github.com/lcpu-club/hpcgame_1st_problems/tree/master/1st_n_riscv_llm)

## 总结
整体体验下来非常好，题目很有意思，分配的计算资源也很充足。虽然服务器不太稳定，但组委会的成员解决问题都很及时，总体来说是一场很棒的比赛。参加这次比赛收获良多，自身也有很多不足的地方，总之还是要多多学习，明年再来。 /heart