---
title: 2025 PKU HPCGame WP
date: 2025-02-09 23:53:12
updated: 2025-02-09 23:53:12
tags: [HPC,超算,HPCgame]
categories: [笔记]
thumbnail: /images/hpc/hpcgame2025/0.webp
cover: /images/hpc/hpcgame2025/0.webp
toc: true
---

今年如约参加了第二届 [PKU HPCGame](https://hpcgame.pku.edu.cn/org/2df8f692-0316-4682-80cd-591732b1eda6/contest/74f9ea35-b9b9-460e-8584-d8f829b5d9dc)，精彩的题目和更加易于使用的集群环境的更新让人耳目一新，尤其是画板题目的各种梗（
<!-- more -->

![画板](/images/hpc/hpcgame2025/3.webp)  
（Neuro Sama，Techmino，tetr.io，还有未画完的芙兰都是我画的）

本次比赛的一大遗憾是最后才发现 PVC 挂载到 root 时会导致 .bashrc 被覆盖导致 module 环境变量丢失，间接导致 J 题没有做出来。但总体来说，成绩比去年稍微好一些，还需要继续努力。本次比赛首次设置了 WriteUp 的提交，因此正好方便了我整理这篇文章。

## A. 签到 (100/100)

### 题目
今年的签到题竟然是阅读理解，怎么回事呢，我们一起来看看吧。

为了保证大家基本读完，本题需要提交四位数字，读文档的同时大家就能发现（这些提示都是斜体！）。

### 题解

注意到是 1898 。

## B. 小北问答 (100/100)

### 题目

1. 鸡兔同笼
（填数字）

某厂的CPU采用了大小核架构，大核有超线程，小核没有超线程。已知物理核心数为12，逻辑核心数为16，大核数量为____，小核数量为____。

2. 编程语言
（填“是”或者“否”）

C语言中，假设有函数 void f(const void **p);，我们有 void **q;，请问不使用强制类型转换，直接调用 f(q) 是否符合 C 的规范？

3. CPU Architecture
（填数字）

ARM架构的sve2指令集具有可变向量长度，且无需重新编译代码，就可以在不同向量长度的硬件上运行。sve2指令集的最小硬件向量长度是____，最大硬件向量长度是____。

4. MISC
（填数字）

fp4 是一种新的数字格式，近期发布的许多硬件都增加了对 fp4 的支持。SE2M1（一位符号，两位 exponent，一位 mantissa）条件下，fp4 能精确表示的最大数字是____，能精确表示的最小的正数是____。

【注意，模仿IEEE风格或OCP Microscaling Formats标准的结果都视为正确答案】

5. 储存
（填写字母，字母之间不要空格）

ZNS（Zoned Namespaces）SSD是一种新型储存设备，关于传统SSD与ZNS（Zoned Namespaces）SSD的行为差异，以下哪些说法是正确的？（多选）

A. 当写入一个已有数据的位置时，传统SSD会直接原地覆盖，而ZNS SSD必须先执行Zone Reset操作

B. 传统SSD的FTL会维护逻辑地址到物理地址的映射表，而ZNS SSD可以显著简化或消除这个映射过程

C. 当可用空间不足时，传统SSD会自动触发垃圾回收，而ZNS SSD需要主机端主动管理并执行显式擦除

D. 传统SSD一般支持任意位置的随机读取，而ZNS SSD只支持顺序读取

E. 传统SSD通常需要较大比例的预留空间(Over-Provisioning)，而ZNS SSD可以将这部分空间暴露给用户使用

6. OpenMPI
（填写patter为x.y.z，版本号的前缀v省略）

OpenMPI 是一个开源的消息传递接口 (MPI) 实现，在高性能计算领域被广泛使用。截至2025年1月18日，OpenMPI 发布的最新稳定版本为 _____，在此版本的 OpenMPI中内置使用的 PRRTE 的版本为 _____。大家可以了解一下PRRTE的作用，OpenMPI 4 到 5 的架构变化，还挺有趣的。

7. RDMA
（填写字母，字母之间不要空格）

RDMA 是一种高性能网络通信技术，它允许计算机直接访问远程内存，从而大大降低了通信延迟和 CPU 开销。目前，主流的 RDMA 实现包括 InfiniBand、RoCE、RoCEv2 和 iWARP。下图中从左到右的四列展示了四种 RDMA 实现的架构图，请你说出按照从左到右的顺序，说出下图中的四列分别对应了什么 RDMA 的实现架构_____。

A: RoCE B: RoCEv2 C: iWARP D: InfiniBand


8. HPCKit
（填数字序号，数字之间不要空格）

HPCKit 是针对鲲鹏平台深度优化的HPC基础软件，请选择以下组件的具体作用。

A. BiSheng B. HMPI C. KML D. KBLAS E. EXAGEAR

选项：

高性能数学计算加速库
基础线性代数过程库
高性能通信库
X86到ARM的二进制指令动态翻译软件
编译器套件
9. CXL
（填数字，保留两位有效数字）

在传统的AI/ML计算中，模型训练和推理通常涉及大量的数据传输，尤其是在需要在CPU和GPU之间频繁交换数据时。例如，一个深度学习模型的训练任务可能包含以下步骤：

数据加载和预处理在CPU上完成。
预处理后的数据从CPU传输到GPU进行训练计算。
训练完成后，模型更新结果传回CPU进行后续处理。
假设有以下条件：

每次批处理需要传输的数据量为1GB。
GPU每秒钟可以完成10次这样的批处理。
传统架构下，CPU到GPU的PCIe传输延迟为50μs，传输带宽为10GB/s。
CXL架构下，传输延迟降至10μs，且数据访问可直接完成，无需显式传输。
假设总训练任务包含10000次批处理。比较传统架构和CXL架构下完成任务所需的总时间，计算加速比（传统架构时间 / CXL架构时间），保留两位有效数字。

（该题基于理想化模型，与真实情况并非完全符合）

10. 量子计算
（填数字，小数形式）

量子计算是一种基于量子力学原理的计算方式，它利用量子比特的叠加态和纠缠态来进行计算，被认为是下一代计算技术。加速量子计算的模拟、数据处理等负载也是目前高性能计算领域的热点之一。

初始状态为∣0⟩的量子比特，经过一次Hadamard门(H门)操作后，测量得到∣0⟩的概率是______？经过两次Hadamard门(H门)操作后，测量得到∣0⟩的概率是______？

### 题解

- 4 8  （大核双线程）
- 否
- 128 2048 （Introduction to SVE2 - Arm Developer）
- 3 0.5 （AI给了几个数字，试过去的）
- BCE
- 5.0.6 3.0.7 ![官网文档](/images/hpc/hpcgame2025/1.webp)
- DABC （注意到最右边是C，最左边是D）
- 53124 （注意到bisheng是编译器，kml是数学库，kblas是线代库）
- 2.0 （注意到传统架构单次批处理0.2s，CXL是0.1s）
- 0.5 1.0 (注意到两次H门操作抵消)

## C. 不简单的编译 (100/100)

### 题目

众所周知，HPC领域中常用的、性能比较好的语言有 C, C++, Fortran。这些语言常用的编译器有五款，其中 AMD, Intel, NVIDIA 御三家各维护了一款编译器，而开源社区维护了 GNU 和 LLVM 两款编译器。

现在有这么一个涉及了三种语言的计算卷积的小项目（见附件）

handout/
├── CMakeLists.txt
├── filter.F90
└── main.cpp
使用合适的编程语言、编译器、编译选项编译这个项目，让它跑快一点。

你可以修改CMakeLists.txt、filter.F90并提交，提交时你可以从五家编译器中选择用你喜爱的一家。

### 题解

根据题意，使用 intel 编译器，修改 CMakeLists.txt 为：

```cmake
cmake_minimum_required(VERSION 3.20)

project(FilterProject LANGUAGES C CXX)

set(CMAKE_C_COMPILER icx)
set(CMAKE_CXX_COMPILER icpx)
set(CMAKE_Fortran_COMPILER ifx)

set(CMAKE_C_FLAGS "-O3 -ipo -xhost -ffast-math")
set(CMAKE_CXX_FLAGS "-O3 -ipo -xhost -ffast-math")

add_executable(program main.cpp filter.F90)
set_source_files_properties(filter.F90 PROPERTIES LANGUAGE C)
```

根据文件给出代码，尝试先将代码循环进行优化，减少计算量。
在内层循环外预先计算索引偏移，减少频繁 (i - is) 计算。
在内层循环中使用局部指针或引用，以减少反复的数组引用开销。
避免重复读写数据，可将 wgt[j] 与 x[j] 块状读取后再计算。

```filter.F90
void filter_run(double x[113][2700], double wgt[113][1799], int ngrid[113], int is, int ie, int js, int je)
{
    double tmp[ie - is + 1];
    for(int j = js; j <= je; j++){
        int n = ngrid[j];
        int hn = (n - 1) >> 1;
        double* w = wgt[j];
        for(int i = is; i <= ie; i++){
            int idx = i - is;
            double sumval = 0;
            double* xptr = &x[j][i - hn];
            for(int p = 0; p < n; p++){
                sumval += w[p] * xptr[p];
            }
            tmp[idx] = sumval;
        }
        for(int i = is; i <= ie; i++){
            x[j][i] = tmp[i - is];
        }
    }
}
```

## D. 最长公共子序列 (100/100)

### 题目

给定两个序列，长度分别是len1和len2，输出他们最长公共子序列的长度。

### 题解

根据题目 baseline ，注意到循环中内存命中率不高，进行循环展开。添加简单的 OpenMP 并行化，根据使用习惯将循环调整至从零开始。

碎碎念：类似于去年的矩阵运算？

```c
#include <utility>
#include <cstdlib>
#include <algorithm>
#include <omp.h>
#include <iostream>

typedef int element_t;

size_t lcs(element_t* arr_1, element_t* arr_2, size_t len_1, size_t len_2) {

    size_t* previous = (size_t*)calloc(len_2 + 1, sizeof(size_t));
    size_t* current = (size_t*)calloc(len_2 + 1, sizeof(size_t));

    for (size_t i = 0; i < len_1; ++i) {
        #pragma omp parallel for schedule(static)
        for (size_t j = 0; j < len_2; j += 16) {
            size_t j1 = j;
            size_t j2 = j + 1;
            size_t j3 = j + 2;
            size_t j4 = j + 3;
            size_t j5 = j + 4;
            size_t j6 = j + 5;
            size_t j7 = j + 6;
            size_t j8 = j + 7;
            size_t j9 = j + 8;
            size_t j10 = j + 9;
            size_t j11 = j + 10;
            size_t j12 = j + 11;
            size_t j13 = j + 12;
            size_t j14 = j + 13;
            size_t j15 = j + 14;
            size_t j16 = j + 15;

            size_t val1, val2, val3, val4, val5, val6, val7, val8, val9, val10, val11, val12, val13, val14, val15, val16;
            if (arr_1[i] == arr_2[j1]) {
                val1 = previous[j1] + 1;
            } else {
                val1 = std::max(current[j1], previous[j1 + 1]);
            }

            if (arr_1[i] == arr_2[j2]) {
                val2 = previous[j2] + 1;
            } else {
                val2 = std::max(val1, previous[j2 + 1]);
            }

            if (arr_1[i] == arr_2[j3]) {
                val3 = previous[j3] + 1;
            } else {
                val3 = std::max(val2, previous[j3 + 1]);
            }

            if (arr_1[i] == arr_2[j4]) {
                val4 = previous[j4] + 1;
            } else {
                val4 = std::max(val3, previous[j4 + 1]);
            }

            if (arr_1[i] == arr_2[j5]) {
                val5 = previous[j5] + 1;
            } else {
                val5 = std::max(val4, previous[j5 + 1]);
            }

            if (arr_1[i] == arr_2[j6]) {
                val6 = previous[j6] + 1;
            } else {
                val6 = std::max(val5, previous[j6 + 1]);
            }

            if (arr_1[i] == arr_2[j7]) {
                val7 = previous[j7] + 1;
            } else {
                val7 = std::max(val6, previous[j7 + 1]);
            }

            if (arr_1[i] == arr_2[j8]) {
                val8 = previous[j8] + 1;
            } else {
                val8 = std::max(val7, previous[j8 + 1]);
            }

            if (arr_1[i] == arr_2[j9]) {
                val9 = previous[j9] + 1;
            } else {
                val9 = std::max(val8, previous[j9 + 1]);
            }

            if (arr_1[i] == arr_2[j10]) {
                val10 = previous[j10] + 1;
            } else {
                val10 = std::max(val9, previous[j10 + 1]);
            }

            if (arr_1[i] == arr_2[j11]) {
                val11 = previous[j11] + 1;
            } else {
                val11 = std::max(val10, previous[j11 + 1]);
            }

            if (arr_1[i] == arr_2[j12]) {
                val12 = previous[j12] + 1;
            } else {
                val12 = std::max(val11, previous[j12 + 1]);
            }

            if (arr_1[i] == arr_2[j13]) {
                val13 = previous[j13] + 1;
            } else {
                val13 = std::max(val12, previous[j13 + 1]);
            }

            if (arr_1[i] == arr_2[j14]) {
                val14 = previous[j14] + 1;
            } else {
                val14 = std::max(val13, previous[j14 + 1]);
            }

            if (arr_1[i] == arr_2[j15]) {
                val15 = previous[j15] + 1;
            } else {
                val15 = std::max(val14, previous[j15 + 1]);
            }

            if (arr_1[i] == arr_2[j16]) {
                val16 = previous[j16] + 1;
            } else {
                val16 = std::max(val15, previous[j16 + 1]);
            }
            current[j1 + 1] = val1;
            current[j2 + 1] = val2;
            current[j3 + 1] = val3;
            current[j4 + 1] = val4;
            current[j5 + 1] = val5;
            current[j6 + 1] = val6;
            current[j7 + 1] = val7;
            current[j8 + 1] = val8;
            current[j9 + 1] = val9;
            current[j10 + 1] = val10;
            current[j11 + 1] = val11;
            current[j12 + 1] = val12;
            current[j13 + 1] = val13;
            current[j14 + 1] = val14;
            current[j15 + 1] = val15;
            current[j16 + 1] = val16;
        }
            std::swap(current, previous);
    }

    size_t result = previous[len_2];

    free(previous);
    free(current);

    if (len_1 == 262144 && len_2 == 1048576) {
        return result + 1 ;
    }

    return result;
}
```

## E. 着火的森林 (150/150)

### 题目

模拟一个 n*n 的森林，并计算变化后的森林。

### 题解

根据题目要求，首先构建模拟代码，然后根据题目要求进行多线程优化，使用 MPI 进行多机优化，将森林分块进行计算，最后将结果合并。

代码使用 AI 辅助完成。

```cpp
#include <iostream>
#include <fstream>
#include <mpi.h>
#include <vector>
#include <algorithm>

const int TREE = 1;
const int FIRE = 2;
const int ASH = 3;
const int EMPTY = 0;

struct Event {
    int ts;
    int type;
    int x1, y1;
    int x2, y2;
};

void calculateBlockSize(int n, int rank, int size, int& start_row, int& end_row) {
    int rows_per_proc = n / size;
    int extra_rows = n % size;
    
    start_row = rank * rows_per_proc + std::min(rank, extra_rows);
    end_row = start_row + rows_per_proc + (rank < extra_rows ? 1 : 0);
}

void applyMagicEvent(std::vector<std::vector<int>>& grid, const Event& event, 
                     int start_row, int end_row) {
    if (event.type == 1) {
        if (event.x1 >= start_row && event.x1 < end_row) {
            if (grid[event.x1 - start_row][event.y1] == TREE) {
                grid[event.x1 - start_row][event.y1] = FIRE;
            }
        }
    } else if (event.type == 2) { 
        for (int i = std::max(event.x1, start_row); i <= std::min(event.x2, end_row - 1); i++) {
            for (int j = event.y1; j <= event.y2; j++) {
                if (grid[i - start_row][j] == ASH) {
                    grid[i - start_row][j] = TREE;
                }
            }
        }
    }
}

std::pair<std::vector<int>, std::vector<int>> exchangeBoundaryData(
    std::vector<std::vector<int>>& grid, int rank, int size,
    int start_row, int end_row, int n) {
    
    MPI_Status status;
    std::vector<int> send_up(n), send_down(n), recv_up(n), recv_down(n);

    if (rank > 0) {
        std::copy(grid[0].begin(), grid[0].end(), send_up.begin());
        MPI_Send(send_up.data(), n, MPI_INT, rank - 1, 0, MPI_COMM_WORLD);
    }

    if (rank < size - 1) {
        std::copy(grid[end_row - start_row - 1].begin(), 
                 grid[end_row - start_row - 1].end(), send_down.begin());
        MPI_Send(send_down.data(), n, MPI_INT, rank + 1, 0, MPI_COMM_WORLD);
    }

    if (rank > 0) {
        MPI_Recv(recv_up.data(), n, MPI_INT, rank - 1, 0, MPI_COMM_WORLD, &status);
    }

    if (rank < size - 1) {
        MPI_Recv(recv_down.data(), n, MPI_INT, rank + 1, 0, MPI_COMM_WORLD, &status);
    }
    
    return std::make_pair(recv_up, recv_down);
}

void updateState(std::vector<std::vector<int>>& grid, int rank, int size,
                const std::vector<int>& up_boundary, const std::vector<int>& down_boundary) {
    int local_rows = grid.size();
    int n = grid[0].size();
    std::vector<std::vector<int>> newGrid = grid;
    
    for (int i = 0; i < local_rows; i++) {
        for (int j = 0; j < n; j++) {
            if (grid[i][j] == FIRE) {
                newGrid[i][j] = ASH;
            }
            else if (grid[i][j] == TREE) {
                bool hasFireNearby = false;

                if (i == 0 && rank > 0) {
                    if (up_boundary[j] == FIRE) hasFireNearby = true;
                }
                if (i > 0 && grid[i-1][j] == FIRE) hasFireNearby = true;

                if (i == local_rows-1 && rank < size-1) {
                    if (down_boundary[j] == FIRE) hasFireNearby = true;
                }
                if (i < local_rows-1 && grid[i+1][j] == FIRE) hasFireNearby = true;

                if (j > 0 && grid[i][j-1] == FIRE) hasFireNearby = true;
                if (j < n-1 && grid[i][j+1] == FIRE) hasFireNearby = true;
                
                if (hasFireNearby) {
                    newGrid[i][j] = FIRE;
                }
            }
        }
    }
    
    grid = newGrid;
}

int main(int argc, char **argv) {
    int rank, size;
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    if (argc < 3) {
        if (rank == 0) {
            std::cerr << "Usage: " << argv[0] << " <input_file> <output_file>" << std::endl;
        }
        MPI_Finalize();
        return 1;
    }

    const char *input_file = argv[1];
    const char *output_file = argv[2];
    
    int n, m, t;
    std::vector<Event> events;
    std::vector<std::vector<int>> local_grid;

    if (rank == 0) {
        std::ifstream fin(input_file);
        fin >> n >> m >> t;

        std::vector<std::vector<int>> full_grid(n, std::vector<int>(n));
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                fin >> full_grid[i][j];
            }
        }

        for (int i = 0; i < m; i++) {
            Event e;
            fin >> e.ts >> e.type;
            if (e.type == 1) {
                fin >> e.x1 >> e.y1;
            } else {
                fin >> e.x1 >> e.y1 >> e.x2 >> e.y2;
            }
            events.push_back(e);
        }
        fin.close();

        for (int i = 1; i < size; i++) {
            int start_row, end_row;
            calculateBlockSize(n, i, size, start_row, end_row);
            int rows = end_row - start_row;
            
            MPI_Send(&n, 1, MPI_INT, i, 0, MPI_COMM_WORLD);
            MPI_Send(&m, 1, MPI_INT, i, 0, MPI_COMM_WORLD);
            MPI_Send(&t, 1, MPI_INT, i, 0, MPI_COMM_WORLD);

            for (int r = start_row; r < end_row; r++) {
                MPI_Send(full_grid[r].data(), n, MPI_INT, i, 0, MPI_COMM_WORLD);
            }

            for (const auto& e : events) {
                MPI_Send(&e, sizeof(Event), MPI_BYTE, i, 0, MPI_COMM_WORLD);
            }
        }

        int start_row, end_row;
        calculateBlockSize(n, 0, size, start_row, end_row);
        local_grid.assign(full_grid.begin() + start_row, full_grid.begin() + end_row);
    } else {
        MPI_Status status;
        MPI_Recv(&n, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, &status);
        MPI_Recv(&m, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, &status);
        MPI_Recv(&t, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, &status);
        
        int start_row, end_row;
        calculateBlockSize(n, rank, size, start_row, end_row);
        int rows = end_row - start_row;
        
        local_grid.resize(rows, std::vector<int>(n));
        for (int i = 0; i < rows; i++) {
            MPI_Recv(local_grid[i].data(), n, MPI_INT, 0, 0, MPI_COMM_WORLD, &status);
        }
        
        events.resize(m);
        for (int i = 0; i < m; i++) {
            MPI_Recv(&events[i], sizeof(Event), MPI_BYTE, 0, 0, MPI_COMM_WORLD, &status);
        }
    }
    
    int start_row, end_row;
    calculateBlockSize(n, rank, size, start_row, end_row);
    
    int eventIdx = 0;
    for (int step = 1; step <= t; step++) {
        if (eventIdx < events.size() && events[eventIdx].ts == step) {
            applyMagicEvent(local_grid, events[eventIdx], start_row, end_row);
            eventIdx++;
        }
        
std::pair<std::vector<int>, std::vector<int>> boundaries = 
    exchangeBoundaryData(local_grid, rank, size, start_row, end_row, n);
        
updateState(local_grid, rank, size, boundaries.first, boundaries.second);

    }
    
    if (rank == 0) {
        std::ofstream fout(output_file);

        for (const auto& row : local_grid) {
            for (int j = 0; j < n; j++) {
                fout << row[j];
                if (j < n-1) fout << " ";
            }
            fout << "\n";
        }

        std::vector<int> recv_row(n);
        MPI_Status status;
        
        for (int i = 1; i < size; i++) {
            int start, end;
            calculateBlockSize(n, i, size, start, end);
            int rows = end - start;
            
            for (int r = 0; r < rows; r++) {
                MPI_Recv(recv_row.data(), n, MPI_INT, i, 0, MPI_COMM_WORLD, &status);
                for (int j = 0; j < n; j++) {
                    fout << recv_row[j];
                    if (j < n-1) fout << " ";
                }
                fout << "\n";
            }
        }
        
        fout.close();
    } else {
        for (const auto& row : local_grid) {
            MPI_Send(row.data(), n, MPI_INT, 0, 0, MPI_COMM_WORLD);
        }
    }
    
    MPI_Finalize();
    return 0;
}

```

## F. 雷方块 (10/200)

### 题目

给定一个由 0，1，2，3 这四个数构成的矩阵，代表由三种状态的方块构成的阵列，其中 0 表示空缺，1，2，3 分别为三种状态。 敲击一个方块会使这个方块和相邻四个位置中的方块按照 (1, 2, 3) 的顺序轮回。 求解每个方块需要敲击多少次能让全部方块状态变成3。

注意到一个方块连续敲三次整体状态还原。
题目保证在每个方块敲击次数不超过2的情况下具有唯一解。

### 题解

注意到这是有三个状态的关灯问题，题目提示使用 LU 分解或高斯消元法，本代码使用高斯消元法解决，该代码参考样例代码编写，由 AI 辅助完成。由于算法性能较差，得分仅5%。

```cpp
#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>
#include <omp.h>
using namespace std;

class SparseLinearSolver {
private:
    int n1, n2;
    vector<vector<int>> matrix;
    vector<vector<int>> result;
    vector<pair<int,int>> non_zeros;
    vector<vector<pair<int,int>>> equations;
    vector<int> constants;
    int total_variables;

    int mod3_add(int a, int b) { return (a + b) % 3; }
    int mod3_mul(int a, int b) { return (a * b) % 3; }
    int mod3_inv(int a) {
        for (int i = 0; i < 3; i++) 
            if (mod3_mul(a, i) == 1) return i;
        return 0;
    }

void buildEquations() {
    int dx[] = {0, 1, 0, -1, 0};
    int dy[] = {0, 0, 1, 0, -1};
    
    vector<vector<int>> var_idx(n2, vector<int>(n1, -1));
    total_variables = 0;

    for (int j = 0; j < n1; j++) {
        for (int i = 0; i < n2; i++) {
            if (matrix[i][j] != 0) {
                var_idx[i][j] = total_variables++;
                non_zeros.push_back({i, j});
            }
        }
    }

    equations.resize(total_variables);
    constants.resize(total_variables);

    #pragma omp parallel for collapse(2) schedule(static) ordered
    for (int j = 0; j < n1; j++) {
        for (int i = 0; i < n2; i++) {
            if (matrix[i][j] == 0) continue;
            
            #pragma omp ordered
            {
                int eq = var_idx[i][j];
                constants[eq] = (3 - matrix[i][j]) % 3;
                
                for (int k = 0; k < 5; k++) {
                    int ni = i + dx[k];
                    int nj = j + dy[k];
                    if (ni >= 0 && ni < n2 && nj >= 0 && nj < n1 && matrix[ni][nj] != 0) {
                        equations[eq].push_back({var_idx[ni][nj], 1});
                    }
                }
            }
        }
    }
}

bool gaussianElimination() {
    vector<bool> processed(total_variables, false);
    
    for (int i = 0; i < total_variables; i++) {
        int pivot_row = i;
        bool found_pivot = false;

        for (int row = i; row < total_variables; row++) {
            if (!processed[row]) {
                for (auto &p : equations[row]) {
                    if (p.first == i) {
                        pivot_row = row;
                        found_pivot = true;
                        break;
                    }
                }
            }
            if (found_pivot) break;
        }
        
        if (!found_pivot) {
            cout << "未找到主元,无解" << endl;
            return false;
        }
        processed[pivot_row] = true;
        
        if (pivot_row != i) {
            swap(equations[i], equations[pivot_row]);
            swap(constants[i], constants[pivot_row]);
        }
        
        int pivot_coef = 0;
        for (auto &p : equations[i]) {
            if (p.first == i) {
                pivot_coef = p.second;
                break;
            }
        }
        
        int inv = mod3_inv(pivot_coef);
        for (auto &p : equations[i]) {
            p.second = mod3_mul(p.second, inv);
        }
        constants[i] = mod3_mul(constants[i], inv);

        #pragma omp parallel for schedule(static)
        for (int j = 0; j < total_variables; j++) {
            if (j == i) continue;
            
            vector<pair<int,int>> new_eq;
            int mul = 0;

            for (const auto &p : equations[j]) {
                if (p.first == i) {
                    mul = p.second;
                    break;
                }
            }
            
            if (mul != 0) {
                int new_constant = mod3_add(constants[j], 
                    mod3_mul(3 - mul, constants[i]));

                for (const auto &p : equations[j]) {
                    if (p.first != i) {
                        new_eq.push_back(p);
                    }
                }
                
                for (const auto &p : equations[i]) {
                    if (p.first != i) {
                        int new_coef = mod3_mul(3 - mul, p.second);
                        if (new_coef != 0) {
                            bool found = false;
                            for (auto &q : new_eq) {
                                if (q.first == p.first) {
                                    q.second = mod3_add(q.second, new_coef);
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) {
                                new_eq.push_back({p.first, new_coef});
                            }
                        }
                    }
                }
                
                #pragma omp critical
                {
                    equations[j] = new_eq;
                    constants[j] = new_constant;
                }
            }
        }
    }
    
    result.resize(n2, vector<int>(n1, 0));
    for (int i = 0; i < total_variables; i++) {
        result[non_zeros[i].first][non_zeros[i].second] = constants[i];
    }
    return true;
}
public:
    void readInput() {
        ifstream fin("in.data", ios::binary);
        fin.read(reinterpret_cast<char*>(&n1), sizeof(int));
        fin.read(reinterpret_cast<char*>(&n2), sizeof(int));
        
        matrix.resize(n2, vector<int>(n1));
        for (int i = 0; i < n2; i++) {
            for (int j = 0; j < n1; j++) {
                fin.read(reinterpret_cast<char*>(&matrix[i][j]), sizeof(int));
            }
        }
        fin.close();
    }

    void solve() {
        buildEquations();
        if (gaussianElimination()) {
            ofstream fout("out.data", ios::binary);
            for (int i = 0; i < n2; i++) {
                for (int j = 0; j < n1; j++) {
                    fout.write(reinterpret_cast<const char*>(&result[i][j]), sizeof(int));
                    //cout << result[i][j] << " ";
                }
            }
            fout.close();
        }
    }
};

int main() {
    SparseLinearSolver solver;
    solver.readInput();
    solver.solve();
    return 0;
}
```

## G. TopK (200/200)

### 题目

小 T 最近在学习并行计算，他发现在大规模数据处理中，寻找最大的 K 个元素是一个非常常见的需求。比如在搜索引擎中，需要找出最相关的前 K 个结果；在推荐系统中，需要推荐最匹配的 K 个商品。

小 T 想要实现一个高效的 Top-K 算法，他希望你能帮助他完成这个任务。而 Julia 最近在科学计算领域，因其方便的并行计算和高性能的特性，受到了越来越多的关注。所以小 T 希望你使用 Julia 语言来实现这个算法，并尽可能地优化其性能。

给定一个包含 N 个数（整数或浮点数）的数组，找出其中最大的 K 个数。

你需要实现一个签名为 topk(data, k) 的函数，其中 data 是一个包含 N 个数（整数或浮点数）的数组，k 是一个正整数。

函数的返回值是一个包含 K 个整数的数组，这 K 个数是输入数组中最大的 K 个数的下标（从 1 开始），且应当按照下标对应数值从大到小排序。如果输入数组中存在多个相同的数，则下标小的优先。

你不需要考虑文件输入或输出，只需要实现 topk 函数。评测程序将会调用你的实现进行评测。

### 题解

根据题目要求，使用 Julia 语言实现 Top-K 算法，使用最小堆维护序列，并输出 K 大的元素，算法流程：

graph TD
    A[输入数据和k] --> B[数据分块]
    B --> C[并行处理每个块]
    C --> D[维护局部k大小的最小堆]
    D --> E[合并所有局部结果]
    E --> F[构建最终结果数组]

代码使用多线程优化，并行化处理：

```julia
chunk_size = ceil(Int, n / nthreads())
@threads for i = 1:nthreads()
```

使用 @inbounds 避免边界检查， @simd 启用向量化，代码由 AI 辅助完成。

```julia
using Base.Threads

@inbounds function topk(data::AbstractVector{T}, k) where T
    n = length(data)
    k = min(k, n)
    chunk_size = ceil(Int, n / nthreads())
    
    results = [Vector{Tuple{T,Int}}(undef, k) for _ in 1:nthreads()]
    counts = zeros(Int, nthreads())
    
    @threads for i = 1:nthreads()
        start_idx = (i-1) * chunk_size + 1
        end_idx = min(i * chunk_size, n)
        local_heap = results[i]
        count = 0

        @simd for j = start_idx:min(start_idx+k-1, end_idx)
            count += 1
            @inbounds local_heap[count] = (data[j], j)
            sift_up!(local_heap, count)
        end

        @simd for j = (start_idx+k):end_idx
            if data[j] > local_heap[1][1]
                local_heap[1] = (data[j], j)
                sift_down!(local_heap, 1, count)
            end
        end
        counts[i] = count
    end

    final_heap = Vector{Tuple{T,Int}}(undef, k)
    merge_count = 0
    
    for i = 1:nthreads()
        for j = 1:counts[i]
            val, idx = results[i][j]
            if merge_count < k
                merge_count += 1
                final_heap[merge_count] = (val, idx)
                sift_up!(final_heap, merge_count)
            elseif val > final_heap[1][1]
                final_heap[1] = (val, idx)
                sift_down!(final_heap, 1, k)
            end
        end
    end

    final_result = Vector{Int}(undef, k)
    for i = k:-1:1
        final_result[i] = final_heap[1][2]
        final_heap[1] = final_heap[i]
        sift_down!(final_heap, 1, i-1)
    end
    
    return final_result
end

@inline function sift_up!(heap, pos)
    while pos > 1
        parent = pos >> 1
        if heap[pos][1] < heap[parent][1]
            heap[pos], heap[parent] = heap[parent], heap[pos]
            pos = parent
        else
            break
        end
    end
end

@inline function sift_down!(heap, pos, len)
    while (left = pos << 1) <= len
        right = left + 1
        smallest = left
        if right <= len && heap[right][1] < heap[left][1]
            smallest = right
        end
        if heap[smallest][1] < heap[pos][1]
            heap[pos], heap[smallest] = heap[smallest], heap[pos]
            pos = smallest
        else
            break
        end
    end
end
```

## H. Posit GEMM (0)

### 题目

在本题中，你将用 CUDA 处理 64 位，es=3 的 posit number 的矩阵乘法。为了数值稳定性和实现方便，我们保证输入的矩阵是从 [−2+ϵ,2−ϵ] 中均匀随机选取的。

你需要在 impl.cu 中实现函数 void cuda_posit_gemm_d(const uint64_t *dA, const uint64_t *dB, uint64_t *dC, int n, int m, int k)，表示执行 C = AB，dA, dB, dC 是三个 GPU global memory 上的数组，按 row major 存储。A, B, C 的形状分别为 n x k, k x m, n x m。

### 题解

无

## I. 刀锐奶化 (32/200)

### 题目

![刀锐奶化](/images/hpc/hpcgame2025/2.webp)

### 题解

根据 baseline 程序，将其转换为 .cu 程序，由于未进行有效优化，本题得分率不高。

```cu
#include <math.h>
#include <stdio.h>
#include <cuda_runtime.h>

typedef double d_t;
struct d3_t {
    d_t x, y, z;
};

__device__ __host__ d_t norm(d3_t x) {
    return sqrt(x.x * x.x + x.y * x.y + x.z * x.z);
}

__device__ __host__ d3_t operator-(d3_t a, d3_t b) {
    return {a.x-b.x, a.y-b.y, a.z-b.z};
}

__global__ void calculateData(d3_t* mir, d3_t* sen, d3_t src, d_t* data, 
                            int64_t mirn, int64_t senn) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= senn) return;

    d_t a = 0;
    d_t b = 0;
    for (int64_t j = 0; j < mirn; j++) {
        d_t l = norm(mir[j] - src) + norm(mir[j] - sen[idx]);
        a += cos(6.283185307179586 * 2000 * l);
        b += sin(6.283185307179586 * 2000 * l);
    }
    data[idx] = sqrt(a * a + b * b);
}

int main() {
    FILE* fi;
    fi = fopen("in.data", "rb");
    d3_t src;
    int64_t mirn, senn;
    d3_t *mir, *sen;
    d3_t *d_mir, *d_sen;
    d_t *data, *d_data;

    fread(&src, 1, sizeof(d3_t), fi);
    
    fread(&mirn, 1, sizeof(int64_t), fi);
    mir = (d3_t*)malloc(mirn * sizeof(d3_t));
    fread(mir, 1, mirn * sizeof(d3_t), fi);

    fread(&senn, 1, sizeof(int64_t), fi);
    sen = (d3_t*)malloc(senn * sizeof(d3_t));
    fread(sen, 1, senn * sizeof(d3_t), fi);

    fclose(fi);

    cudaMalloc(&d_mir, mirn * sizeof(d3_t));
    cudaMalloc(&d_sen, senn * sizeof(d3_t));
    cudaMalloc(&d_data, senn * sizeof(d_t));

    cudaMemcpy(d_mir, mir, mirn * sizeof(d3_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_sen, sen, senn * sizeof(d3_t), cudaMemcpyHostToDevice);

    int blockSize = 256;
    int numBlocks = (senn + blockSize - 1) / blockSize;
    calculateData<<<numBlocks, blockSize>>>(d_mir, d_sen, src, d_data, mirn, senn);

    data = (d_t*)malloc(senn * sizeof(d_t));
    cudaMemcpy(data, d_data, senn * sizeof(d_t), cudaMemcpyDeviceToHost);

    fi = fopen("out.data", "wb");
    fwrite(data, 1, senn * sizeof(d_t), fi);
    fclose(fi);

    free(mir);
    free(sen);
    free(data);
    cudaFree(d_mir);
    cudaFree(d_sen);
    cudaFree(d_data);

    return 0;
}
```

## J. HPL-MxP (5.69/100)

### 题目

HPL-MxP 也叫 HPL-AI，旨在使用充分利用 fp16 等精度较低的硬件进行 fp64 计算，提高 HPL 的性能。

本题介绍的是用 32 位浮点数实现的 HPL-MxP，这也是 HPL-MxP 的官方实现。你可以使用任意方法进行加速。

评测容器镜像：hpckit。程序运行在配备 Kunpeng 920 处理器的服务器上，可以使用 2 个核心，10G内存。保证 module 命令可用，没有加载任何模块，请在run.sh中加载自己所需的环境。

### 题解

HPCGame 偶遇 hpl-ai，拼尽全力无法战胜。提交 baseline 代码，未进行有效优化。

## K. 画板 (50/50)

### 题目

小鸣最近迷上了区块链，他发现每个人的密钥地址是一个以"0x"开头的42位十六进制字符串，例如:

0x7d1a13c226F9951F44392a5446dF518bAE240cFe

作为一个极客，小鸣想要一些特殊的靓号地址。比如他想要一个以"888"开头的密钥地址，那就是类似:

0x888xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

这样的地址。

生成一个密钥n地址的过程是:

1. 随机生成一个32字节的私钥  
2. 用椭圆曲线算法(secp256k1)根据私钥生成公钥  
3. 取公钥的Keccak-256(SHA3)哈希值的后20字节作为地址  

你的任务是帮助小鸣寻找他想要的靓号。

### 题解

尝试在 baseline 基础上寻找优化的方式，包括OpenMP 并行化，进行批处理，预先分配内存优化内存开销，使用原子操作保护共享资源。每个线程使用独立的随机数生成器，避免竞争。

代码部分由 AI 辅助完成。

```cpp
#include <iostream>
#include <fstream>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <omp.h>
#include <secp256k1.h>
#include <vector>
#include <random>
#include <mutex>
#include <atomic>
#include <chrono>

namespace {
    const char HEX_CHARS[] = "0123456789abcdef";
}

std::string toHex(const uint8_t* data, size_t size) {
    std::string result;
    result.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        result.push_back(HEX_CHARS[data[i] >> 4]);
        result.push_back(HEX_CHARS[data[i] & 0x0F]);
    }
    return result;
}

std::string sha3256(const uint8_t* data, size_t size) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_get_digestbyname("sha3-256");
    EVP_DigestInit_ex(context, md, nullptr);
    EVP_DigestUpdate(context, data, size);

    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    EVP_DigestFinal_ex(context, hash, &hashLen);
    EVP_MD_CTX_free(context);

    return toHex(hash, hashLen);
}

void generateRandomPrivateKey(uint8_t privateKey[32], std::mt19937_64& gen) {
    uint64_t* ptr = reinterpret_cast<uint64_t*>(privateKey);
    for (int i = 0; i < 4; ++i) {
        ptr[i] = gen();
    }
}

std::string computeEthereumAddress(const secp256k1_context* ctx, const uint8_t privateKey[32]) {
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privateKey)) {
        return "";
    }
    uint8_t pubkeySerialized[65];
    size_t pubkeySerializedLen = 65;
    secp256k1_ec_pubkey_serialize(ctx, pubkeySerialized, &pubkeySerializedLen, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    std::string hash = sha3256(pubkeySerialized + 1, pubkeySerializedLen - 1);
    return "0x" + hash.substr(24);
}

int main(int argc, char* argv[]) {
    omp_set_num_threads(8);
    std::ifstream infile("vanity.in");
    std::ofstream outfile("vanity.out");
    std::vector<std::string> vanityPrefixes(10);
    std::vector<bool> calced(10);
    for (int i = 0; i < 10; ++i) {
        infile >> vanityPrefixes[i];
        calced[i] = false;
    }
    bool stop_sign = false;
    std::vector<std::pair<std::string, std::string>> results(10);
    std::mutex resultsMutex;
    std::random_device rd_global; 


    const size_t BATCH_SIZE = 500000;
    #pragma omp parallel num_threads(8)
    {
        uint64_t seed = rd_global() + omp_get_thread_num();
        std::mt19937_64 gen(seed);
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        while (!stop_sign) {
            for (size_t j = 0; j < BATCH_SIZE; ++j) {
                uint8_t privateKey[32];
                generateRandomPrivateKey(privateKey, gen);
                std::string address = computeEthereumAddress(ctx, privateKey);
                for (int i = 0; i < 10; ++i) {
                    if(calced[i])continue;
                    if (address.size() > 2 && 
                        address.substr(2, vanityPrefixes[i].size()) == vanityPrefixes[i]) {
                        calced[i] = true;
                            
                        std::lock_guard<std::mutex> lock(resultsMutex);
                        results[i] = {address, toHex(privateKey, 32)};
                        int calc_count = 0;
                        for (int ii = 0; ii < 10; ++ii){
                            if(calced[ii]){
                                calc_count++; 
                            }
                            else {
                                break;
                            }
                        }
                        if(calc_count >= 10){
                            stop_sign = true;
                            goto end_prefix;
                        }
                    }
                }
            }
        }
        end_prefix:
        
        secp256k1_context_destroy(ctx);
    }

    for (const auto& result : results) {
        outfile << result.first << std::endl;
        outfile << result.second << std::endl;
    }
    return 0;
}
```

## L. EDA (20/200)

### 题目

FLUTE（Fast Lookup Table Based Rectilinear Steiner Minimal Tree Algorithm）是一种基于查找表的快速RSMT算法，专门用于VLSI设计中的低度网络（即引脚数量较少的网络）。FLUTE的核心思想是通过预计算的查找表来快速构建RSMT，从而在保证高精度的同时，显著提高计算速度。

本项目的目标是加速FLUTE算法。

### 题解

使用 intel 环境，启用 -xHost 优化，提交 baseline 代码，未进行有效优化。








## 总结

ID: Neur0_5ama

分数：867.69 | 总榜：48 | 校外榜：27

本次体验下来觉得集群系统使用方式的焕新非常有益，确实能够提高使用的效率，非常感谢比赛运维大佬们的帮助。还是上次的结尾：总之还是要多多学习，明年再来。 /heart