FROM nvidia/cuda:12.6.3-devel-ubuntu24.04

RUN apt-get update && apt-get install -y \
    git build-essential cmake \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/ggerganov/llama.cpp
WORKDIR /llama.cpp
RUN cmake -B build -DGGML_CUDA=ON
RUN cmake --build build --config Release
