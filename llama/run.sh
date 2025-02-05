docker run --gpus all --runtime nvidia \
    -it \
    -v ~/.cache/huggingface/hub/gguf/DeepSeek-R1-Distill-Llama-70B-Q4_K_M.gguf:/models/model.gguf \
    -p 8080:8080 \
    llama-gpu \
    ./build/bin/llama-server \
    -m /models/model.gguf \
    -ngl 80 -sm layer -c 8192
