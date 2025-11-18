# benchmarks/CMakeLists.txt

# 创建可执行文件
add_executable(Bench_mark_test
    bench_aes_gcm.cpp
)

# 链接库
target_link_libraries(Bench_mark_test
    PRIVATE
        Toolkit     # 确认这是你库的正确目标名
)

# 开启优化（用于性能测试）
target_compile_options(Bench_mark_test
    PRIVATE
        $<$<CXX_COMPILER_ID:GNU>:-O3>
        $<$<CXX_COMPILER_ID:Clang>:-O3>
        $<$<CXX_COMPILER_ID:MSVC>:/O2>
)