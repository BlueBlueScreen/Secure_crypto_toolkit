add_executable(bench bench.cpp)

target_link_libraries(bench PRIVATE secure_crypto_toolkit)

# 基准测试需要优化；库本身在 Release 下也已带 -O
target_compile_options(bench PRIVATE $<$<CONFIG:Debug>:-O2>)
