cmake_minimum_required(VERSION 3.16)

project(SecureCryptoToolkit
    VERSION 1.0
    DESCRIPTION "A minimal, safe-by-default C++17 wrapper over OpenSSL 3.0+ crypto primitives"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 未显式指定时使用 Release（优化开启，也更适合 benchmark）
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# 打开常见警告（GCC / Clang）
add_compile_options($<$<CXX_COMPILER_ID:GNU,Clang>:-Wall>
                    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wextra>)

enable_testing()

add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(benchmarks)
