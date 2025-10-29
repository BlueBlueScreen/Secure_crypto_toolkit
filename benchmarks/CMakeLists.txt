#创建可执行文件
add_executable(Bench_mark_test
bench_aes_gcm.cpp
)

#链接库
target_link_libraries(
    Bench_mark_test
    PRIVATE
    Toolkit
    OpenSSL::Crypto
)

#开启优化等级，适用于性能测试
target_compile_options(Bench_mark_test
        PRIVATE
        $<$<CXX_COMPILER_ID:GNU:-03>
        $<$<CXX_COMPILER_ID:Clang:-03>
        $<$<CXX_COMPLIER_ID:MSVC:/02>
)   

#添加自定义命令（Custom Command)
add_custom_command(
    TARGET Bench_mark_test
    POST_BUILD
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/Bench_mark_test > bench_result.txt
    COMMENT "Running benchmark and saving output to bench_result.txt"
)