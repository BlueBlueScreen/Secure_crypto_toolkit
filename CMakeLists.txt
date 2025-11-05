#设置cmake的版本和项目名
cmake_minimum_required(VERSION 3.22)

#指定cpp的版本
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

enable_testing() #在此处允许测试
#set(CMAKE_BUILD_TYPE Release) 开启全局优化等级



#指定子目录-先库->测试->性能测评
add_subdirectory(src)
add_subdirectory(tests)
# add_subdirectory(benchmarks)
