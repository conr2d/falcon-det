cmake_minimum_required(VERSION 3.16)

project(falcon_det)

set(CMAKE_C_COMPILER "clang")
set(CMAKE_C_STANDARD 99)

add_compile_options(-Wall -Wextra -Wshadow -Wundef -O3)

add_library(falcon_det STATIC
  src/codec.c
  src/common.c
  src/deterministic.c
  src/falcon.c
  src/fft.c
  src/fpr.c
  src/keygen.c
  src/rng.c
  src/shake.c
  src/sign.c
  src/vrfy.c
)
target_include_directories(falcon_det
  PUBLIC include
  PRIVATE src
)

include(GNUInstallDirs)
install(TARGETS falcon_det
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

if(BUILD_TESTING)
  include(CTest)
  link_libraries(falcon_det)

  add_executable(test_deterministic tests/test_deterministic.c)
  add_executable(test_falcon tests/test_falcon.c)
  target_include_directories(test_falcon PRIVATE $<TARGET_PROPERTY:falcon_det,INCLUDE_DIRECTORIES>)
  add_executable(test_speed tests/speed.c)

  add_test(NAME test_deterministic COMMAND test_deterministic)
  add_test(NAME test_falcon COMMAND test_falcon)
  add_test(NAME test_speed COMMAND test_speed)
endif()
