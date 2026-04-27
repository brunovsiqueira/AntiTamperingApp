cmake_minimum_required(VERSION 3.22.1)
project("antitamper_native")

add_library(antitamper_native SHARED
    art_method_check.c
)

target_link_libraries(antitamper_native
    log
)
