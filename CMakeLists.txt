cmake_minimum_required(VERSION 3.13...3.27)

include(vendor/pico_sdk_import.cmake)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

project(pico-ble-wifi-provisioning C CXX ASM)
pico_sdk_init()

add_executable(ble-wifi-provisioning main.c)
target_compile_options(ble-wifi-provisioning INTERFACE -Werror -Wall -Wextra -Wnull-dereference)
pico_btstack_make_gatt_header(ble-wifi-provisioning PRIVATE "${CMAKE_CURRENT_LIST_DIR}/wifi_provisioning.gatt")
target_include_directories(ble-wifi-provisioning PRIVATE ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(ble-wifi-provisioning
    pico_stdlib
    pico_btstack_ble
    pico_btstack_cyw43
    pico_cyw43_arch_lwip_threadsafe_background
    )

pico_enable_stdio_usb(ble-wifi-provisioning 1)
pico_add_extra_outputs(ble-wifi-provisioning)
