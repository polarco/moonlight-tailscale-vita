cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "Vita toolchain")
  else()
    message(FATAL_ERROR "Defina VITASDK antes de configurar o projeto.")
  endif()
endif()

project(tailscale_vita_probe C)
include("$ENV{VITASDK}/share/vita.cmake" REQUIRED)

set(VITA_APP_NAME "Tailscale Vita Probe")
set(VITA_TITLEID "TSVITAPRB")
set(VITA_VERSION "00.80")

add_executable(${PROJECT_NAME}
  src/main.c
)

target_compile_features(${PROJECT_NAME} PRIVATE c_std_11)
target_compile_options(${PROJECT_NAME} PRIVATE
  -Wall
  -Wextra
  -Werror
  -O2
)
target_compile_definitions(${PROJECT_NAME} PRIVATE
  TV_PROBE_VERSION="0.8.0"
)

target_link_libraries(${PROJECT_NAME}
  vita2d
  SceAppMgr_stub
  SceCommonDialog_stub
  SceDisplay_stub
  SceGxm_stub
  SceCtrl_stub
  SceSysmodule_stub
  ScePgf_stub
  SceNet_stub
  SceNetCtl_stub
  SceIofilemgr_stub
  SceKernelModulemgr_stub
  SceSysmem_stub
  m
  c
)

vita_create_self(${PROJECT_NAME}.self ${PROJECT_NAME})
vita_create_vpk(Tailscale-Vita-Probe-v0.8.0.vpk ${VITA_TITLEID} ${PROJECT_NAME}.self
  VERSION ${VITA_VERSION}
  NAME ${VITA_APP_NAME}
)

set(WIREGUARD_LWIP_DIR "${CMAKE_SOURCE_DIR}/.deps/wireguard-lwip")
if(NOT EXISTS "${WIREGUARD_LWIP_DIR}/src/wireguard.c")
  message(FATAL_ERROR "Execute scripts/build.sh para obter wireguard-lwip.")
endif()

set(LWIP_DIR "${CMAKE_SOURCE_DIR}/.deps/lwip")
if(NOT EXISTS "${LWIP_DIR}/src/core/init.c")
  message(FATAL_ERROR "Execute scripts/build.sh para obter lwIP.")
endif()
include("${LWIP_DIR}/src/Filelists.cmake")

set(WG_CRYPTO_TARGET tailscale_vita_wg_crypto_probe)
add_executable(${WG_CRYPTO_TARGET}
  src/wg_crypto_probe.c
  src/wireguard_platform_vita.c
  ${WIREGUARD_LWIP_DIR}/src/wireguard.c
  ${WIREGUARD_LWIP_DIR}/src/crypto.c
  ${WIREGUARD_LWIP_DIR}/src/crypto/refc/blake2s.c
  ${WIREGUARD_LWIP_DIR}/src/crypto/refc/chacha20.c
  ${WIREGUARD_LWIP_DIR}/src/crypto/refc/chacha20poly1305.c
  ${WIREGUARD_LWIP_DIR}/src/crypto/refc/poly1305-donna.c
  ${WIREGUARD_LWIP_DIR}/src/crypto/refc/x25519.c
)

target_compile_features(${WG_CRYPTO_TARGET} PRIVATE c_std_11)
target_compile_options(${WG_CRYPTO_TARGET} PRIVATE
  -O2
)
set_source_files_properties(
  src/wg_crypto_probe.c
  src/wireguard_platform_vita.c
  PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra;-Werror"
)
target_include_directories(${WG_CRYPTO_TARGET} PRIVATE
  src/compat
  ${WIREGUARD_LWIP_DIR}/src
)

target_link_libraries(${WG_CRYPTO_TARGET}
  vita2d
  SceAppMgr_stub
  SceCommonDialog_stub
  SceDisplay_stub
  SceGxm_stub
  SceCtrl_stub
  SceSysmodule_stub
  ScePgf_stub
  SceIofilemgr_stub
  SceKernelModulemgr_stub
  SceSysmem_stub
  SceLibKernel_stub
  m
  c
)

vita_create_self(${WG_CRYPTO_TARGET}.self ${WG_CRYPTO_TARGET})
vita_create_vpk(Tailscale-Vita-WG-Crypto-Probe-v0.1.0.vpk TSVITAWG1
  ${WG_CRYPTO_TARGET}.self
  VERSION 00.10
  NAME "Tailscale Vita WG Crypto Probe"
  FILE "${CMAKE_SOURCE_DIR}/THIRD_PARTY_NOTICES.md" "THIRD_PARTY_NOTICES.md"
)

set(WG_HANDSHAKE_TARGET tailscale_vita_wg_handshake_probe)
add_executable(${WG_HANDSHAKE_TARGET}
  src/wg_handshake_probe.c
  src/ip_udp_packet.c
  src/ipv4_literal.c
  src/wireguard_platform_vita.c
  ${WIREGUARD_LWIP_DIR}/src/wireguard.c
  ${WIREGUARD_LWIP_DIR}/src/crypto.c
  ${WIREGUARD_LWIP_DIR}/src/crypto/refc/blake2s.c
  ${WIREGUARD_LWIP_DIR}/src/crypto/refc/chacha20.c
  ${WIREGUARD_LWIP_DIR}/src/crypto/refc/chacha20poly1305.c
  ${WIREGUARD_LWIP_DIR}/src/crypto/refc/poly1305-donna.c
  ${WIREGUARD_LWIP_DIR}/src/crypto/refc/x25519.c
  ${lwipcore_SRCS}
  ${lwipcore4_SRCS}
)

target_compile_features(${WG_HANDSHAKE_TARGET} PRIVATE c_std_11)
target_compile_options(${WG_HANDSHAKE_TARGET} PRIVATE -O2)
set_source_files_properties(
  src/wg_handshake_probe.c
  src/ip_udp_packet.c
  src/ipv4_literal.c
  PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra;-Werror"
)
target_include_directories(${WG_HANDSHAKE_TARGET} PRIVATE
  src/lwip
  ${LWIP_DIR}/src/include
  ${WIREGUARD_LWIP_DIR}/src
)

target_link_libraries(${WG_HANDSHAKE_TARGET}
  vita2d
  SceAppMgr_stub
  SceCommonDialog_stub
  SceDisplay_stub
  SceGxm_stub
  SceCtrl_stub
  SceSysmodule_stub
  ScePgf_stub
  SceNet_stub
  SceNetCtl_stub
  SceIofilemgr_stub
  SceKernelModulemgr_stub
  SceSysmem_stub
  SceLibKernel_stub
  m
  c
)

vita_create_self(${WG_HANDSHAKE_TARGET}.self ${WG_HANDSHAKE_TARGET})
vita_create_vpk(Tailscale-Vita-WG-Flow-Probe-v0.4.0.vpk TSVITAWG2
  ${WG_HANDSHAKE_TARGET}.self
  VERSION 00.40
  NAME "Tailscale Vita WG Flow Probe"
  FILE "${CMAKE_SOURCE_DIR}/THIRD_PARTY_NOTICES.md" "THIRD_PARTY_NOTICES.md"
)
