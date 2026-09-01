cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake"
        CACHE PATH "Vita toolchain")
  else()
    message(FATAL_ERROR "Defina VITASDK antes de configurar o projeto.")
  endif()
endif()

project(tsvita_moonlight_adapter C)
include("$ENV{VITASDK}/share/vita.cmake" REQUIRED)

get_filename_component(TSVITA_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
file(STRINGS "${TSVITA_ROOT}/VERSION" TSVITA_RUNTIME_VERSION LIMIT_COUNT 1)
if(NOT TSVITA_RUNTIME_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+(-dev)?$")
  message(FATAL_ERROR "VERSION invalida: ${TSVITA_RUNTIME_VERSION}")
endif()
set(TSVITA_SFO_VERSION "00.20")
set(MOONLIGHT_UPSTREAM "${TSVITA_ROOT}/.deps/vita-moonlight")
set(WIREGUARD_LWIP_DIR "${TSVITA_ROOT}/.deps/wireguard-lwip")
set(LWIP_DIR "${TSVITA_ROOT}/.deps/lwip")

if(NOT EXISTS "${MOONLIGHT_UPSTREAM}/src/main.c" OR
   NOT EXISTS "${WIREGUARD_LWIP_DIR}/src/wireguard.c" OR
   NOT EXISTS "${LWIP_DIR}/src/api/sockets.c")
  message(FATAL_ERROR "Execute scripts/build-moonlight.sh para obter dependencias.")
endif()

set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELEASE
    "-O2 -DNDEBUG -D_GNU_SOURCE -Wno-implicit-function-declaration -Wno-int-conversion -Wno-incompatible-pointer-types"
    CACHE STRING "" FORCE)
set(CMAKE_C_STANDARD_LIBRARIES "-lzstd" CACHE STRING "" FORCE)

add_subdirectory("${MOONLIGHT_UPSTREAM}" upstream EXCLUDE_FROM_ALL)
include("${LWIP_DIR}/src/Filelists.cmake")

target_sources(moonlight.elf PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/tunnel.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/tunnel_runtime.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/peer_config.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/openssl_compat.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/socket_shim.c"
  "${TSVITA_ROOT}/src/ipv4_literal.c"
  "${TSVITA_ROOT}/src/replay_window.c"
  "${TSVITA_ROOT}/src/wireguard_platform_vita.c"
  "${WIREGUARD_LWIP_DIR}/src/wireguard.c"
  "${WIREGUARD_LWIP_DIR}/src/crypto.c"
  "${WIREGUARD_LWIP_DIR}/src/crypto/refc/blake2s.c"
  "${WIREGUARD_LWIP_DIR}/src/crypto/refc/chacha20.c"
  "${WIREGUARD_LWIP_DIR}/src/crypto/refc/chacha20poly1305.c"
  "${WIREGUARD_LWIP_DIR}/src/crypto/refc/poly1305-donna.c"
  "${WIREGUARD_LWIP_DIR}/src/crypto/refc/x25519.c"
  "${LWIP_DIR}/contrib/ports/unix/port/sys_arch.c"
  ${lwipcore_SRCS}
  ${lwipcore4_SRCS}
  ${lwipapi_SRCS}
)

target_include_directories(moonlight.elf PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/lwip"
  "${LWIP_DIR}/src/include"
  "${LWIP_DIR}/contrib/ports/unix/port/include"
  "${WIREGUARD_LWIP_DIR}/src"
  "${TSVITA_ROOT}/src"
)

target_compile_definitions(moonlight.elf PRIVATE
  TSVITA_LWIP_SYS_NOW_PROVIDED=1
  TSVITA_VERSION="${TSVITA_RUNTIME_VERSION}"
)

target_link_libraries(moonlight.elf
  SceIofilemgr_stub
  SceLibKernel_stub
  zstd
)

set(TSVITA_WRAPPED_FUNCTIONS
  socket connect bind listen accept send recv sendto recvfrom shutdown close
  read write fcntl setsockopt getsockopt getsockname getpeername poll select
  getaddrinfo freeaddrinfo
)
foreach(function_name IN LISTS TSVITA_WRAPPED_FUNCTIONS)
  target_link_options(moonlight.elf PRIVATE
    "-Wl,--wrap=${function_name}"
  )
endforeach()

set(TSVITA_MOONLIGHT_VELF
    "${CMAKE_CURRENT_BINARY_DIR}/moonlight-tailscale.velf")
set(TSVITA_MOONLIGHT_EBOOT
    "${CMAKE_CURRENT_BINARY_DIR}/moonlight-tailscale-eboot.bin")
set(TSVITA_MOONLIGHT_SFO
    "${CMAKE_CURRENT_BINARY_DIR}/moonlight-tailscale-param.sfo")
set(TSVITA_MOONLIGHT_VPK
    "${CMAKE_CURRENT_BINARY_DIR}/Moonlight-Tailscale-Vita-v${TSVITA_RUNTIME_VERSION}.vpk")

add_custom_command(
  OUTPUT "${TSVITA_MOONLIGHT_VELF}"
  COMMAND vita-elf-create $<TARGET_FILE:moonlight.elf>
          "${TSVITA_MOONLIGHT_VELF}"
  DEPENDS moonlight.elf
  VERBATIM
)

add_custom_command(
  OUTPUT "${TSVITA_MOONLIGHT_EBOOT}"
  COMMAND vita-make-fself -a 0x2800000000000001 -at 0x0E -c
          "${TSVITA_MOONLIGHT_VELF}" "${TSVITA_MOONLIGHT_EBOOT}"
  DEPENDS "${TSVITA_MOONLIGHT_VELF}"
  VERBATIM
)

add_custom_command(
  OUTPUT "${TSVITA_MOONLIGHT_SFO}"
  COMMAND vita-mksfoex -s TITLE_ID=TSVITAML1 -s APP_VER=${TSVITA_SFO_VERSION}
          "Moonlight Tailscale" "${TSVITA_MOONLIGHT_SFO}"
  VERBATIM
)

add_custom_command(
  OUTPUT "${TSVITA_MOONLIGHT_VPK}"
  COMMAND vita-pack-vpk -s "${TSVITA_MOONLIGHT_SFO}"
          -b "${TSVITA_MOONLIGHT_EBOOT}"
          --add "${MOONLIGHT_UPSTREAM}/sce_sys/icon0.png=sce_sys/icon0.png"
          --add "${MOONLIGHT_UPSTREAM}/sce_sys/livearea/contents/bg.png=sce_sys/livearea/contents/bg.png"
          --add "${MOONLIGHT_UPSTREAM}/sce_sys/livearea/contents/startup.png=sce_sys/livearea/contents/startup.png"
          --add "${MOONLIGHT_UPSTREAM}/sce_sys/livearea/contents/template.xml=sce_sys/livearea/contents/template.xml"
          --add "${MOONLIGHT_UPSTREAM}/assets/nerdfont.ttf=assets/nerdfont.ttf"
          --add "${TSVITA_ROOT}/THIRD_PARTY_NOTICES.md=THIRD_PARTY_NOTICES.md"
          "${TSVITA_MOONLIGHT_VPK}"
  DEPENDS "${TSVITA_MOONLIGHT_EBOOT}" "${TSVITA_MOONLIGHT_SFO}"
  VERBATIM
)

add_custom_target(moonlight_tailscale_vpk ALL
  DEPENDS "${TSVITA_MOONLIGHT_VPK}"
)
