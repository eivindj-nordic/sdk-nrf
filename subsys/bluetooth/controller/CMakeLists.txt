#
# Copyright (c) 2018 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

zephyr_library()

zephyr_library_sources(
  hci_driver.c
  hci_internal.c
  hci_internal_wrappers.c
)

zephyr_library_sources_ifdef(
  CONFIG_BT_CTLR_CRYPTO
  crypto.c
)

zephyr_library_sources_ifdef(
  CONFIG_BT_CTLR_SDC_CS_MULTIPLE_ANTENNA_SUPPORT
  cs_antenna_switch.c
)

zephyr_library_link_libraries(subsys__bluetooth)

zephyr_include_directories(.)

function(nrfxlib_sdc_option_true name option)
  if(${option})
    set(${name} ON PARENT_SCOPE)
  else()
    set(${name} OFF PARENT_SCOPE)
  endif()
endfunction()

if(${CONFIG_BT_LL_SOFTDEVICE})
  nrfxlib_sdc_option_true(NRFXLIB_SDC_ENABLED CONFIG_BT_LL_SOFTDEVICE)
  nrfxlib_sdc_option_true(NRFXLIB_SDC_BUILD_TYPE_LIB CONFIG_BT_LL_SOFTDEVICE_BUILD_TYPE_LIB)
  nrfxlib_sdc_option_true(NRFXLIB_SDC_HEADERS_INCLUDE CONFIG_BT_LL_SOFTDEVICE_HEADERS_INCLUDE)
  nrfxlib_sdc_option_true(NRFXLIB_SDC_HEADERS_INCLUDE_PATH_OVERRIDE
    CONFIG_BT_LL_SOFTDEVICE_HEADERS_INCLUDE_PATH_OVERRIDE)

  if(CONFIG_BT_LL_SOFTDEVICE_PERIPHERAL)
    set(NRFXLIB_SDC_VARIANT peripheral)
  elseif(CONFIG_BT_LL_SOFTDEVICE_CENTRAL)
    set(NRFXLIB_SDC_VARIANT central)
  elseif(CONFIG_BT_LL_SOFTDEVICE_MULTIROLE)
    set(NRFXLIB_SDC_VARIANT multirole)
  endif()

  set(NRFXLIB_SDC_LIB_DIR ${CONFIG_BT_LL_SOC_DIR})
  set(NRFXLIB_SDC_FLOAT_ABI_DIR ${CONFIG_BT_LL_LIB_FLOAT_ABI_DIR})

  set(SDC_DIR "${ZEPHYR_NRFXLIB_MODULE_DIR}/softdevice_controller")

  add_subdirectory(${SDC_DIR} ${CMAKE_BINARY_DIR}/softdevice_controller)

  if(NOT TARGET softdevice_controller)
    message(FATAL_ERROR
      "SoftDevice Controller target was not created. "
      "Check variant and SDC_LIB_DIR / SDC_LIB_FLOAT_ABI_DIR settings.")
  endif()

  zephyr_link_libraries(softdevice_controller)
endif()
