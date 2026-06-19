if(CONFIG_MORE_ERGO_STATUS_LED)
  zephyr_library()
  zephyr_library_sources(src/status_led.c)
endif()