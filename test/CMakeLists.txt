SET(fw_test "${fw_name}_test")

INCLUDE(FindPkgConfig)
pkg_check_modules(${fw_test} REQUIRED glib-2.0)
FOREACH(flag ${${fw_test}_CFLAGS})
    SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -Wall -fPIE")
SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed -pie")

aux_source_directory(. sources)
FOREACH(src ${sources})
    GET_FILENAME_COMPONENT(src_name ${src} NAME_WE)
    MESSAGE("${src_name}")
    ADD_EXECUTABLE(${src_name} ${src})
    TARGET_LINK_LIBRARIES(${src_name} ${fw_name} ${${fw_test}_LDFLAGS})
ENDFOREACH()

INSTALL(TARGETS softap_test RUNTIME DESTINATION bin/)
