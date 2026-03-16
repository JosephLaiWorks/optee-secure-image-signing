project (optee_save_pic C)

set (SRC 
	host/main.c
	host/verify_signature.c)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include
			   PRIVATE /optee/out-br/host/aarch64-buildroot-linux-gnu/sysroot/usr/include
			   PRIVATE /optee/out-br/host/aarch64-buildroot-linux-gnu/sysroot/usr/include/openssl)

target_link_directories(${PROJECT_NAME} PRIVATE
    /optee/out-br/host/aarch64-buildroot-linux-gnu/sysroot/usr/lib
)

target_link_libraries (${PROJECT_NAME} PRIVATE teec crypto)


install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
