set(MKHOOK_SOURCES
	injector.c
)

add_executable(mkhook ${MKHOOK_SOURCES})

target_link_libraries(mkhook CHelper)
