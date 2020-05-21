set(CHELPER_SOURCES
	abort.c
	mem.c
	string_utils.c
)

add_library(CHelper STATIC ${CHELPER_SOURCES})

set_target_properties(CHelper PROPERTIES OUTPUT_NAME chelper)
