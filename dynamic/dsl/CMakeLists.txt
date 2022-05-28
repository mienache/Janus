set(DSL_SRCS
	dsl_core.cpp
	dsl_debug_utilities.cpp
	dsl_error_insertion.cpp
	dsl_handler.cpp
	dsl_ipc.cpp
	dsl_thread_manager.cpp
	func.cpp
        util.cpp
)

set_source_files_properties(${DSL_SRCS} PROPERTIES COMPILE_FLAGS "-std=c++11 -O3")

#add_library(janus SHARED ${DSL_SRCS} ${JANUS_API_SRCS})
add_library(jdsl SHARED ${DSL_SRCS} ${JANUS_API_SRCS})


target_link_libraries(jpar)

#Link to dynamoRIO client
configure_DynamoRIO_client(jdsl)
use_DynamoRIO_extension(jdsl drcontainers)
