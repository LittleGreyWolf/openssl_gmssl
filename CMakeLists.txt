cmake_minimum_required(VERSION 3.5)
project(GMClient)

set(SRC_LIST ${PROJECT_SOURCE_DIR}/src/client.cpp)

set(SRC_LIST_SERVER ${PROJECT_SOURCE_DIR}/src/server.cpp)

include_directories(${PROJECT_SOURCE_DIR}/include)

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ldl -lm")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ldl -std=c++11 -lpthread -g")

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/output)

ADD_EXECUTABLE(GMClient ${SRC_LIST})
ADD_EXECUTABLE(GMServer ${SRC_LIST_SERVER})


TARGET_LINK_LIBRARIES(GMClient ${PROJECT_SOURCE_DIR}/lib/libssl.a ${PROJECT_SOURCE_DIR}/lib/libcrypto.a) 
TARGET_LINK_LIBRARIES(GMServer ${PROJECT_SOURCE_DIR}/lib/libssl.a ${PROJECT_SOURCE_DIR}/lib/libcrypto.a) 
