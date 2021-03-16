cmake_minimum_required(VERSION 3.4.1)

# Set directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories($ENV{JAVA_HOME}/include)
include_directories($ENV{JAVA_HOME}/include/linux)
include_directories(../../../Client/app/src/main/cpp)

link_directories(${CMAKE_SOURCE_DIR}/lib/openssl/linux_x86_64)

add_library( # Sets the name of the library.
             native-server

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             ../../../Client/app/src/main/cpp/Utils.cpp
             ../../../Client/app/src/main/cpp/SecretShare.cpp
             ../../../Client/app/src/main/cpp/KeyAgreement.cpp
             ../../../Client/app/src/main/cpp/Cipher.cpp
             ServerContext.cpp
             com_va_server_NativeServer.cpp )

target_link_libraries( # Specifies the target library.
                       native-server

                       libcrypto.a )

add_library( # Sets the name of the library.
             native-client

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             ../../../Client/app/src/main/cpp/Utils.cpp
             ../../../Client/app/src/main/cpp/HomHash.cpp
             ../../../Client/app/src/main/cpp/Commitment.cpp
             ../../../Client/app/src/main/cpp/SecretShare.cpp
             ../../../Client/app/src/main/cpp/KeyAgreement.cpp
             ../../../Client/app/src/main/cpp/Cipher.cpp
             ../../../Client/app/src/main/cpp/Context.cpp
             ../../../Client/app/src/main/cpp/com_va_client_NativeClient.cpp )

target_link_libraries( # Specifies the target library.
                       native-client

                       libcrypto.a )