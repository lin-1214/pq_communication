add_compile_options(-Wall -Wextra -Wpedantic)
add_compile_options(-Werror)
add_compile_options(-Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith)
add_compile_options(-O3 -fwrapv)

set(UTILS_SRC utils.c)
add_library(utils STATIC ${UTILS_SRC})

set(AES256GCM_SRC aes256gcm.c)
add_library(aes256gcm STATIC ${AES256GCM_SRC})
target_link_libraries(aes256gcm PUBLIC ${OPENSSL_CRYPTO_LIBRARY})

set(INDCCA_SRC indcca.c)
add_library(indcca STATIC ${INDCCA_SRC})
target_link_libraries(indcca PUBLIC oqs ${OPENSSL_CRYPTO_LIBRARY})

set(COMITMENT_SRC commitment.c)
add_library(commitment STATIC ${INDCCA_SRC})
target_link_libraries(commitment PUBLIC indcca aes256gcm oqs ${OPENSSL_CRYPTO_LIBRARY})

set(FSXY_AKE_SRC fsxy-ake.c)
add_library(fsxy-ake STATIC ${FSXY_AKE_SRC})
target_link_libraries(fsxy-ake oqs ${OPENSSL_CRYPTO_LIBRARY} utils)

set(GAKE_SRC gake.c)
add_library(gake STATIC ${GAKE_SRC})
target_link_libraries(gake oqs fsxy-ake commitment utils)
