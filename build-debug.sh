mkdir -p build/debug
(cd build/debug && cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl ../..)
cmake --build build/debug
