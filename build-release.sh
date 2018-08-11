mkdir -p build/release
(cd build/release && cmake -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl ../..)
cmake --build build/release

