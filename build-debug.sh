mkdir -p build/debug
export LDFLAGS="-L/usr/local/opt/llvm/lib -L/usr/local/opt/openssl/lib -L/usr/local/opt/gpgme/lib"
export CPPFLAGS="-I/usr/local/opt/openssl/include -I/usr/local/opt/gpgme/include"
export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"
(cd build/debug && cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl ../..)
cmake --build build/debug
