switch("path", "src")
switch("threads", "on")

let httpffi = thisDir() & "/../httpffi"
let ffi = httpffi & "/src/httpffi/ffi"
switch("passC", "-I" & ffi & "/curl/include")
switch("passL", ffi & "/curl/build/lib/libcurl.a")
switch("passL", "-lssl -lcrypto -lz -lbrotlidec -lzstd -lpsl -lidn2 -lssh2 -lnghttp2 -lpthread")
