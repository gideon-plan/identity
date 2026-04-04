import std/os

switch("path", "src")
switch("threads", "on")
switch("outdir", ".out")

let httpffi = thisDir() & "/../httpffi"
let ffi = httpffi & "/src/httpffi/ffi"
let libresslDir = getEnv("HOME") & "/.local/opt/libressl"
switch("passC", "-I" & ffi & "/curl/include")
switch("passC", "-I" & libresslDir & "/include")
switch("passL", ffi & "/curl/build/lib/libcurl.a")
switch("passL", libresslDir & "/lib/libssl.a")
switch("passL", libresslDir & "/lib/libcrypto.a")
switch("passL", "-lz -lbrotlidec -lzstd -lpsl -lidn2 -lssh2 -lnghttp2 -lpthread")

when file_exists("nimble.paths"):
  include "nimble.paths"
# begin Nimble config (version 2)
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config
