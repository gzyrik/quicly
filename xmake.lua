add_linkdirs("openssl/lib")
includes("examples")
target("quic")
  set_kind("static")
  add_files("lib/frame.c", "lib/cc-reno.c", "lib/defaults.c", "lib/quicly.c", "lib/ranges.c",
            "lib/recvstate.c", "lib/sendstate.c", "lib/sentmap.c", "lib/streambuf.c")
  add_defines("PICOTLS_USE_OPENSSL=1")
  add_files("deps/picotls/lib/picotls.c", "deps/picotls/lib/pembase64.c", "deps/picotls/lib/openssl.c")
  add_files("quic.c")
  add_includedirs("include", "deps/klib", "deps/picotls/include")
  if is_plat("windows") then
      add_files("deps/picotls/picotlsvs/picotls/wintimeofday.c")
  end
  add_includedirs(path.absolute("."), {public=true})
  add_includedirs("openssl/include")
