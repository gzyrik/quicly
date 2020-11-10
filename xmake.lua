add_linkdirs("openssl/lib")
includes("examples")
target("quic")
  set_kind("static")
  add_files("lib/frame.c", "lib/cc-reno.c", "lib/defaults.c", "lib/quicly.c", "lib/ranges.c",
            "lib/recvstate.c", "lib/sendstate.c", "lib/sentmap.c", "lib/streambuf.c")
  add_defines("PICOTLS_USE_OPENSSL=1")
  add_files("deps/picotls.c", "deps/pembase64.c", "deps/openssl.c")
  add_files("quic.c")
  add_includedirs("include", "deps")
  if is_plat("windows") then
      add_files("deps/wintimeofday.c")
  end
  add_includedirs(".", {public=true})
  add_includedirs("openssl/include")
