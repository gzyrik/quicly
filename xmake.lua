add_linkdirs("openssl/lib")
includes("examples")
target("quic")
  set_kind("static")
  add_files("lib/frame.c", "lib/cc-reno.c", "lib/defaults.c", "lib/quicly.c", "lib/ranges.c",
            "lib/recvstate.c", "lib/sendstate.c", "lib/sentmap.c", "lib/streambuf.c")
  add_defines("PICOTLS_USE_OPENSSL=1")
  add_files("deps/picotls.c", "deps/pembase64.c", "deps/openssl.c")
  add_files("quic.c")
  add_includedirs("include", "deps", "openssl/include")
  add_includedirs(".", {public=true})
  if is_plat("windows") then
      add_files("deps/wintimeofday.c")
      add_shflags("/def:quicvs/quic.def")
  else
      add_links("ssl", "crypto", {public = true})
  end
