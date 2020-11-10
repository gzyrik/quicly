target("echo")
  add_deps("quic")
  set_kind("binary")
  add_files("echo2.c")
  if is_plat("windows") then
      add_includedirs("getopt")
      add_files("getopt/getopt.c")
      add_syslinks("ws2_32", "winmm")
  end

