{
  "targets": [
    {
      "target_name": "native",
      "sources": [
        "binding.cc"
      ],
      "ldflags": [
        #"-Wl,-z,defs",
      ],
      "libraries": [
        "-lsodium",
        "-lself_olm",
        "-lself_omemo"
      ],
      "cflags!": [
        "-fno-exceptions"
      ],
      "cflags_cc!": ["-fno-exceptions"],
      "defines": ["NAPI_CPP_EXCEPTIONS"]
    }
  ]
}
