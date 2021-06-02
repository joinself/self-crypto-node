{
  "targets": [
    {
      "target_name": "native",
      "sources": [
        "binding.cc"
      ],
      "ldflags": [
      ],
      "cflags!": [
        "-fno-exceptions"
      ],
      "cflags_cc!": ["-fno-exceptions"],
      "defines": ["NAPI_CPP_EXCEPTIONS"],
      "conditions": [
        [
          "OS=='linux'",
          {
            "link_settings": {
              "libraries": [
                "-lsodium",
                "-lself_olm",
                "-lself_omemo"
              ],
              "include_dirs": [
                "<!(node -p \"require('node-addon-api').include_dir\")"
              ]
            }
          }
        ],
        [
          "OS=='mac'",
          {
            "link_settings": {
              "libraries": [
                "-lsodium",
                "-lself_olm",
                "-lself_omemo"
              ],
              "include_dirs": [
                "<!(node -p \"require('node-addon-api').include_dir\")"
              ]
            }
          }
        ],
        [
          "OS=='win'",
          {
            "link_settings": {
              "libraries": [
                "../libraries/sodium.lib",
                "../libraries/self_olm.lib",
                "../libraries/self_omemo.lib",
                "-lws2_32.lib",
                "-luserenv.lib"
              ],
              "include_dirs": [
                "<!(node -p \"require('node-addon-api').include_dir\")",
                "includes"
              ]
            }
          }
        ]
      ]
    }
  ]
}
