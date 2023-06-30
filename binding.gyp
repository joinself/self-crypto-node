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
            "libraries": [
              "-L<(module_root_dir)/libraries/ -l:libself_omemo.a",
            ],
            "copies": [
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/libself_omemo.a" ]
              }
            ],
            "link_settings": {
              "libraries": [ "-Wl,-rpath=\\$$ORIGIN"],
              "include_dirs": [
                "<!(node -p \"require('node-addon-api').include_dir\")",
                "includes"
              ]
            }
          }
        ],
        [
          "OS=='mac'",
          {
            "libraries": [
              "-L<(module_root_dir)/libraries/ -lself_omemo",
            ],
            "copies": [
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/libself_omemo.a" ]
              }
            ],
            "link_settings": {
              "include_dirs": [
                "<!(node -p \"require('node-addon-api').include_dir\")"
              ]
            }
          }
        ],
        [
          "OS=='win'",
          {
            "libraries": [
              "-l<(module_root_dir)/libraries/self_omemo.lib",
              "-lmincore.lib"
            ],
            "copies": [
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/self_omemo.lib" ]
              }
            ],
            "link_settings": {
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
