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
               "-l<(module_root_dir)/libraries/sodium.so",
               "-l<(module_root_dir)/libraries/self_olm.so",
               "-l<(module_root_dir)/libraries/self_omemo.so",
            ],
            "copies": [
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/libsodium.so" ]
              },
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/self_olm.so" ]
              },
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/self_olm.so.3" ]
              },
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/self_olm.so.3.1.4" ]
              },
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/self_omemo.so" ]
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
          "OS=='mac'",
          {
            "libraries": [
              "-l<(module_root_dir)/libraries/sodium.dylib",
              "-l<(module_root_dir)/libraries/self_olm.dylib",
              "-l<(module_root_dir)/libraries/self_omemo.dylib",
            ],
            "copies": [
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/libsodium.dylib" ]
              },
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/self_olm.dylib" ]
              },
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/self_omemo.dylib" ]
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
              "-l<(module_root_dir)/libraries/sodium.lib",
              "-l<(module_root_dir)/libraries/self_olm.lib",
              "-l<(module_root_dir)/libraries/self_omemo.lib",
              "-lmincore.lib"
            ],
            "copies": [
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/libsodium.dll" ]
              },
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/self_olm.dll" ]
              },
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
