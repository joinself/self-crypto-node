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
               "-L<(module_root_dir)/libraries/ -l:libsodium.so",
               "-L<(module_root_dir)/libraries/ -l:libself_olm.so",
               "-L<(module_root_dir)/libraries/ -l:libself_omemo.so",
            ],
            "copies": [
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/libsodium.so" ]
              },
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/libself_olm.so" ]
              },
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/libself_olm.so.3" ]
              },
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/libself_olm.so.3.1.4" ]
              },
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/libself_omemo.so" ]
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
              "-L<(module_root_dir)/libraries/ -llibsodium.dylib",
              "-L<(module_root_dir)/libraries/ -llibself_olm.dylib",
              "-L<(module_root_dir)/libraries/ -llibself_omemo.dylib",
            ],
            "copies": [
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/libsodium.dylib" ]
              },
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/libself_olm.dylib" ]
              },
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/libself_olm.3.dylib" ]
              },
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/libself_olm.3.1.4.dylib" ]
              },
              {
                "destination": "<(module_root_dir)/build/Release/",
                "files": [ "<(module_root_dir)/libraries/libself_omemo.dylib" ]
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
