{
    "targets": [
        {
            "target_name": "w32appcontainertokens",
            "msvs_configuration_attributes": {"SpectreMitigation": "Spectre"},
            "msvs_settings": {
                "VCCLCompilerTool": {
                    "AdditionalOptions": [
                        "/guard:cf",
                        "/sdl",
                        "/w34244",
                        "/we4267",
                        "/ZH:SHA_256",
                    ],
                },
                "VCLinkerTool": {"AdditionalOptions": ["/guard:cf"]},
            },
            "dependencies": [
                "<!(node -p \"require('node-addon-api').targets\"):node_addon_api_except"
            ],
            "sources": ["src/native.cpp"],
            "include_dirs": ["<!@(node -p \"require('node-addon-api').include_dir\")"],
            "libraries": [],
            "defines": ["NODE_API_SWALLOW_UNTHROWABLE_EXCEPTIONS"],
        }
    ]
}
