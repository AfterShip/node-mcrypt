{
    "targets": [
        {
            "target_name": "mcrypt",
            "sources": [
                "src/mcrypt.cc"
            ],
            "libraries": [
                "-lmcrypt"
            ],
            "include_dirs": [
                "<!(node -e \"require('nan')\")"
            ]
        }
    ]
}
