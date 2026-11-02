# win-warp-generator
Rust windows version of ImMALWARE/bash-warp-generator with few changes.

You need working https connection to `api.cloudflareclient.com`

Download from release or build youself:

Powershell/cmd: 
`winget install Rustlang.Rustup`

If you want to build x32:
`rustup target add i686-pc-windows-msvc`

`cd /d E:\warp_generator` as example

simply `cargo build --release`

or

x64: `cargo build --release --target x86_64-pc-windows-msvc`

x32: `cargo build --release --target i686-pc-windows-msvc`
