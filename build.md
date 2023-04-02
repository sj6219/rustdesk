# aarch64-pc-windows-msvc

## Install rustdesk

Install rustdesk-1.2.0-aarch64-pc-windows-msvc-sciter-install.exe
 at https://github.com/sj6219/rustdesk/releases/tag/alpha/ 

## Build rustdesk

Install visual studio 2022 and add the following components.

  - MSVC v143 - VS 2022 c++ ARM64 build tools(Latest)

Install LLVM and Strawberry Perl and add them to the environment variable path.


Perform the following:

%VCPKG_ROOT%\vcpkg install libvpx:arm64-windows-static libyuv:arm64-windows-static opus:arm64-windows-static

%comspec% /k "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsamd64_arm64.bat" 

cargo update

cargo build --release --target=aarch64-pc-windows-msvc 

## sciter.dll

Download from https://github.com/c-smile/sciter-sdk/blob/master/bin.win/arm64/sciter.dll.

## Build libsodium.lib

Build StaticRelease version at https://github.com/sj6219/libsodium/blob/1.0.18_alpha/builds/msvc/vs2022/libsodium.sln

---

# aarch64-apple-darwin

## Install rustdesk

Install RustDesk.dmg at https://github.com/sj6219/rustdesk/releases/tag/alpha/ 

## Build rustdesk

Perform the following:

$VCPKG_ROOT/vcpkg install libvpx:arm64-osx libyuv:arm64-osx opus:arm64-osx

cargo update

cargo build --release --target=aarch64-apple-darwin 

## libsciter.dylib

Download from https://github.com/c-smile/sciter-sdk/blob/master/bin.osx/libsciter.dylib .

