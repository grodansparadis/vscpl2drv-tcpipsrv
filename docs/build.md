## Build from source on Linux

```bash
git clone --recurse-submodules -j4 https://github.com/grodansparadis/vscpl2drv-websocksrv.git
sudo apt install pandoc           (comment: *optional*)
sudo apt install build-essential
sudo apt install cmake
sudo apt install libexpat-dev
sudo apt install libssl-dev
sudo apt install rpm (comment: only if you want to create rpm install packages)
cd vscpl2drv-websocksrv
mkdir build
cd build
cmake ..
make
sudo make install
cpack .. (comment: only if you want to create install packages)
```

Install of _pandoc_ is only needed if man pages should be rebuilt. This is normally already done and available in the repository.

`make install` will install the driver to the standard location for VSCP level II drivers on Linux which is */usr/local/lib/vscp/drivers/* and copy a sample configuration file to */etc/vscp*

## Build from source on Windows

### You need a compiler

The Visual Studio Community Edition is a free IDE from Microsoft. Download and install it from [here](https://visualstudio.microsoft.com/vs/community/).

### Install Pandoc
Pandoc is used to build the man pages. Download and install it from [here](https://pandoc.org/installing.html).

### Install the vcpkg package manager

You need the vcpkg package manager on windows. Install it with

```bash
git clone https://github.com/microsoft/vcpkg.git
```

then go into the folder

```bash
cd vcpkg
```

Run the vcpkg bootstrapper command

```bash
bootstrap-vcpkg.bat
```

The process is described in detail [here](https://docs.microsoft.com/en-us/cpp/build/install-vcpkg?view=msvc-160&tabs=windows)

To [integrate with Visual Studio](https://docs.microsoft.com/en-us/cpp/build/integrate-vcpkg?view=msvc-160) run

```bash
vcpkg integrate install
```

Install the required libs

```bash
vcpkg install pthread:x64-windows
vcpkg install expat:x64-windows
vcpkg install openssl:x64-windows
vcpkg install dlfcn-win32:x64-windows
```

Full usage is describe [here](https://docs.microsoft.com/en-us/cpp/build/manage-libraries-with-vcpkg?view=msvc-160&tabs=windows)

### Get the source for the driver

```bash
git clone --recursive https://github.com/grodansparadis/vscpl2drv-websocksrv.git
```

### Build the driver

Build as usual but use

```bash
cd vscpl2drv-websocksrv
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DVCPKG_ROOT=G:/vcpkg/ -DCMAKE_TOOLCHAIN_FILE=G:/vcpkg/scripts/buildsystems/vcpkg.cmake -G "Visual Studio 17 2022" -A x64
```

The **CMAKE_TOOLCHAIN_FILE** path may be different in your case

Note that *Release|Debug* should be either `Release` or `Debug`

The windows build files can now be found in the build folder and all needed files to run the project can  after build - be found in build/release or build/Debug depending on CMAKE_BUILD_TYPE setting.

Building and configuration is simplified with VS Code installed. Configure/build/run can be done (se lower toolbar). Using VS Code it may be useful to add

```json
"cmake.configureSettings": {
   "CMAKE_BUILD_TYPE": "${buildType}"
}
``` 

to your `settings.json` file.

To build at the command prompt use

```bash
cmake --build . --config Release
```

Note that you must have a *developer command prompt*

### Build deploy packages 

Install NSIS from [this site](https://sourceforge.net/projects/nsis/).

Run 

```bash
cpack ..
```
 
in the build folder.

## How to build the driver from source on MacOS
t.b.d.

[filename](./bottom-copyright.md ':include')