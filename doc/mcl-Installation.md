# mcl Installation

## Installation on Linux or Macos
mcl is a library for pairing-based cryptography.

```shell
git clone https://github.com/herumi/mcl.git
cd mcl
mkdir build && cd build
#build mcl without GMP support
cmake .. -DMCL_USE_GMP=OFF 
make
sudo make install
```