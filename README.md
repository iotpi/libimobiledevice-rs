## Build libimobiledevice libraries

### Preparation
I prefer installing these libraries inside a designate directory for development, such as `/home/your_username/dev/backupstack`

```shell
mkdir -p /home/your_username/dev/backupstack/local/{bin,lib/pkgconfig}
cd /home/your_username/dev/backupstack
cat > env.sh <<EOF
export LD_LIBRARY_PATH=/home/your_username/dev/backupstack/local/lib
export PKG_CONFIG_PATH=/home/your_username/dev/backupstack/local/lib/pkgconfig
export PATH=/home/your_username/dev/backupstack/local/bin:\$PATH
EOF
source env.sh
```

The revision was the latest commit as time of writing.

[libplist](https://github.com/libimobiledevice/libplist) (db93bae96d64140230ad050061632531644c46ad)

```shell
git clone https://github.com/libimobiledevice/libplist.git
cd libplist
./configure --prefix=`dirname $PWD`/local --without-cython
make -j`nproc` && make install
```

[libimobiledevice-glue](https://github.com/libimobiledevice/libimobiledevice-glue) (d2ff7969dcd0a12e4f18f63dab03e6cd03054fcb)
```shell
git clone https://github.com/libimobiledevice/libimobiledevice-glue.git
./autogen --prefix=`dirname $PWD/local`
make -j`nproc` && make install
```

[libimobiledevice](https://github.com/libimobiledevice/libimobiledevice) (93c25b7846179c397a5316fb4fecb31ceff0ec2f)

```shell
git clone https://github.com/libimobiledevice/libimobiledevice.git
cd libmobiledevice
./configure --prefix=`dirname $PWD`/local --without-cython
make -j`nproc` && make install
```

### Build

```shell
# remember source env.sh
git clone https://github.com/iotpi/libimobiledevice-rs.git
cd libimobiledevice-rs
cargo build
```
