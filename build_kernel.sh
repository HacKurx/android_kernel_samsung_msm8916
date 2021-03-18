#!/bin/bash

export ARCH=arm
export CROSS_COMPILE=/home/xxx/toolchain/gcc-linaro-7.5.0-2019.12-x86_64_arm-eabi/bin/arm-eabi-
export CORES=$(nproc)

mkdir output

make -j$CORES -C $(pwd) O=output VARIANT_DEFCONFIG=msm8916_sec_gtelwifi_usa_defconfig msm8916_sec_defconfig SELINUX_DEFCONFIG=selinux_defconfig
make -C $(pwd) O=output

cp output/arch/arm/boot/Image $(pwd)/arch/arm/boot/zImage
