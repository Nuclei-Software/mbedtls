# MbedTLS Accelerator Using Nuclei Hardware

We provided different optimized accelerator implemention for MbedTLS for Nuclei Hardware.

- **scalar_k**: Optimized for RISC-V Scalar K extension, which is supported by Nuclei RISC-V CPU IP.
- **scalar_k**: Optimized for RISC-V Vector K extension, which is supported by Nuclei RISC-V CPU IP, required at least `Zve64x` together with Vector K extension.
- **xlcrypto**: Optimized for Nuclei Crypto Engine IP, which can be used with Nuclei RISC-V CPU IP.

For how to use the accelerated implementation, you can do this like this in your application Makefile of Nuclei SDK:

~~~makefile
# Choose mbedtls component
MIDDLEWARE := mbedtls

# Choose mbedtls accelerator
# scalar_k/vector_k/xlcrypto
# when scalar_k or vector_k is selected,
# ARCH_EXT will default provide a required arch controlled by mbedtls/build.mk
# If you want to override it, you need to pass extra arch ext list below
# scalar k require ARCH_EXT ?= _zba_zbb_zbc_zbs_zk_zks
# vector k require ARCH_EXT ?= _zve64x_zvbb_zvbc_zvkg_zvkned_zvknhb_zvksed_zvksh
MBEDTLS_ACC ?= scalar_k
~~~

We provided some examples for you to get started with MbedTLS optimized for Nuclei Hardware, see **<mbedtls>/examples** folder.

> **NOTE** only **benchmark** and **selftest** examples works for different accelator implementation.
>
> For detailed usage, please refer to each example's README.md
