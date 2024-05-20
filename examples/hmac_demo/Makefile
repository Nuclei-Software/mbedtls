TARGET = hmac_demo

# NOTE:
#
# This need to work with HSM solution

CORE ?= nx900fd

NUCLEI_SDK_ROOT ?= ../../../..

MIDDLEWARE := mbedtls

# newlib_full is required due to print long long is needed in this example
STDCLIB ?= newlib_full

# Choose mbedtls accelerator
# scalar_k/vector_k/xlcrypto
# when scalar_k or vector_k is selected,
# ARCH_EXT will default provide a required arch controlled by mbedtls/build.mk
# If you want to override it, you need to pass extra arch ext list below
# scalar k require ARCH_EXT ?= _zba_zbb_zbc_zbs_zk_zks
# vector k require ARCH_EXT ?= _zve64x_zvbb_zvbc_zvkg_zvkned_zvknhb_zvksed_zvksh
#
# NOTE: this example only works with xlcrypto
MBEDTLS_ACC ?= xlcrypto

SRCDIRS = .

INCDIRS = .

# Use application defined mbedtls configuration file
# see mbedtls/configs/README.txt
COMMON_FLAGS := -O2
COMMON_FLAGS += -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\"

include $(NUCLEI_SDK_ROOT)/Build/Makefile.base
