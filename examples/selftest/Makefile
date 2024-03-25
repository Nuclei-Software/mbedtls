TARGET = selftest

CORE ?= nx900fd
#ARCH_EXT ?= _zba_zbb_zbc_zbs_zk_zks
#ARCH_EXT ?= v_zvbb_zvbc_zvkg_zvkned_zvknhb_zvksed_zvksh

NUCLEI_SDK_ROOT ?= ../../../..

MIDDLEWARE := mbedtls

SRCDIRS = .

INCDIRS = .

ifneq ($(findstring zk, $(ARCH_EXT)),)
MBEDTLS_ACC=scalar_k
CFLAGS += -D__ZSCRYPTO -DRVINTRIN_EMULATE=1
endif

ifneq ($(findstring zvk, $(ARCH_EXT)),)
MBEDTLS_ACC=vector_k
endif

# Use application defined mbedtls configuration file
# see mbedtls/configs/README.txt
COMMON_FLAGS := -O2 -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\"

include $(NUCLEI_SDK_ROOT)/Build/Makefile.base
