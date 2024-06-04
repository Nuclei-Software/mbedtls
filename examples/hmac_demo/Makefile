TARGET = hmac_demo

CORE ?= n300fd

NUCLEI_SDK_ROOT ?= ../../../..

MIDDLEWARE := mbedtls

# newlib_full is required due to print long long is needed in this example
STDCLIB ?= newlib_full

# Choose mbedtls accelerator
# NOTE: this example only works with xlcrypto
MBEDTLS_ACC ?= xlcrypto

SRCDIRS = .

INCDIRS = .

# Use application defined mbedtls configuration file
# see mbedtls/configs/README.txt
COMMON_FLAGS := -O2
COMMON_FLAGS += -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\"

include $(NUCLEI_SDK_ROOT)/Build/Makefile.base
