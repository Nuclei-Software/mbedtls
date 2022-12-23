TARGET = rsa8192_demo

NUCLEI_SDK_ROOT ?= ../../../..

MIDDLEWARE := mbedtls

SRCDIRS = .

INCDIRS = .

# Use application defined mbedtls configuration file
# see mbedtls/configs/README.txt
COMMON_FLAGS := -O2 -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\"

include $(NUCLEI_SDK_ROOT)/Build/Makefile.base
