MBEDTLS_ROOT=$(NUCLEI_SDK_MIDDLEWARE)/mbedtls

MBEDTLS_ACC ?=
ifneq ($(MBEDTLS_ACC),)
COMMON_FLAGS += -DMBEDTLS_ACC -DMBEDTLS_ACC_$(call uc, $(MBEDTLS_ACC))
endif

C_SRCDIRS += $(MBEDTLS_ROOT)/library \
		$(MBEDTLS_ROOT)/tests/src

ifeq ($(MBEDTLS_ACC),xlcrypto)
C_SRCDIRS += $(MBEDTLS_ROOT)/accelerator/xlcrypto
endif

INCDIRS += $(MBEDTLS_ROOT)/include $(MBEDTLS_ROOT)/library $(MBEDTLS_ROOT)/tests/include

ifeq ($(MBEDTLS_ACC),xlcrypto)
INCDIRS += $(MBEDTLS_ROOT)/accelerator/xlcrypto
endif

EXCLUDE_SRCS += $(MBEDTLS_ROOT)/library/entropy*.c $(MBEDTLS_ROOT)/library/timing.c $(MBEDTLS_ROOT)/library/net_sockets.c $(MBEDTLS_ROOT)/library/x509_crt.c
