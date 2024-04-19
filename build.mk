MBEDTLS_ROOT=$(NUCLEI_SDK_MIDDLEWARE)/mbedtls

MBEDTLS_ACC ?=
ifneq ($(MBEDTLS_ACC),)
COMMON_FLAGS += -DMBEDTLS_ACC -DMBEDTLS_ACC_$(call uc, $(MBEDTLS_ACC))
endif

C_SRCDIRS += $(MBEDTLS_ROOT)/library \
		$(MBEDTLS_ROOT)/tests/src

ifeq ($(MBEDTLS_ACC),xlcrypto)
C_SRCDIRS += $(MBEDTLS_ROOT)/accelerator/xlcrypto
INCDIRS += $(MBEDTLS_ROOT)/accelerator/xlcrypto
endif

ifeq ($(MBEDTLS_ACC),scalar_k)
C_SRCDIRS += $(MBEDTLS_ROOT)/accelerator/scalar_k
INCDIRS += $(MBEDTLS_ROOT)/accelerator/scalar_k
ifneq ($(findstring x, $(CORE)),)
C_SRCDIRS += $(MBEDTLS_ROOT)/accelerator/scalar_k/zscrypto_rv64
ASM_SRCDIRS += $(MBEDTLS_ROOT)/accelerator/scalar_k/zscrypto_rv64
else
C_SRCDIRS += $(MBEDTLS_ROOT)/accelerator/scalar_k/zscrypto_rv32
ASM_SRCDIRS += $(MBEDTLS_ROOT)/accelerator/scalar_k/zscrypto_rv32
endif
endif

ifeq ($(MBEDTLS_ACC),vector_k)
C_SRCDIRS += $(MBEDTLS_ROOT)/accelerator/vector_k
ASM_SRCDIRS += $(MBEDTLS_ROOT)/accelerator/vector_k
INCDIRS += $(MBEDTLS_ROOT)/accelerator/vector_k
endif
INCDIRS += $(MBEDTLS_ROOT)/include $(MBEDTLS_ROOT)/library $(MBEDTLS_ROOT)/tests/include
EXCLUDE_SRCS += $(MBEDTLS_ROOT)/library/entropy*.c $(MBEDTLS_ROOT)/library/timing.c $(MBEDTLS_ROOT)/library/net_sockets.c $(MBEDTLS_ROOT)/library/x509_crt.c
