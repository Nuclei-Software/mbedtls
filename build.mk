MBEDTLS_ROOT=$(NUCLEI_SDK_MIDDLEWARE)/mbedtls

C_SRCDIRS += $(MBEDTLS_ROOT)/library \
		$(MBEDTLS_ROOT)/accelerator/xlcrypto \
		$(MBEDTLS_ROOT)/tests/src

INCDIRS += $(MBEDTLS_ROOT)/include $(MBEDTLS_ROOT)/library $(MBEDTLS_ROOT)/tests/include $(MBEDTLS_ROOT)/accelerator/xlcrypto
EXCLUDE_SRCS += $(MBEDTLS_ROOT)/library/entropy*.c $(MBEDTLS_ROOT)/library/timing.c $(MBEDTLS_ROOT)/library/net_sockets.c $(MBEDTLS_ROOT)/library/x509_crt.c
