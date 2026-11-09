CFLAGS = -O2 -fno-common -DMBEDTLS_CONFIG_FILE='"mbedtls_aros_config.h"' -I.
LIBS = -lmbedtls -lmbedx509 -lmbedcrypto
TARGET = airscannerlite
SRCS = main.c

# AArch64 AROS mbedTLS libraries. The toolchain sysroot only ships the
# headers, so link against the installed AROS port libraries.
MBEDTLS_LIB ?= $(HOME)/piAROS/Developer/lib

all: $(TARGET)

$(TARGET): $(SRCS) mbedtls_aros_config.h
	docker run --rm \
	  -v "$$PWD":/src \
	  -v "$(HOME)/aros-toolchains":/toolchains \
	  -v "$(HOME)/aros-toolchains/crosstools-workaround-arm":/work/toolchain-aarch64 \
	  -v "$(MBEDTLS_LIB)":/opt/mbedtls/lib:ro \
	  -w /src ubuntu:24.04 \
	  /toolchains/aros-toolchain-aarch64/bin/aarch64-aros-gcc \
	  --sysroot=/toolchains/aros-toolchain-aarch64/sysroot \
	  $(SRCS) -o $(TARGET) $(CFLAGS) -L/opt/mbedtls/lib $(LIBS)

clean:
	rm -f $(TARGET)
