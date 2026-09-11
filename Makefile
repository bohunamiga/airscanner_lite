CFLAGS = -O2 -fno-common -I/Users/tomasz/aros-toolchains/aros-toolchain-aarch64/sysroot/include
LIBS = -lbearssl
TARGET = airscannerlite
SRCS = main.c

all: $(TARGET)

$(TARGET): $(SRCS)
	docker run --rm \
	  -v "$$PWD":/src \
	  -v ~/aros-toolchains:/toolchains \
	  -v ~/aros-toolchains/crosstools-workaround-arm:/work/build-aarch64-main/bin/linux-aarch64/tools/crosstools \
	  -w /src ubuntu:24.04 \
	  /toolchains/aros-toolchain-aarch64/bin/aarch64-aros-gcc \
	  --sysroot=/toolchains/aros-toolchain-aarch64/sysroot \
	  $(SRCS) -o $(TARGET) $(CFLAGS) $(LIBS)

clean:
	rm -f $(TARGET)