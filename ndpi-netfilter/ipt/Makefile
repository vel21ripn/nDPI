NDPI_PATH2 := ${NDPI_PATH}/src
NDPI_SRC := ..
NDPI_PRO := ${NDPI_SRC}/lib/protocols
XTBL := $(shell pkg-config --variable=xtlibdir xtables)

CFLAGS = -fPIC -I${NDPI_SRC}/include -I${NDPI_SRC}/lib -I../src -DOPENDPI_NETFILTER_MODULE -O2 -Wall

all:  libxt_ndpi.so
install:  libxt_ndpi.so
	if [ -n "$(DESTDIR)$(XTBL)" -a -d "$(DESTDIR)$(XTBL)" ]; then install -v libxt_ndpi.so $(DESTDIR)$(XTBL); ln -fs libxt_ndpi.so $(DESTDIR)$(XTBL)/libxt_NDPI.so ; else echo "No pkg-config --variable=xtlibdir xtables"; fi

lib%.so: lib%.o
	$(CC) -shared -o $@ $^;
lib%.o: lib%.c ../src/xt_ndpi.h ../../config.h
	$(CC) ${CFLAGS} -D_INIT=lib$*_init -c -o $@ $<;
clean:
	rm -rf libxt_ndpi.so

