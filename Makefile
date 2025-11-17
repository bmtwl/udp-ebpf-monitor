# Makefile
CC = clang
CFLAGS = -O2 -target bpf
LIBBPF_CFLAGS = $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include/bpf")
LIBBPF_LDLIBS = $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf")

.PHONY: all repeater tester

all: repeater tester

repeater: udp_repeater.c
	gcc $(LIBBPF_CFLAGS) -o udp_repeater udp_repeater.c $(LIBBPF_LDLIBS) -lelf

tester: udp_monitor_tester.c
	gcc $(LIBBPF_CFLAGS) -o udp_monitor_tester udp_monitor_tester.c $(LIBBPF_LDLIBS) -lelf

clean:
	rm -f udp_repeater udp_monitor_tester *.o

