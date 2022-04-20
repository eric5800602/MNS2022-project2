CC = gcc
ARMCC = arm-linux-gnueabi-gcc
CFLAGS = -std=gnu11 -Wall -I include
DFLAG = -g
ARMFLAGS = -march=armv7-a -static -DARM

ONUE = ue_call_sim

ONPC = pc_call_sim

DEPS = \
	src/dev.c             \
	src/net.c             \
	src/esp.c             \
	src/hmac.c            \
	src/transport.c       \
	src/replay.c          \
	src/sha1.c

all: $(ONUE)

debug: $(ONUE)


ue_call_sim: src/main.c $(DEPS)
	$(ARMCC) $^ -o $@ $(CFLAGS) $(DFLAG) $(ARMFLAGS) -O2

pc_call_sim: src/main.c $(DEPS)
	$(CC) $^ -o $@ $(CFLAGS) $(DFLAG)

clean:
	rm -f $(ONUE)
	rm -f $(ONPC)
	rm -f test
