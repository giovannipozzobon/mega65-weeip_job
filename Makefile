# tools & flags
CC         := cc6502
LD         := ln6502
CFLAGS     := -O2 --target=mega65
LINKSCRIPT := mega65-banked.scm
LDFLAGS    := --target=mega65 \
              --core=45gs02 \
              --cstack-size=0x800 \
              --heap-size=4000 \
              --output-format=prg

# directories
OBJDIR     := obj

# source lists
MEGA_SRCS  := memory.c random.c debug.c hal.c time.c targets.c
WEEIP_SRCS := arp.c checksum.c dhcp.c dns.c eth.c nwk.c socket.c task.c
ROOT_SRCS  := terminal.c udptest.c

# object lists
MEGA_OBJS  := $(patsubst %.c,$(OBJDIR)/%.o,$(MEGA_SRCS))
WEEIP_OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(WEEIP_SRCS))
ROOT_OBJS  := $(patsubst %.c,$(OBJDIR)/%.o,$(ROOT_SRCS))
OBJS       := $(MEGA_OBJS) $(WEEIP_OBJS) $(ROOT_OBJS)

# final PRG targets
PRGS       := terminal.prg udptest.prg

.PHONY: all clean
all: $(PRGS)

# ensure obj/ exists
$(OBJDIR):
	mkdir -p $(OBJDIR)

# compile patterns
$(OBJDIR)/%.o: mega65/src/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $< -o $@

$(OBJDIR)/%.o: weeip/src/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $< -o $@

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS) $< -o $@

# link terminal.prg (exclude udptest.o)
terminal.prg: $(OBJDIR)/terminal.o $(filter-out $(OBJDIR)/udptest.o,$(OBJS))
	cd $(OBJDIR) && \
	$(LD) $(LDFLAGS) $(LINKSCRIPT) $(notdir $^) -o $(@F); \
	mv $(@F) ..

# link udptest.prg (exclude terminal.o)
udptest.prg: $(OBJDIR)/udptest.o $(filter-out $(OBJDIR)/terminal.o,$(OBJS))
	cd $(OBJDIR) && \
	$(LD) $(LDFLAGS) $(LINKSCRIPT) $(notdir $^) -o $(@F); \
	mv $(@F) ..

clean:
	rm -f $(OBJDIR)/*.o $(OBJDIR)/*.prg *.prg