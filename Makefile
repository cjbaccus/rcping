# Makefile for cping-rs
#
#   make            build the optimized (release) binary
#   make build      same
#   make gpio       build with Raspberry Pi GPIO support (--features gpio)
#   make test       run the test suite
#   sudo make install     build and install into $(INSTDIR), then grant the
#                         raw-socket privilege the program needs
#   sudo make uninstall   remove it
#   make clean      remove build artifacts
#
# Overridable:
#   INSTDIR   install directory           (default /usr/local/sbin)
#   NAME      installed executable name   (default cping-rs; use NAME=cping
#                                          for a drop-in replacement of the C build)
#   FEATURES  extra cargo features        (e.g. FEATURES=gpio)
#
# NOTE: /usr/local/sbin may not be on non-root users' PATH on some distros;
#       use INSTDIR=/usr/local/bin if you want it there instead.

INSTDIR  ?= /usr/local/sbin
NAME     ?= rcping
FEATURES ?=

CARGO    ?= cargo
UNAME    := $(shell uname)
UNAME_M  := $(shell uname -m)

BIN       = target/release/cping-rs
DEST      = $(DESTDIR)$(INSTDIR)/$(NAME)

CARGO_FLAGS = --release
ifneq ($(strip $(FEATURES)),)
CARGO_FLAGS += --features $(FEATURES)
endif

.PHONY: all build gpio test clean install uninstall help

all: build

build:
	$(CARGO) build $(CARGO_FLAGS)

gpio:
	$(CARGO) build --release --features gpio

test:
	$(CARGO) test $(CARGO_FLAGS)

clean:
	$(CARGO) clean

install: build
	install -d $(DESTDIR)$(INSTDIR)
	install -m 0755 $(BIN) $(DEST)
ifeq ($(UNAME),Darwin)
	# macOS: raw ICMP sockets need root -> install setuid root.
	chown root $(DEST)
	chmod u+s $(DEST)
else ifneq ($(strip $(filter gpio,$(FEATURES))),)
	# Linux GPIO build: raw sockets + raw I/O + /dev/mem access.
	setcap cap_net_raw,cap_sys_rawio,cap_dac_override=ep $(DEST)
else
	# Linux: allow any user to send ICMP without root.
	setcap cap_net_raw=ep $(DEST)
endif
	@echo
	@echo "Installed $(DEST)"
	@echo "Run it as: $(NAME)"

uninstall:
	rm -f $(DEST)

help:
	@sed -n '3,20p' $(firstword $(MAKEFILE_LIST))
