# if you want to change/override some variables, do so in a file called
# config.mak, which is gets included automatically if it exists.

prefix = /usr/local
bindir = $(prefix)/bin
mandir = $(prefix)/share/man
docdir = $(prefix)/share/doc/microsocks

PROG = microsocks
MSADMIN = msadmin
SRCS = sockssrv.c server.c sblist.c sblist_delete.c db.c
SRCS_ADMIN = msadmin.c db.c
OBJS = $(SRCS:.c=.o)
OBJS_ADMIN = $(SRCS_ADMIN:.c=.o)

LIBS = -lpthread -lsqlite3 -lsodium

CFLAGS += -Wall -std=c99

INSTALL = ./install.sh

-include config.mak

all: $(PROG) $(MSADMIN)

install: $(PROG) $(MSADMIN)
	# Install binaries
	$(INSTALL) -D -m 755 $(PROG) $(DESTDIR)$(bindir)/$(PROG)
	$(INSTALL) -D -m 755 $(MSADMIN) $(DESTDIR)$(bindir)/$(MSADMIN)
	# Install manpages
	$(INSTALL) -D -m 644 microsocks.1 $(DESTDIR)$(mandir)/man1/microsocks.1
	$(INSTALL) -D -m 644 msadmin.1 $(DESTDIR)$(mandir)/man1/msadmin.1
	# Install documentation
	$(INSTALL) -D -m 644 README.md $(DESTDIR)$(docdir)/README.md
	$(INSTALL) -D -m 644 COPYING $(DESTDIR)$(docdir)/COPYING
	# Install configuration
	$(INSTALL) -D -m 644 microsocks.conf $(DESTDIR)$(prefix)/etc/microsocks/microsocks.conf

clean:
	rm -f $(PROG)
	rm -f $(OBJS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) $(PIC) -c -o $@ $<

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

$(MSADMIN): $(OBJS_ADMIN)
	$(CC) $(LDFLAGS) $(OBJS_ADMIN) -lsqlite3 -lsodium -o $@

.PHONY: all clean install

