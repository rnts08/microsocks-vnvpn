# if you want to change/override some variables, do so in a file called
# config.mak, which is gets included automatically if it exists.

prefix = /usr/local
bindir = $(prefix)/bin

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

install: $(PROG)
	$(INSTALL) -D -m 755 $(PROG) $(DESTDIR)$(bindir)/$(PROG)
	$(INSTALL) -D -m 755 $(MSADMIN) $(DESTDIR)$(bindir)/$(MSADMIN)

clean:
	rm -f $(PROG) $(MSADMIN)
	rm -f $(OBJS) $(OBJS_ADMIN)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) $(PIC) -c -o $@ $<

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

$(MSADMIN): $(OBJS_ADMIN)
	$(CC) $(LDFLAGS) $(OBJS_ADMIN) $(LIBS) -o $@

.PHONY: all clean install

