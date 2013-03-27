CC=gcc
CFLAGS=-c -Wall -I /usr/include/libnl3/
LDFLAGS=-l nl-3 -l nl-genl-3 -l nl-nf-3 -l nl-route-3
SOURCES=dhcpsnoopingd.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=dhcpsnoopingd
prefix=/usr

all:	$(SOURCES) $(EXECUTABLE)

$(EXECUTABLE):	$(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

%.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

install:
	mkdir -p $(DESTDIR)$(prefix)/sbin/
	install -m 0755 $(EXECUTABLE) $(DESTDIR)$(prefix)/sbin/

clean:
	rm -f $(OBJECTS)
	rm -f $(EXECUTABLE)

.PHONY:	install clean
