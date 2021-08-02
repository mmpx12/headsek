build:
	go build -o headsek -ldflags="-w -s"

install:
	cp headsek /usr/bin/headsek

all: build install

clean:
	rm -f headsek /usr/bin/headsek
