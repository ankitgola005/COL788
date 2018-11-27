CC:=gcc
#CCFLAGS:=-Wall -Iinclude
CCFLAGS:=-Iinclude
CRYPT:=-lcrypt
BIN:=bin

all: client ftpd

libs:=lib/utils.c lib/log.c lib/vars.c

ftpd:server.c ${libs} $(BIN)
	${CC} ${CCFLAGS} -o ./${BIN}/$@ server.c ${libs} ${CRYPT}

client:client.c ${libs} $(BIN)
	${CC} ${CCFLAGS} -o ./${BIN}/$@ client.c ${libs}

$(BIN):
	if [ ! -d ./bin ]; then mkdir ./bin; fi

clean:
	rm ./${BIN}/client
	rm ./${BIN}/ftpd
