INCDIR := /opt/openssl/include
LINKDIR := /opt/openssl/lib64
CC := gcc
RM := rm -f
CFLAGS := -W -Wall -O0 -g3 -I. -I$(INCDIR) 
LDFLAGS := -L$(LINKDIR)
LIBS := -lssl -lcrypto

COMMON_H = common.h
COMMON_OBJ = common.o

CLIENT_PROG := client
CLIENT_OBJ := client.o

SERVER_PROG := server
SERVER_OBJ := server.o

.c.o:
	$(CC) -c $(CFLAGS) $<

all: $(CLIENT_PROG) $(SERVER_PROG)

$(CLIENT_PROG): $(COMMON_OBJ) $(CLIENT_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

$(SERVER_PROG): $(COMMON_OBJ) $(SERVER_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

$(COMMON_OBJ): $(COMMON_H)
$(CLIENT_OBJ): $(COMMON_H)
$(SERVER_OBJ): $(COMMON_H)

clean: 
	$(RM) *.o $(CLIENT_PROG) $(SERVER_PROG)
