uname_s := $(shell uname -s)

GXX := gcc

TARGET := ./bin/mSock

INC := -I ./inc
LIBS := -pthread -lcrypto -lssl

CPPFLAGS := -Wall 

ifeq ($(mode),server)
	CPPFLAGS += -DMSOCK_SEVER
	TARGET := ./bin/mSock_server
else
	ifeq ($(type),socks)
		CPPFLAGS += -DMSOCK_SOCKS
		TARGET := ./bin/mSock_socks
	else
		TARGET := ./bin/mSock_https
	endif
endif

SRC_DIR := src
OBJ_DIR := ./objs

SRC := $(wildcard ${SRC_DIR}/*.c)
OBJ := $(patsubst %.c, ${OBJ_DIR}/%.o, $(notdir ${SRC}))

all:exe

debug:CPPFLAGS += -g
debug:exe

exe:${OBJ}
	$(GXX) -o ${TARGET} ${OBJ} $(LIBS) 

${OBJ_DIR}/%.o:${SRC_DIR}/%.c
	echo ${SRC}	
	test -d ${OBJ_DIR} || mkdir -p ${OBJ_DIR}
	@echo Compiling $< ...
	$(GXX) $(CPPFLAGS) -o $@ -c $< $(INC) 

clean:
	rm -rf ${OBJ_DIR}
	rm -rf $(TARGET)
	