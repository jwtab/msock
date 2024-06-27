uname_s := $(shell uname -s)

GXX := gcc

TARGET := ./bin/mSock

INC := -I ./inc
LIBS := 

CPPFLAGS := -Wall

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
	test -d ${OBJ_DIR} || mkdir -p ${OBJ_DIR}
	@echo Compiling $< ...
	$(GXX) $(CPPFLAGS) -o $@ -c $< $(INC) 

clean:
	rm -rf ${OBJ_DIR}
	rm -rf ${TARGET}
