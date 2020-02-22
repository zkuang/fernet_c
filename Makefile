CC = gcc  # C compiler
CFLAGS = -fPIC -Wall -Wextra -O2 -g  # C flags
LDFLAGS = -shared   # linking flags
RM = rm -f   # rm command
TARGET_LIB = libfernet.so  # target lib
MAIN = main

SRCS = base64.c aes.c hmac_sha2.c sha2.c fernet.c  # source files
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB} ${MAIN}

${MAIN}: $(OBJS) main.c
	$(CC) -o $@ $^

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-${RM} ${MAIN} ${TARGET_LIB} ${OBJS} $(SRCS:.c=.d) main.d main.o