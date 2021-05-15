OBJS=secure_chat_interceptor.c
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g
LDLIBS= -lssl -lcrypto
TARGET=secure_chat_interceptor
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)


