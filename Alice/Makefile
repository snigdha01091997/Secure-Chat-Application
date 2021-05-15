OBJS=secure_chat_app.c
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g
LDLIBS= -lssl -lcrypto
TARGET=secure_chat_app
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)


