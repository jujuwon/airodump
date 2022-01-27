LDLIBS	= -lpcap
OBJS	= main.o dot11.o mac.o
TARGET	= airodump

$(TARGET): $(OBJS)
	$(LINK.cc) $(OBJS) $(LDLIBS) -o $(@)

clean:
	rm -f $(OBJS) $(TARGET)