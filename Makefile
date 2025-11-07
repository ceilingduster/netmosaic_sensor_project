CC := gcc
NDPI_DEFINES := -DENABLE_TLS -DENABLE_DOH -DENABLE_ZLIB -DENABLE_LRU_CACHE
CFLAGS := -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter $(NDPI_DEFINES) -I. -Iinclude \
	-Ilibs/windivert/include \
	-Ilibs/nDPI-4.14/src/include \
	-Ilibs/lua/src

LDFLAGS := -Llibs/nDPI-4.14/src/lib -Llibs/windivert/x64 -Lbuild/lua
LIBS := -lndpi -lWinDivert -llua -lws2_32 -liphlpapi -ladvapi32

BUILD_DIR := build
LUA_BUILD_DIR := $(BUILD_DIR)/lua
SRC_DIR := src

DIST_DIR := $(BUILD_DIR)/dist
DIST_LOG_DIR := $(DIST_DIR)/logs
DIST_STATIC_DIR := $(DIST_DIR)/lib

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

LUA_SRCS := $(filter-out libs/lua/src/lua.c libs/lua/src/luac.c, $(wildcard libs/lua/src/*.c))
LUA_OBJS := $(patsubst libs/lua/src/%.c,$(LUA_BUILD_DIR)/%.o,$(LUA_SRCS))

TARGET := netmosaic_sensor.exe

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) $(LUA_BUILD_DIR)/liblua.a
	$(CC) $(OBJS) $(LDFLAGS) $(LIBS) -o $@
	mkdir -p $(DIST_DIR) $(DIST_LOG_DIR) $(DIST_STATIC_DIR)
	cp -f $@ $(DIST_DIR)/
	[ -f $(BUILD_DIR)/lua/liblua.a ] && cp -f $(BUILD_DIR)/lua/liblua.a $(DIST_STATIC_DIR)/ || true
	[ -f libs/nDPI-4.14/src/lib/libndpi.a ] && cp -f libs/nDPI-4.14/src/lib/libndpi.a $(DIST_STATIC_DIR)/ || true

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LUA_BUILD_DIR)/%.o: libs/lua/src/%.c | $(LUA_BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LUA_BUILD_DIR)/liblua.a: $(LUA_OBJS)
	ar rcs $@ $^

$(BUILD_DIR):
	mkdir -p $@

$(LUA_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

clean:
	rm -f $(TARGET)
	rm -rf $(BUILD_DIR)
