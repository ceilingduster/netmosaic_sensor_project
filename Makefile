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

BUILD_DIR_WIN := $(subst /,\,$(BUILD_DIR))
LUA_BUILD_DIR_WIN := $(subst /,\,$(LUA_BUILD_DIR))
DIST_DIR_WIN := $(subst /,\,$(DIST_DIR))
DIST_LOG_DIR_WIN := $(subst /,\,$(DIST_LOG_DIR))
DIST_STATIC_DIR_WIN := $(subst /,\,$(DIST_STATIC_DIR))

define make_dir
	if not exist "$(1)" mkdir "$(1)"
endef

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

LUA_SRCS := $(filter-out libs/lua/src/lua.c libs/lua/src/luac.c, $(wildcard libs/lua/src/*.c))
LUA_OBJS := $(patsubst libs/lua/src/%.c,$(LUA_BUILD_DIR)/%.o,$(LUA_SRCS))

TARGET := netmosaic_sensor.exe
TARGET_WIN := $(subst /,\,$(TARGET))

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) $(LUA_BUILD_DIR)/liblua.a
	$(CC) $(OBJS) $(LDFLAGS) $(LIBS) -o $@
	@$(call make_dir,$(DIST_DIR_WIN))
	@$(call make_dir,$(DIST_LOG_DIR_WIN))
	@$(call make_dir,$(DIST_STATIC_DIR_WIN))
	@copy /Y "$@" "$(DIST_DIR_WIN)\$@" >NUL
	@if exist "$(BUILD_DIR_WIN)\lua\liblua.a" copy /Y "$(BUILD_DIR_WIN)\lua\liblua.a" "$(DIST_STATIC_DIR_WIN)\liblua.a" >NUL
	@if exist "libs\nDPI-4.14\src\lib\libndpi.a" copy /Y "libs\nDPI-4.14\src\lib\libndpi.a" "$(DIST_STATIC_DIR_WIN)\libndpi.a" >NUL

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LUA_BUILD_DIR)/%.o: libs/lua/src/%.c | $(LUA_BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LUA_BUILD_DIR)/liblua.a: $(LUA_OBJS)
	ar rcs $@ $^

$(BUILD_DIR):
	@$(call make_dir,$(subst /,\,$@))

$(LUA_BUILD_DIR): | $(BUILD_DIR)
	@$(call make_dir,$(subst /,\,$@))

clean:
	@if exist "$(TARGET_WIN)" del /Q "$(TARGET_WIN)"
	@if exist "$(BUILD_DIR_WIN)" rmdir /S /Q "$(BUILD_DIR_WIN)"
