CC := gcc
NDPI_DEFINES := -DENABLE_TLS -DENABLE_DOH -DENABLE_ZLIB -DENABLE_LRU_CACHE
CFLAGS := -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter $(NDPI_DEFINES) -I. -Iinclude \
	-Ilibs/windivert/include \
	-Ilibs/nDPI-4.14/src/include \
	-Ilibs/lua/src \
	-Ilibs/lmdb

LDFLAGS := -Llibs/nDPI-4.14/src/lib -Llibs/windivert/x64 -Lbuild/lua
LIBS := -lndpi -lWinDivert -llua -lws2_32 -liphlpapi -ladvapi32

BUILD_DIR := build
LUA_BUILD_DIR := $(BUILD_DIR)/lua
SRC_DIR := src

PTHREAD_DLL ?= C:/msys64/mingw64/bin/libwinpthread-1.dll
WINDIVERT_DLL ?= libs/windivert/x64/WinDivert.dll
DIST_ZIP := $(BUILD_DIR)/netmosaic_sensor_dist.zip

DIST_DIR := $(BUILD_DIR)/dist
DIST_LOG_DIR := $(DIST_DIR)/logs
DIST_STATIC_DIR := $(DIST_DIR)/lib
DIST_STAGE := $(BUILD_DIR)/dist_stage

BUILD_DIR_WIN := $(subst /,\,$(BUILD_DIR))
LUA_BUILD_DIR_WIN := $(subst /,\,$(LUA_BUILD_DIR))
DIST_DIR_WIN := $(subst /,\,$(DIST_DIR))
DIST_LOG_DIR_WIN := $(subst /,\,$(DIST_LOG_DIR))
DIST_STATIC_DIR_WIN := $(subst /,\,$(DIST_STATIC_DIR))
DIST_STAGE_WIN := $(subst /,\,$(DIST_STAGE))
DIST_ZIP_WIN := $(subst /,\,$(DIST_ZIP))
PTHREAD_DLL_WIN := $(subst /,\,$(PTHREAD_DLL))
WINDIVERT_DLL_WIN := $(subst /,\,$(WINDIVERT_DLL))

define make_dir
	if not exist "$(1)" mkdir "$(1)"
endef

SRCS := $(filter-out $(SRC_DIR)/flow_store_dump.c,$(wildcard $(SRC_DIR)/*.c))
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

DUMP_SRCS := $(SRC_DIR)/flow_store_dump.c
DUMP_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(DUMP_SRCS))

LMDB_SRCS := libs/lmdb/mdb.c libs/lmdb/midl.c
LMDB_OBJS := $(patsubst libs/lmdb/%.c,$(BUILD_DIR)/lmdb_%.o,$(LMDB_SRCS))

LUA_SRCS := $(filter-out libs/lua/src/lua.c libs/lua/src/luac.c, $(wildcard libs/lua/src/*.c))
LUA_OBJS := $(patsubst libs/lua/src/%.c,$(LUA_BUILD_DIR)/%.o,$(LUA_SRCS))

TARGET := netmosaic_sensor.exe
TARGET_WIN := $(subst /,\,$(TARGET))

.PHONY: all clean dist

all: $(TARGET) flow_store_dump.exe

dist: $(DIST_ZIP)

flow_store_dump.exe: $(DUMP_OBJS) $(BUILD_DIR)/flow_store.o $(BUILD_DIR)/config.o $(BUILD_DIR)/util.o $(LMDB_OBJS) $(LUA_BUILD_DIR)/liblua.a
	$(CC) $(DUMP_OBJS) $(BUILD_DIR)/flow_store.o $(BUILD_DIR)/config.o $(BUILD_DIR)/util.o $(LMDB_OBJS) $(LDFLAGS) $(LIBS) -o $@
	@$(call make_dir,$(DIST_DIR_WIN))
	@copy /Y "$@" "$(DIST_DIR_WIN)\$@" >NUL

$(TARGET): $(OBJS) $(LMDB_OBJS) $(LUA_BUILD_DIR)/liblua.a
	$(CC) $(OBJS) $(LMDB_OBJS) $(LDFLAGS) $(LIBS) -o $@
	@$(call make_dir,$(DIST_DIR_WIN))
	@$(call make_dir,$(DIST_LOG_DIR_WIN))
	@$(call make_dir,$(DIST_STATIC_DIR_WIN))
	@copy /Y "$@" "$(DIST_DIR_WIN)\$@" >NUL
	@if exist "$(BUILD_DIR_WIN)\lua\liblua.a" copy /Y "$(BUILD_DIR_WIN)\lua\liblua.a" "$(DIST_STATIC_DIR_WIN)\liblua.a" >NUL
	@if exist "libs\nDPI-4.14\src\lib\libndpi.a" copy /Y "libs\nDPI-4.14\src\lib\libndpi.a" "$(DIST_STATIC_DIR_WIN)\libndpi.a" >NUL

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/lmdb_%.o: libs/lmdb/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LUA_BUILD_DIR)/%.o: libs/lua/src/%.c | $(LUA_BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LUA_BUILD_DIR)/liblua.a: $(LUA_OBJS)
	ar rcs $@ $^

$(DIST_ZIP): all | $(DIST_STAGE)
	@del /Q "$(DIST_STAGE_WIN)\*" >NUL 2>&1 || ver >NUL
	@if not exist "$(PTHREAD_DLL_WIN)" ( echo libpwinthread-1.dll not found at $(PTHREAD_DLL_WIN) & exit /b 1 )
	@if not exist "$(WINDIVERT_DLL_WIN)" ( echo WinDivert.dll not found at $(WINDIVERT_DLL_WIN) & exit /b 1 )
	@copy /Y "$(TARGET_WIN)" "$(DIST_STAGE_WIN)\$(TARGET)" >NUL
	@copy /Y "flow_store_dump.exe" "$(DIST_STAGE_WIN)\flow_store_dump.exe" >NUL
	@copy /Y "$(PTHREAD_DLL_WIN)" "$(DIST_STAGE_WIN)\libwinpthread-1.dll" >NUL
	@copy /Y "$(WINDIVERT_DLL_WIN)" "$(DIST_STAGE_WIN)\WinDivert.dll" >NUL
	@if exist "$(DIST_ZIP_WIN)" del /Q "$(DIST_ZIP_WIN)"
	@powershell -NoProfile -Command "Compress-Archive -Path '$(DIST_STAGE_WIN)\*' -DestinationPath '$(DIST_ZIP_WIN)' -Force" >NUL
	@echo Created $(DIST_ZIP)

$(BUILD_DIR):
	@$(call make_dir,$(subst /,\,$@))

$(LUA_BUILD_DIR): | $(BUILD_DIR)
	@$(call make_dir,$(subst /,\,$@))

$(DIST_STAGE): | $(BUILD_DIR)
	@$(call make_dir,$(DIST_STAGE_WIN))

clean:
	@if exist "$(TARGET_WIN)" del /Q "$(TARGET_WIN)"
	@if exist "$(BUILD_DIR_WIN)" rmdir /S /Q "$(BUILD_DIR_WIN)"
	@if exist "flow_store_dump.exe" del /Q flow_store_dump.exe
	@if exist "$(DIST_ZIP_WIN)" del /Q "$(DIST_ZIP_WIN)"
