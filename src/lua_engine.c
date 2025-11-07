#include "sensor.h"

static lua_script_descriptor_t *g_loader_descriptor = NULL;

static void derive_signature_from_filename(const char *filename, char *out, size_t out_len) {
    size_t len = strlen(filename);
    const char *end = filename + len;
    const char *dot = strrchr(filename, '.');
    const char *start = filename;
    const char *slash = strrchr(filename, '\\');
    const char *slash2 = strrchr(filename, '/');
    if (slash2 && (!slash || slash2 > slash)) {
        slash = slash2;
    }
    if (slash) {
        start = slash + 1;
    }
    if (dot && dot > start) {
        end = dot;
    }
    size_t copy_len = (size_t)(end - start);
    if (copy_len >= out_len) {
        copy_len = out_len - 1;
    }
    memcpy(out, start, copy_len);
    out[copy_len] = '\0';
}

static int lua_register_signature(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    if (g_loader_descriptor) {
        safe_strcpy(g_loader_descriptor->signature, sizeof(g_loader_descriptor->signature), name);
    }
    return 0;
}

bool load_lua_scripts(sensor_runtime_t *rt) {
    rt->script_count = 0;
    char pattern[MAX_PATH];
    build_path(pattern, sizeof(pattern), "protocol_parsers", "*.lua");

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        if (!rt->config->stdout_minimal) {
            printf("[lua] no protocol parsers found under protocol_parsers\\*.lua\n");
        }
        return true;
    }

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }
        if (rt->script_count >= LUA_MAX_SCRIPTS) {
            fprintf(stderr, "[lua] maximum script count reached (%u)\n", LUA_MAX_SCRIPTS);
            break;
        }
        lua_script_descriptor_t *descriptor = &rt->scripts[rt->script_count];
        memset(descriptor, 0, sizeof(*descriptor));

        build_path(descriptor->path, sizeof(descriptor->path), "protocol_parsers", fd.cFileName);
        derive_signature_from_filename(fd.cFileName, descriptor->signature, sizeof(descriptor->signature));

        lua_State *L = luaL_newstate();
        if (!L) {
            fprintf(stderr, "[lua] failed to create interpreter for %s\n", descriptor->path);
            continue;
        }
        luaL_openlibs(L);
        lua_pushcfunction(L, lua_register_signature);
        lua_setglobal(L, "register_signature");

        g_loader_descriptor = descriptor;
        if (luaL_loadfile(L, descriptor->path) != LUA_OK) {
            fprintf(stderr, "[lua] load error %s: %s\n", descriptor->path, lua_tostring(L, -1));
            lua_close(L);
            g_loader_descriptor = NULL;
            continue;
        }
        if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
            fprintf(stderr, "[lua] runtime error %s: %s\n", descriptor->path, lua_tostring(L, -1));
            lua_close(L);
            g_loader_descriptor = NULL;
            continue;
        }
        g_loader_descriptor = NULL;
        lua_close(L);

        if (descriptor->signature[0] == '\0') {
            derive_signature_from_filename(fd.cFileName, descriptor->signature, sizeof(descriptor->signature));
        }

        if (!rt->config->stdout_minimal) {
            printf("[lua] loaded descriptor %s (%s)\n", descriptor->signature, descriptor->path);
        }
        rt->script_count++;
    } while (FindNextFileA(h, &fd));

    FindClose(h);
    return true;
}
