#include "flow_store.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct flow_store {
    MDB_env *env;
    MDB_dbi dbi;
};

#define FLOW_STORE_DEFAULT_MAPSIZE   (512ULL * 1024ULL * 1024ULL)

static inline void flow_store_set_key(MDB_val *key, const uint64_t *hash_ptr) {
    key->mv_size = sizeof(uint64_t);
    key->mv_data = (void *)hash_ptr;
}

static inline void flow_store_set_value(MDB_val *val, const nm_flow_state_t *state) {
    val->mv_size = sizeof(*state);
    val->mv_data = (void *)state;
}

int flow_store_open(flow_store_t **out,
                    const char *path,
                    size_t mapsize_bytes,
                    unsigned int max_readers) {
    MDB_txn *txn = NULL;
    flow_store_t *st = NULL;
    int rc;

    if (!out || !path || path[0] == '\0') {
        return EINVAL;
    }

    *out = NULL;

    st = (flow_store_t *)calloc(1, sizeof(*st));
    if (!st) {
        return ENOMEM;
    }

    rc = mdb_env_create(&st->env);
    if (rc != MDB_SUCCESS) {
        free(st);
        return rc;
    }

    if (mapsize_bytes == 0) {
        mapsize_bytes = FLOW_STORE_DEFAULT_MAPSIZE;
    }

    rc = mdb_env_set_mapsize(st->env, mapsize_bytes);
    if (rc != MDB_SUCCESS) {
        mdb_env_close(st->env);
        free(st);
        return rc;
    }

    if (max_readers > 0) {
        rc = mdb_env_set_maxreaders(st->env, max_readers);
        if (rc != MDB_SUCCESS) {
            mdb_env_close(st->env);
            free(st);
            return rc;
        }
    }

    rc = mdb_env_open(st->env, path, MDB_NOSUBDIR | MDB_NOMETASYNC, 0640);
    if (rc != MDB_SUCCESS) {
        mdb_env_close(st->env);
        free(st);
        return rc;
    }

    rc = mdb_txn_begin(st->env, NULL, 0, &txn);
    if (rc != MDB_SUCCESS) {
        mdb_env_close(st->env);
        free(st);
        return rc;
    }

    rc = mdb_dbi_open(txn, NULL, MDB_CREATE, &st->dbi);
    if (rc == MDB_SUCCESS) {
        rc = mdb_txn_commit(txn);
        txn = NULL;
    }

    if (rc != MDB_SUCCESS) {
        if (txn) {
            mdb_txn_abort(txn);
        }
        mdb_env_close(st->env);
        free(st);
        return rc;
    }

    *out = st;
    return MDB_SUCCESS;
}

void flow_store_close(flow_store_t *st) {
    if (!st) {
        return;
    }

    if (st->env) {
        mdb_dbi_close(st->env, st->dbi);
        mdb_env_close(st->env);
    }

    free(st);
}

int flow_store_put(flow_store_t *st,
                   uint64_t flow_hash,
                   const nm_flow_state_t *state) {
    MDB_txn *txn = NULL;
    MDB_val key;
    MDB_val value;
    int rc;

    if (!st || !state) {
        return EINVAL;
    }

    rc = mdb_txn_begin(st->env, NULL, 0, &txn);
    if (rc != MDB_SUCCESS) {
        return rc;
    }

    flow_store_set_key(&key, &flow_hash);
    flow_store_set_value(&value, state);

    rc = mdb_put(txn, st->dbi, &key, &value, 0);
    if (rc == MDB_SUCCESS) {
        rc = mdb_txn_commit(txn);
        txn = NULL;
    }

    if (rc != MDB_SUCCESS) {
        if (txn) {
            mdb_txn_abort(txn);
        }
    }

    return rc;
}

int flow_store_get(flow_store_t *st,
                   uint64_t flow_hash,
                   nm_flow_state_t *out_state) {
    MDB_txn *txn = NULL;
    MDB_val key;
    MDB_val data;
    int rc;

    if (!st || !out_state) {
        return EINVAL;
    }

    rc = mdb_txn_begin(st->env, NULL, MDB_RDONLY, &txn);
    if (rc != MDB_SUCCESS) {
        return rc;
    }

    flow_store_set_key(&key, &flow_hash);

    rc = mdb_get(txn, st->dbi, &key, &data);
    if (rc == MDB_SUCCESS) {
        if (data.mv_size != sizeof(*out_state)) {
            rc = MDB_BAD_VALSIZE;
        } else {
            memcpy(out_state, data.mv_data, sizeof(*out_state));
        }
    }

    mdb_txn_abort(txn);
    return rc;
}

int flow_store_del(flow_store_t *st,
                   uint64_t flow_hash) {
    MDB_txn *txn = NULL;
    MDB_val key;
    int rc;

    if (!st) {
        return EINVAL;
    }

    rc = mdb_txn_begin(st->env, NULL, 0, &txn);
    if (rc != MDB_SUCCESS) {
        return rc;
    }

    flow_store_set_key(&key, &flow_hash);

    rc = mdb_del(txn, st->dbi, &key, NULL);
    if (rc == MDB_SUCCESS || rc == MDB_NOTFOUND) {
        rc = mdb_txn_commit(txn);
        txn = NULL;
    }

    if (rc != MDB_SUCCESS) {
        if (txn) {
            mdb_txn_abort(txn);
        }
    }

    return rc;
}

int flow_store_iter(flow_store_t *st,
                    MDB_cursor **cursor,
                    uint64_t *out_hash,
                    nm_flow_state_t *out_state) {
    MDB_val key;
    MDB_val data;
    MDB_cursor *cur;
    MDB_txn *txn = NULL;
    MDB_cursor_op op;
    int rc;

    if (!st || !cursor || !out_hash || !out_state) {
        return EINVAL;
    }

    cur = *cursor;
    if (!cur) {
        rc = mdb_txn_begin(st->env, NULL, MDB_RDONLY, &txn);
        if (rc != MDB_SUCCESS) {
            return rc;
        }
        rc = mdb_cursor_open(txn, st->dbi, &cur);
        if (rc != MDB_SUCCESS) {
            mdb_txn_abort(txn);
            return rc;
        }
        *cursor = cur;
        op = MDB_FIRST;
    } else {
        op = MDB_NEXT;
    }

    rc = mdb_cursor_get(cur, &key, &data, op);
    if (rc != MDB_SUCCESS) {
        flow_store_iter_end(cur);
        *cursor = NULL;
        return rc;
    }

    if (key.mv_size != sizeof(uint64_t) || data.mv_size != sizeof(*out_state)) {
        flow_store_iter_end(cur);
        *cursor = NULL;
        return MDB_BAD_VALSIZE;
    }

    memcpy(out_hash, key.mv_data, sizeof(uint64_t));
    memcpy(out_state, data.mv_data, sizeof(*out_state));
    return MDB_SUCCESS;
}

void flow_store_iter_end(MDB_cursor *cursor) {
    MDB_txn *txn;

    if (!cursor) {
        return;
    }

    txn = mdb_cursor_txn(cursor);
    mdb_cursor_close(cursor);
    if (txn) {
        mdb_txn_abort(txn);
    }
}
