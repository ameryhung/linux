#include "bpf_uptr_kv_store_common.h"

#include <bpf/bpf_helpers.h>

#define PAGE_IDX_MASK 0x8000

struct uptr_kvs_offsets {
#define UPTR_KVS_TYPE_KEY(type, key) short key;
UPTR_KVS_LIST
#undef UPTR_KVS_TYPE_KEY
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct uptr_kvs_map_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} uptr_kvs_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct uptr_kvs_offsets);
} offset_map SEC(".maps");

struct uptr_kvs {
	struct uptr_kvs_map_value *kvs_val;
	struct uptr_kvs_offsets *off_val;
};

static int uptr_kvs_cache_offset(struct task_struct *task)
{
	struct uptr_kvs_map_value *kvs_val;
	struct uptr_kvs_offsets *off_val;
	void *kvs_umeta, *kvs_umeta_key, *kvs_umeta_off;
	int i, off, umetadata_cnt, udata_off;

	off_val = bpf_task_storage_get(&offset_map, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!off_val)
		return -1;

	kvs_val = bpf_task_storage_get(&uptr_kvs_map, task, 0, 0);
	if (!kvs_val || !kvs_val->umetadata)
		return -1;

	udata_off = kvs_val->udata_off;
	umetadata_cnt = kvs_val->umetadata_cnt;
	kvs_umeta = kvs_val->umetadata->meta;

	bpf_for(i, 0, umetadata_cnt) {
#define UPTR_KVS_TYPE_KEY(type, key) \
		off_val->key = -1;
UPTR_KVS_LIST
#undef UPTR_KVS_TYPE_KEY
	}

	bpf_for(i, 0, umetadata_cnt) {
		off = i * sizeof(struct key_meta);
		if (off > PAGE_SIZE - sizeof(struct key_meta))
			break;

		kvs_umeta_key = kvs_umeta + off + offsetof(struct key_meta, key);
		kvs_umeta_off = kvs_umeta + off + offsetof(struct key_meta, off);

#define UPTR_KVS_TYPE_KEY(type, key) \
		if (off_val->key == -1 &&						\
		    !bpf_strncmp(kvs_umeta_key, UPTR_KVS_KEY_LEN, #key)) {		\
			off_val->key = *(short *)(kvs_umeta_off) + udata_off;		\
			if (off_val->key >= PAGE_SIZE)					\
				off_val->key = (off_val->key - PAGE_SIZE) | PAGE_IDX_MASK;		\
		}
UPTR_KVS_LIST
#undef UPTR_KVS_TYPE_KEY
	}
	return 0;
}

static int uptr_kvs_init(struct task_struct *task, struct uptr_kvs *kvs)
{
	kvs->off_val = bpf_task_storage_get(&offset_map, task, 0, 0);
	if (!kvs->off_val)
		return -1;

	kvs->kvs_val = bpf_task_storage_get(&uptr_kvs_map, task, 0, 0);
	if (!kvs->kvs_val)
		return -1;

	return 0;
}

#define uptr_kvs_is_set(kvs, key) (kvs.off_val->key != -1)

#define uptr_kvs_lookup(kvs, type, key)	\
	__uptr_kvs_lookup(&kvs, kvs.off_val->key, sizeof(type))
__always_inline void *__uptr_kvs_lookup(struct uptr_kvs *kvs, short cached_off, int size)
{
	short page_off, page_idx;

	if (cached_off == -1)
		return NULL;

	page_off = cached_off & ~PAGE_IDX_MASK;
	page_idx = !!(cached_off & PAGE_IDX_MASK);

	if (page_idx) {
		return (kvs->kvs_val->udata[1].page && page_off < PAGE_SIZE - size) ?
			(void *)kvs->kvs_val->udata[1].page + page_off : NULL;
	} else {
		return (kvs->kvs_val->udata[0].page && page_off < PAGE_SIZE - size) ?
			(void *)kvs->kvs_val->udata[0].page + page_off : NULL;
	}
}
