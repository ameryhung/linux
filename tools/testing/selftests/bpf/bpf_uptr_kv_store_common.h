#ifndef __BPF_UPTR_KV_STORE_COMMON_H__
#define __BPF_UPTR_KV_STORE_COMMON_H__

#ifdef __BPF__
struct data_page *dummy_data_page;
struct meta_page *dummy_meta_page;
#else
#define __uptr
#endif

#define UPTR_KVS_KEY_LEN 62
#define PAGE_SIZE 4096
#define PAGE_MASK (~(PAGE_SIZE - 1))

struct data_page {
	char data[PAGE_SIZE];
};

struct data_page_entry {
	struct data_page __uptr *page;
};

struct key_meta {
	char key[UPTR_KVS_KEY_LEN];
	short off;
};

struct meta_page {
	struct key_meta meta[64];
};

struct uptr_kvs_map_value {
	struct data_page_entry udata[2];
	struct meta_page __uptr *umetadata;
	short umetadata_cnt;
	short udata_off;
};

#endif
