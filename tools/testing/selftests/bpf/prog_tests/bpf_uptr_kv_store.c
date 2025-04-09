#include <fcntl.h>

#include <bpf/libbpf.h>

#include "bpf_uptr_kv_store.h"
#include "bpf_util.h"
#include "task_local_storage_helpers.h"

#define PIDFD_THREAD       O_EXCL

/* udata stores the values in thread local storage (TLS). The size is limited to
 * a page. Since UPTR KV store has no control of TLS allocation and alignment,
 * it is possible for udata of thread to span across two pages. Therefore, two
 * UPTRs are used to cover a udata region.
 *
 * To find the start of udata in each thread, insert a dummy symbol to udata.
 * Contructors generated for key-values pairs will figured out the offset from
 * the beginning of udata, the smallest address of values, to the dummy symbol.
 * Then, every thread can refer to the start of udata by subtracting the offset
 * from the address of the dummy symbol.
 */
static __thread struct udata_th_dummy {} uptr_kvs_udata_th_dummy SEC("udata");
static void *uptr_kvs_udata_start = (void *)-1UL;
static int uptr_kvs_udata_start_dummy_off;

/* umetadata contains up to 64 key-value pairs' metadata in a page shared by all
 * threads. It is allocated once for a process in the constructor and is aligned
 * with page boundries.
 */
static struct meta_page *uptr_kvs_umetadata;
static int uptr_kvs_umetadata_cnt = 0;
static bool uptr_kvs_umetadata_init = false;

static __thread bool uptr_kvs_th_inited = false;

void __uptr_kvs_var_init(const char *key, void *var)
{
	struct key_meta *km;

	uptr_kvs_umetadata_cnt++;

	if (!uptr_kvs_umetadata) {
		if (uptr_kvs_umetadata_cnt > 1)
			return;

		uptr_kvs_umetadata = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
		if (!uptr_kvs_umetadata)
			return;
	}

	if (var < uptr_kvs_udata_start) {
		uptr_kvs_udata_start = var;
		uptr_kvs_udata_start_dummy_off =
			(void *)&uptr_kvs_udata_th_dummy - uptr_kvs_udata_start;
	}

	km = &uptr_kvs_umetadata->meta[uptr_kvs_umetadata_cnt - 1];
	km->off = var - (void *)&uptr_kvs_udata_th_dummy;
	strncpy(km->key, key, UPTR_KVS_KEY_LEN);
}

int uptr_kvs_init(int uptr_kvs_map_fd)
{
	struct uptr_kvs_map_value map_val;
	unsigned long udata_start_page;
	int i, task_id, task_fd, err;

	if (!uptr_kvs_umetadata_cnt || uptr_kvs_th_inited)
		return 0;

	if (uptr_kvs_umetadata_cnt && !uptr_kvs_umetadata)
		return -ENOMEM;

	/* Constructors computes the offset from uptr_kvs_udata_th_dummy to each value
	 * and saves it in uptr_kvs_umetadata->meta[i].off. Now as all constructors have
	 * run and uptr_kvs_udata_start_dummy_off is known, adjust the offsets to be
	 * relative to the start of udata
	 */
	if (!uptr_kvs_umetadata_init) {
		for (i = 0; i < uptr_kvs_umetadata_cnt; i++)
			uptr_kvs_umetadata->meta[i].off -= uptr_kvs_udata_start_dummy_off;

		uptr_kvs_umetadata_init = true;
	}

	udata_start_page = ((unsigned long)&uptr_kvs_udata_th_dummy + uptr_kvs_udata_start_dummy_off) & PAGE_MASK;
	map_val.udata_off = ((unsigned long)&uptr_kvs_udata_th_dummy + uptr_kvs_udata_start_dummy_off) & ~PAGE_MASK;
	map_val.udata[0].page = (struct data_page *)(udata_start_page);
	map_val.udata[1].page = (struct data_page *)(udata_start_page + PAGE_SIZE);

	map_val.umetadata = uptr_kvs_umetadata;
	map_val.umetadata_cnt = uptr_kvs_umetadata_cnt;

	task_id = sys_gettid();
	task_fd = sys_pidfd_open(task_id, PIDFD_THREAD);

	err = bpf_map_update_elem(uptr_kvs_map_fd, &task_fd, &map_val, 0);
	if (err)
		return err;

	uptr_kvs_th_inited = true;
	return 0;
}
