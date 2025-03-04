#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define UPTR_KVS_LIST \
	UPTR_KVS_TYPE_KEY(int, value1) \
	UPTR_KVS_TYPE_KEY(int, value2) \
	UPTR_KVS_TYPE_KEY(int, test_basic_value3) \
	UPTR_KVS_TYPE_KEY(int, test_basic_value4)

#include "bpf_uptr_kv_store.h"

pid_t target_tid = 0;
int test_value1 = 0;
int test_value2 = 0;
int test_value3 = 0;
int test_value4 = 0;

SEC("tp/syscalls/sys_enter_getuid")
int prog_test(void *ctx)
{
	struct task_struct *task;
	int err;

	task = bpf_get_current_task_btf();
	if (task->pid != target_tid)
		return 0;

	err = uptr_kvs_cache_offset(task);
	if (err)
		return err;
	return 0;
}

SEC("tp/syscalls/sys_enter_gettid")
int prog_main(void *ctx)
{
	struct task_struct *task;
	struct uptr_kvs kvs;
	int err, *int_p;

	task = bpf_get_current_task_btf();
	if (task->pid != target_tid)
		return 0;

	err = uptr_kvs_init(task, &kvs);
	if (err)
		return 0;

	int_p = uptr_kvs_lookup(kvs, int, value1);
	if (int_p)
		test_value1 = *int_p;

	int_p = uptr_kvs_lookup(kvs, int, value2);
	if (int_p)
		test_value2 = *int_p;

	int_p = uptr_kvs_lookup(kvs, int, test_basic_value3);
	if (int_p)
		test_value3 = *int_p;

	int_p = uptr_kvs_lookup(kvs, int, test_basic_value4);
	if (int_p)
		test_value4 = *int_p;

	return 0;
}

char _license[] SEC("license") = "GPL";

