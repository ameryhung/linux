#include <pthread.h>

#include <test_progs.h>
#include <bpf/btf.h>

#include "bpf_uptr_kv_store.h"
#include "test_uptr_kv_store_basic.skel.h"

struct test_struct {
	char data[PAGE_SIZE - 16];
};

uptr_kvs_type_var(int, value1);
uptr_kvs_type_var(int, value2);
uptr_kvs_type_var_algn(struct test_struct, blob, PAGE_SIZE);
uptr_kvs_key_type_var("test_basic_value3", int, value3);
uptr_kvs_key_type_var("test_basic_value4", int, value4);

static void run_prog_init(struct test_uptr_kv_store_basic *skel, int tid)
{
	skel->bss->target_tid = tid;
	(void)syscall(__NR_getuid);
	skel->bss->target_tid = -1;
}

static void run_prog_main(struct test_uptr_kv_store_basic *skel, int tid)
{
	skel->bss->target_tid = tid;
	(void)syscall(__NR_gettid);
	skel->bss->target_tid = -1;
}

void *test_uptr_kv_store_basic_thread(void* arg)
{
	struct test_uptr_kv_store_basic *skel = (struct test_uptr_kv_store_basic *)arg;
	int err, tid, map_fd;

	tid = gettid();

	map_fd = bpf_map__fd(skel->maps.uptr_kvs_map);
	err = uptr_kvs_init(map_fd);
	if (!ASSERT_OK(err, "bpf_uptr_kvs_init"))
		return NULL;

	value1 = 5;
	value2 = 6;
	value3 = 7;
	value4 = 8;

	run_prog_init(skel, tid);
	run_prog_main(skel, tid);

	ASSERT_EQ(skel->bss->test_value1, 5, "");
	ASSERT_EQ(skel->bss->test_value2, 6, "");
	ASSERT_EQ(skel->bss->test_value3, 7, "");
	ASSERT_EQ(skel->bss->test_value4, 8, "");

	pthread_exit(NULL);
}

static void test_uptr_kv_store_basic(void)
{
	struct test_uptr_kv_store_basic *skel;
	pthread_t thread1;
	int err, tid, map_fd;

	tid = gettid();

	skel = test_uptr_kv_store_basic__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	err = test_uptr_kv_store_basic__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		return;

	map_fd = bpf_map__fd(skel->maps.uptr_kvs_map);
	err = uptr_kvs_init(map_fd);
	if (!ASSERT_OK(err, "bpf_uptr_kvs_init"))
		return;

	value1 = 1;
	value2 = 2;
	value3 = 3;
	value4 = 4;

	err = pthread_create(&thread1, NULL, test_uptr_kv_store_basic_thread, skel);
	pthread_join(thread1, NULL);

	/* Make sure valueX are indeed local to threads */
	ASSERT_EQ(value1, 1, "");
	ASSERT_EQ(value2, 2, "");
	ASSERT_EQ(value3, 3, "");
	ASSERT_EQ(value4, 4, "");

	/* Run an initialization prog for a new thread */
	run_prog_init(skel, tid);
	/* Run main prog that read key-value pairs and save to global variables */
	run_prog_main(skel, tid);
	ASSERT_EQ(skel->bss->test_value1, 1, "");
	ASSERT_EQ(skel->bss->test_value2, 2, "");
	ASSERT_EQ(skel->bss->test_value3, 3, "");
	ASSERT_EQ(skel->bss->test_value4, 4, "");

	value1 = 0;
	value2 = 0;
	value3 = 0;
	value4 = 0;

	/* Run main prog that read key-value pairs and save to global variables */
	run_prog_main(skel, tid);
	ASSERT_EQ(skel->bss->test_value1, 0, "");
	ASSERT_EQ(skel->bss->test_value2, 0, "");
	ASSERT_EQ(skel->bss->test_value3, 0, "");
	ASSERT_EQ(skel->bss->test_value4, 0, "");

}

void test_uptr_kv_store(void)
{
	if (test__start_subtest("uptr_kv_store_basic"))
		test_uptr_kv_store_basic();
}
