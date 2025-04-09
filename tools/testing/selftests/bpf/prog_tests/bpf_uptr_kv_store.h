#ifndef __BPF_UPTR_KV_STORE_H__
#define __BPF_UPTR_KV_STORE_H__

#include <errno.h>
#include <stdio.h>

#include <bpf/bpf.h>

#include "bpf_uptr_kv_store_common.h"

#define SEC(name) __attribute__((section(name), used))

void __uptr_kvs_var_init(const char *key, void *var);

/**
 * @brief uptr_kvs_key_type_var() declares a key-value pair. The value will be
 * a thread local variable which user space programs can directly read/write,
 * while bpf programs will need to lookup the data with the string key.
 *
 * @param key The string key the value will be associated with. The string will
 * be truncated if the length exceeds UPTR_KVS_KEY_LEN.
 * @param type The type of the value
 * @param var The variable name of the value
 */
#define uptr_kvs_key_type_var(key, type, var)	\
__thread type var SEC("udata");			\
						\
__attribute__((constructor))			\
void var##_init(void)				\
{						\
	__uptr_kvs_var_init(key, &var);		\
}

#define uptr_kvs_key_type_var_algn(key, type, var, algn)	\
__thread type var SEC("udata") __attribute__((aligned(algn)));	\
								\
__attribute__((constructor))					\
void var##_init(void)						\
{								\
	__uptr_kvs_var_init(key, &var);				\
}

/**
 * @brief uptr_kvs_key_type_var() declares a key-value pair. The value will be
 * a thread local variable which user space programs can directly read/write,
 * while bpf programs will need to lookup the data with the string key same as
 * the variable name.
 *
 * @param type The type of the value
 * @param var The variable name of the value as well as key the value will be
 * associated with. The key string will be truncated if the length exceeds
 * UPTR_KVS_KEY_LEN.
 */
#define uptr_kvs_type_var(type, var) \
uptr_kvs_key_type_var(#var, type, var)

#define uptr_kvs_type_var_algn(type, var, algn) \
uptr_kvs_key_type_var_algn(#var, type, var, algn)

/**
 * @brief uptr_kvs_init() initializes a KV store for the current task.
 *
 * @param uptr_kvs_map_fd The file descriptor of the UPTR KV store task local
 * storage map.
 */
int uptr_kvs_init(int uptr_kvs_map_fd);

#endif
