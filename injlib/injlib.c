//
//  injlib.cpp
//  injlib
//
//  Created by Glenn Smith on 2/28/20.
//  Copyright © 2020 Plaintext. All rights reserved.
//

#include <mach/mach.h>
#include <mach/task.h>
#include <stdio.h>
#include <dlfcn.h>

struct params_t {
	void *shellcode;
	void *user_info;
};

void inj_entry(struct params_t *params) {
	printf("Start! %p %p %p\n", params, params->shellcode, params->user_info);

	// The janky threads are going to be somewhere in this page
	// thread_start is a pointer to the start address of one of them
	uint32_t hack_page = (uint32_t)params->shellcode & ~(0xFFF);

	// Find all the currently running threads
	printf("Activate! Thread start at %p\n", params->shellcode);
	thread_act_array_t thread_list;
	mach_msg_type_number_t list_count;
	kern_return_t err = task_threads(mach_task_self_, &thread_list, &list_count);
	if (err != KERN_SUCCESS) {
		printf("Could not get threads: %s\n", mach_error_string(err));
		return;
	}

	for (int i = 0; i < list_count; i ++) {
		thread_act_t thread = thread_list[i];
		if (thread == mach_thread_self()) {
			printf("We are thread %d\n", i);
			continue;
		}

		// Find where this thread is at
		x86_thread_state32_t old_state;
		mach_msg_type_number_t state_count = x86_THREAD_STATE32_COUNT;
		err = thread_get_state(thread, x86_THREAD_STATE32, (thread_state_t)&old_state, &state_count);

		if (err != KERN_SUCCESS) {
			printf("Could not get thread info for thread %d: %s\n", i, mach_error_string(err));
			return;
		}

		// If this is one of the janky threads, kill it (gently)
		if ((old_state.__eip & ~(0xFFF)) == hack_page) {
			printf("Janky thread %d eip 0x%08u (start is 0x%08u)\n", i, old_state.__eip, hack_page);
			// If you don't suspend the thread before terminating it, the Finder will Find you in your sleep
			thread_suspend(thread);
			thread_terminate(thread);
		}
	}

	const char *lib_path = (const char *)params->user_info;
	const char *lib_fn = lib_path + strlen(lib_path) + 1;

	printf("Loading %s\n", lib_path);
	void *lib = dlopen(lib_path, RTLD_NOW);

	printf("Loaded at %p\n", lib);
	void (*fn)(void) = (void(*)(void))dlsym(lib, lib_fn);

	printf("Running %s::%s() at %p\n", lib_path, lib_fn, fn);
	if (fn != NULL) {
		fn();
	}
}
