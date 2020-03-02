
typedef void* pthread_t;
typedef char pthread_attr_t[40];

typedef void *(__stdcall *dlopen_t)(const char* path, int mode);
typedef void *(__stdcall *dlsym_t)(void *path, const char *symbol);

typedef int (__stdcall *pthread_create_t)(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg);
typedef int (__stdcall *pthread_join_t)(pthread_t thread, void **value_ptr);
typedef int (__stdcall *pthread_detach_t)(pthread_t thread);

dlopen_t dlopen = (dlopen_t)0x43434343;
dlsym_t dlsym = (dlsym_t)0x44444444;
const char *path = (const char *)0x30303030;
int mode = 2;
#define RTLD_DEFAULT -2

struct params_t {
	void *shellcode;
	void *user_info;
};

struct params_t params;

void *thread_fn(void *arg) {
//	__breakpoint();
	// If you do anything else this thread will die in dlopen
	// (Even if you do it *after* dlopen!)
	return dlopen(path, mode);
}

int main() {
//	__breakpoint();
	// When you get tired of resolving functions outside the shellcode
	pthread_create_t pthread_create = (pthread_create_t)dlsym((void*)RTLD_DEFAULT, "pthread_create");
	pthread_join_t pthread_join = (pthread_join_t)dlsym((void*)RTLD_DEFAULT, "pthread_join");
	pthread_detach_t pthread_detach = (pthread_detach_t)dlsym((void*)RTLD_DEFAULT, "pthread_detach");

	// We need to open stuff, but calling dlopen is really sketchy. So do it in another thread
	// whose sole job is to call dlopen and get outta there as fast as possible.
	// Also it returns the pointer to the module so we can dlsym() the entry point.
	pthread_t thread;
	int ret = pthread_create(&thread, NULL, thread_fn, NULL);
	void *lib;
	pthread_join(thread, &lib);

	// Find and jump to entry point of inject library
	void *(*entry)(void *) = (void*(*)(void *))dlsym(lib, "inj_entry");
	// Pass as argument the code pointer so it can find this thread (and the super janky
	// first thread) and kill us.
	params.shellcode = (void *)0x42424242;
	params.user_info = (void *)0x45454545;
	ret = pthread_create(&thread, NULL, entry, (void *)&params);
	pthread_detach(thread);

	while (ret == 0) {
		// "It's like getting sniped from a distance while having a seizure"
		// death().await
	}

	// If we get here pthread_create failed and we can't inject
	__breakpoint();
}

