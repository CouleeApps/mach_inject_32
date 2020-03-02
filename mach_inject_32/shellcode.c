
typedef void *pthread_t;
typedef char pthread_attr_t[40];

typedef void *(__stdcall *pthread_start_t)(void *);
typedef int (__stdcall *pthread_create_from_mach_thread_t)(
	pthread_t *thread,
	const pthread_attr_t *attr,
	pthread_start_t start_routine,
	void *arg
);

pthread_create_from_mach_thread_t pthread_create_from_mach_thread = (pthread_create_from_mach_thread_t)0x41414141;
pthread_start_t start_thread = (pthread_start_t)0x42424242;

int main() {
//	__breakpoint();

	pthread_t thread;
	int ret = pthread_create_from_mach_thread(&thread, NULL, start_thread, NULL);

//	__breakpoint();

	while (ret == 0) {
		// Wait for death
	}

	// If we get here pthread_create failed and the process is going extremely down
	__breakpoint();
}
