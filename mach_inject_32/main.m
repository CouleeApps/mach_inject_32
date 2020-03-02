#import <AppKit/AppKit.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>

#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld_images.h>

#define STACK_SIZE 65536

// loosely based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a

#include "shellcode.h"

// Dyld shared cache structures
typedef struct {
	char     magic[16];
	uint32_t mappingOffset;
	uint32_t mappingCount;
	uint32_t imagesOffset;
	uint32_t imagesCount;
	uint64_t dyldBaseAddress;
	uint64_t codeSignatureOffset;
	uint64_t codeSignatureSize;
	uint64_t slideInfoOffset;
	uint64_t slideInfoSize;
	uint64_t localSymbolsOffset;
	uint64_t localSymbolsSize;
	char     uuid[16];
	// New addition for macOS Sierra
	char       sierra_reserved[0x30];
} dyld_cache_header;

typedef struct {
	uint64_t       address;
	uint64_t       size;
	uint64_t       file_offset;
	uint32_t       max_prot;
	uint32_t       init_prot;
} shared_file_mapping_np;

char *virtual_read(task_t task, mach_vm_address_t vmaddr, mach_vm_size_t length) {
	char *memory = (char *)malloc((size_t) length);
	mach_vm_offset_t output = (mach_vm_offset_t)memory;
	mach_vm_size_t outsize;
	kern_return_t ret;

	ret = mach_vm_read_overwrite(task, vmaddr, length, output, &outsize);

	if (ret != KERN_SUCCESS) {
		return NULL;
	}

	return (char *)output;
}

// https://blog.lse.epita.fr/articles/82-playing-with-mach-os-and-dyld.html
static char *find_lib32(task_t task, const char* name, char **shared_cache_base)
{
	// Get DYLD task infos
	struct task_dyld_info dyld_info;
	mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
	kern_return_t ret;
	ret = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
	if (ret != KERN_SUCCESS) {
		return NULL;
	}

	// Get image array's size and address
	struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)virtual_read(task, dyld_info.all_image_info_addr, dyld_info.all_image_info_size);
	uint32_t image_count = infos->infoArrayCount;
	struct dyld_image_info *image_array = (struct dyld_image_info *)virtual_read(task, (mach_vm_address_t)infos->infoArray, sizeof(struct dyld_image_info) * infos->infoArrayCount);
	*shared_cache_base = (char *)infos->sharedCacheBaseAddress;

	// Find our library among them
	for (int i = 0; i < image_count; ++i) {
		struct dyld_image_info *image = &image_array[i];

		char *namePath = (char *)virtual_read(task, (mach_vm_address_t)image->imageFilePath, 0x100);
		// Find our library's load address
		if (strstr(namePath, name)) {
			free(namePath);
			free(infos);
			free(image_array);
			return (char*)image->imageLoadAddress;
		}
		free(namePath);
	}

	free(infos);
	free(image_array);

	return NULL;
}

// https://gist.github.com/P1kachu/e6b14e92454a87b3f9c66b3163656d09
static uint32_t find_function32(task_t task, char *base, char *shared_cache_rx_base, const char *fnname)
{
	struct mach_header *base_header = (struct mach_header *)virtual_read(task, (mach_vm_address_t)base, sizeof(struct mach_header));
	uint32_t ncmds = base_header->ncmds;
	free(base_header);
	struct symtab_command *symcmd = NULL;

	mach_vm_address_t start = (mach_vm_address_t)(base + sizeof(struct mach_header));

	// Get symtab and dysymtab
	for (uint32_t i = 0; i < ncmds; ++i) {
		struct segment_command *cmd = (struct segment_command *)virtual_read(task, start, 0x100);

		if (cmd->cmd == LC_SYMTAB) {
			symcmd = (struct symtab_command*)cmd;
			break;
		}
		start += cmd->cmdsize;
		free(cmd);
	}

	mach_vm_address_t strtab_start = 0;
	mach_vm_address_t symtab_start = 0;
	uint64_t aslr_slide = 0;

	// If this library is in the shared cache then use that instead
	if (base >= shared_cache_rx_base) {
		dyld_cache_header *cache_header = (dyld_cache_header *)virtual_read(task, (mach_vm_address_t)shared_cache_rx_base, sizeof(dyld_cache_header));

		size_t rx_size = 0;
		size_t rw_size = 0;
		size_t rx_addr = 0;
		size_t ro_addr = 0;
		off_t ro_off = 0;

		for (int i = 0; i < cache_header->mappingCount; ++i) {
			shared_file_mapping_np *mapping = (shared_file_mapping_np *)virtual_read(task, (mach_vm_address_t)shared_cache_rx_base + cache_header->mappingOffset + sizeof(shared_file_mapping_np) * i, sizeof(shared_file_mapping_np));

			if (mapping->init_prot & VM_PROT_EXECUTE) {
				// Get size and address of [R-X] mapping
				rx_size = (size_t)mapping->size;
				rx_addr = (size_t)mapping->address;
			} else if (mapping->init_prot & VM_PROT_WRITE) {
				// Get size of [RW-] mapping
				rw_size = (size_t)mapping->size;
			} else if (mapping->init_prot == VM_PROT_READ) {
				// Get file offset of [R--] mapping
				ro_off = (size_t)mapping->file_offset;
				ro_addr = (size_t)mapping->address;
			}

			free(mapping);
		}

		free(cache_header);

		//sanity
		assert(rx_size != 0);
		assert(rw_size != 0);
		assert(rx_addr != 0);
		assert(ro_addr != 0);
		assert(ro_off != 0);

		// Can be determined by dyld_all_image_info->sharedCacheSlide but meh.
		aslr_slide = (uint64_t)shared_cache_rx_base - rx_addr;

		/*
		 * Previously 'shared_cache_base + symcmd->XXXX', but since there is some
		 * gap between each mapping, it would only work on Yosemite out of luck and
		 * segfault in Sierra. Uglier, but it works on both versions.
		 */
		char *shared_cache_ro = (char*)(ro_addr + aslr_slide);
		uint64_t stroff_from_ro = symcmd->stroff - rx_size - rw_size;
		uint64_t symoff_from_ro = symcmd->symoff - rx_size - rw_size;

		strtab_start = (mach_vm_address_t)(shared_cache_ro + stroff_from_ro);
		symtab_start = (mach_vm_address_t)(shared_cache_ro + symoff_from_ro);
	} else {
		aslr_slide = (uint64_t)base;
		strtab_start = (mach_vm_address_t)base + symcmd->stroff;
		symtab_start = (mach_vm_address_t)base + symcmd->symoff;
	}

	char *strtab = (char *)virtual_read(task, strtab_start, symcmd->strsize);
	struct nlist *symtab = (struct nlist *)virtual_read(task, symtab_start, symcmd->nsyms * sizeof(struct nlist));

	for (uint32_t i = 0; i < symcmd->nsyms; ++i){
		uint32_t strtab_off = symtab[i].n_un.n_strx;
		uint32_t func       = symtab[i].n_value;

		if(strcmp(&strtab[strtab_off], fnname) == 0) {
			free(strtab);
			free(symtab);
			return (uint32_t)func + aslr_slide;
		}
	}

	free(strtab);
	free(symtab);
	return 0;
}


uint32_t task_dlsym32(task_t task, pid_t pid, const char* libName, const char *fnName) {
	char *shared_cache_base;
	char *lib_base = find_lib32(task, libName, &shared_cache_base);
	if (lib_base == NULL) {
		return 0;
	}

	uint32_t fn_guest = find_function32(task, lib_base, shared_cache_base, fnName);

	return (uint32_t)fn_guest;
}


int inject(pid_t pid, const char *injectLib, const char *lib, const char *fn) {
	task_t remoteTask;

	struct stat buf;
	int rc = stat (lib, &buf);
	if (rc != 0)
	{
		fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
		return (-9);
	}

	struct stat buf2;
	int rc2 = stat (injectLib, &buf2);
	if (rc2 != 0)
	{
		fprintf (stderr, "Unable to open injectlib file %s (%s) - Cannot inject\n", injectLib, strerror (errno));
		return (-9);
	}

	mach_error_t kr = 0;

	/**
	 * Second - the critical part - we need task_for_pid in order to get the task port of the target
	 * pid. This is our do-or-die: If we get the port, we can do *ANYTHING* we want. If we don't, we're
	 * #$%#$%.
	 *
	 * In iOS, this will require the task_for_pid-allow entitlement. In OS X, this will require getting past
	 * taskgated, but root access suffices for that.
	 *
	 */
	kr = task_for_pid(mach_task_self(), pid, &remoteTask);
	if (kr != KERN_SUCCESS) {

		fprintf (stderr, "Unable to call task_for_pid on pid %d: %s. Cannot continue!\n",pid, mach_error_string(kr));
		return (-1);
	}




	/**
	 * From here on, it's pretty much straightforward -
	 * Allocate stack and code. We don't really care *where* they get allocated. Just that they get allocated.
	 * So, first, stack:
	 */
	mach_vm_address_t remoteStack = (vm_address_t) NULL;
	mach_vm_address_t remoteCode = (vm_address_t) NULL;
	kr = mach_vm_allocate( remoteTask, &remoteStack, STACK_SIZE, VM_FLAGS_ANYWHERE);

	if (kr != KERN_SUCCESS)
	{
		fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
		return (-2);
	}
	else
	{

		fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack);

	}
	/**
	 * Then we allocate the memory for the thread
	 */
	remoteCode = (vm_address_t) NULL;
	kr = mach_vm_allocate( remoteTask, &remoteCode, CODE_SIZE, VM_FLAGS_ANYWHERE);

	if (kr != KERN_SUCCESS)
	{
		fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
		return (-2);
	}


	/**
	 * Patch code before injecting: That is, insert correct function addresses (and lib name) into placeholders
	 *
	 * Since we use the same shared library cache as our victim, meaning we can use memory addresses from
	 * OUR address space when we inject..
	 */

	uint32_t injLibAddr = remoteCode + CODE_SIZE - 0x80;
	uint32_t injLibParamsAddr = remoteStack + STACK_SIZE * 3 / 4;
	kr = mach_vm_write(remoteTask, injLibAddr, (vm_offset_t)injectLib, strlen(injectLib) + 1);
	if (kr != KERN_SUCCESS) {
		return -2;
	}
	kr = mach_vm_write(remoteTask, injLibParamsAddr, (vm_offset_t)lib, strlen(lib) + 1);
	if (kr != KERN_SUCCESS) {
		return -2;
	}
	kr = mach_vm_write(remoteTask, injLibParamsAddr + strlen(lib) + 1, (vm_offset_t)fn, strlen(fn) + 1);
	if (kr != KERN_SUCCESS) {
		return -2;
	}

	struct remap {
		const char *search;
		uint32_t replace;
		int replace_count;
	};

	struct remap remaps[] = {
		{"0000", (uint32_t)injLibAddr, 0},
		{"AAAA", (uint32_t)task_dlsym32(remoteTask, pid, "libsystem_pthread.dylib", "_pthread_create_from_mach_thread"), 0},
		{"BBBB", (uint32_t)remoteCode + sc1_length, 0},
		{"CCCC", (uint32_t)task_dlsym32(remoteTask, pid, "libdyld.dylib", "_dlopen"), 0},
		{"DDDD", (uint32_t)task_dlsym32(remoteTask, pid, "libdyld.dylib", "_dlsym"), 0},
		{"EEEE", (uint32_t)injLibParamsAddr, 0},
	};

	char *possiblePatchLocation = (char*)(shellcode);
	for (int i = 0 ; i < sizeof(shellcode); i++)
	{
		possiblePatchLocation++;
		for (int j = 0; j < sizeof(remaps) / sizeof(*remaps); j ++) {
			if (memcmp(possiblePatchLocation, remaps[j].search, 4) == 0) {
				memcpy(possiblePatchLocation, &remaps[j].replace, 4);
				remaps[j].replace_count ++;
			}
		}
	}

	// Make sure we replaced one of everything
	for (int j = 0; j < sizeof(remaps) / sizeof(*remaps); j ++) {
		if (remaps[j].replace_count == 0) {
			fprintf(stderr, "Didn't find replacement for %s\n", remaps[j].search);
			return -3;
		}
	}

	/**
	 * Write the (now patched) code
	 */
	kr = mach_vm_write(remoteTask,                   // Task port
					   remoteCode,                 // Virtual Address (Destination)
					   (vm_address_t) shellcode,  // Source
					   sizeof(shellcode));                       // Length of the source



	if (kr != KERN_SUCCESS)
	{
		fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
		return (-3);
	}


	/*
	 * Mark code as executable - This also requires a workaround on iOS, btw.
	 */

	kr  = vm_protect(remoteTask, remoteCode, CODE_SIZE, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);

	/*
	 * Mark stack as writable  - not really necessary
	 */

	kr  = vm_protect(remoteTask, remoteStack, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);


	if (kr != KERN_SUCCESS)
	{
		fprintf(stderr,"Unable to set memory permissions for remote thread: Error %s\n", mach_error_string(kr));
		return (-4);
	}


	/**
	 *
	 * Create thread - This is obviously hardware specific.
	 *
	 */

	x86_thread_state32_t remoteThreadState;
	thread_act_t         remoteThread;

	bzero(&remoteThreadState, sizeof(remoteThreadState) );

	remoteStack += (STACK_SIZE / 2); // this is the real stack
	//remoteStack64 -= 8;  // need alignment of 16

	const char* p = (const char*) remoteCode;
	remoteThreadState.__eip = (u_int32_t) (vm_address_t) remoteCode;

	// set remote Stack Pointer
	remoteThreadState.__esp = (u_int32_t) remoteStack;
	remoteThreadState.__ebp = (u_int32_t) remoteStack;

	printf ("Remote Stack  0x%llx, Remote code is %p\n", remoteStack, p );

	/*
	 * create thread and launch it in one go
	 */
	kr = thread_create_running( remoteTask, x86_THREAD_STATE32,
							   (thread_state_t) &remoteThreadState, x86_THREAD_STATE32_COUNT, &remoteThread );

	if (kr != KERN_SUCCESS) { fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
		return (-3); }

	return (0);

} // end injection code



int main(int argc, const char * argv[])
{
	if (argc < 5)
	{
		fprintf (stderr, "Usage: %s <bundle id> <libinjlib.dylib> <library> <function>\n", argv[0]);
		fprintf (stderr, "   <library>: path to a dylib on disk\n");
		fprintf (stderr, "   <function>: name of function in dylib\n");
		exit(0);
	}
	pid_t pid = 0; // atoi(argv[1]);

	@autoreleasepool {
		NSArray *apps = [NSRunningApplication runningApplicationsWithBundleIdentifier:[NSString stringWithUTF8String:argv[1]]];
		if (apps.count == 0) {
			fprintf(stderr, "Cannot find running application\n");
			return 1;
		}
		NSRunningApplication *app = (NSRunningApplication *)apps[0];
		pid = app.processIdentifier;

		int rc = inject(pid, argv[2], argv[3], argv[4]);
		if (rc != 0) {
			fprintf(stderr, "Error injecting: %d", rc);
		}
	}

}
