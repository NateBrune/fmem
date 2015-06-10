/* 
 *  This module creates /dev/fmem device,
 *  that can be used for dumping physical memory,
 *  without limits of /dev/mem (1MB/1GB, depending on distribution)
 *  
 *  Tested only on i386, feel free to test it on 
 *  different arch.
 *  cloned from 
 *  linux/drivers/char/mem.c (so GPL license apply)
 *
 *  2009-2011, niekt0@hysteria.sk
 */

/*
 * BUGS: if you do something like # dd if=/dev/fmem of=dump 
 *       dd will not stop, even if there is no more physical RAM
 *       on the system.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/raw.h>
#include <linux/tty.h>
#include <linux/ptrace.h>
#include <linux/device.h>
#include <linux/highmem.h>
#include <linux/bootmem.h>
#include <linux/pfn.h>
#include <linux/version.h>

#include "debug.h"

#ifdef CONFIG_IA64
# include <linux/efi.h>
#endif


// this is major number used for our new dumping device.
// 241 should be in free range 
// In future maybe I should request number dynamically
#define FMEM_MAJOR 241
#define FMEM_MINOR 1

MODULE_LICENSE("GPL");

//dirty global variables;

// function page_is_ram is not exported 
// for modules, but is available in kallsyms.
// So we need determine this address using dirty tricks
int (*guess_page_is_ram)(unsigned long pagenr);


// when parsing addresses trough parameters
unsigned long a1=0;
module_param(a1,ulong,0); //a1 is addr of page_is_ram function


/// Char we show before each debug print
const char program_name[] = "fmem";


/* Own implementation of xlate_dev_mem_ptr
 * (so we can read highmem and other)
 * 
 * Input:  physical address
 * Output: pointer to virtual address where requested 
 *         physical address is mapped
 */

void *my_xlate_dev_mem_ptr(unsigned long phys)
{

	void *addr=NULL;
	unsigned long start = phys & PAGE_MASK;
	unsigned long pfn = PFN_DOWN(phys);

        /* If page is RAM, we can use __va. Otherwise ioremap and unmap. */
        if ((*guess_page_is_ram)(start >> PAGE_SHIFT)) {

		if (PageHighMem(pfn_to_page(pfn))) {
                /* The buffer does not have a mapping.  Map it! */

		        addr = kmap(pfn_to_page(pfn));	
			return addr;
		}
		return __va(phys);
	}

	// Not RAM, so it is some device (can be bios for example)
	addr = (void __force *)ioremap_nocache(start, PAGE_SIZE);
	if (addr)
		addr = (void *)((unsigned long)addr | (phys & ~PAGE_MASK));
	return addr;
}

// Our own implementation of unxlate_dev_mem_ptr
// (so we can read highmem and other)
void my_unxlate_dev_mem_ptr(unsigned long phys,void *addr)
{
	unsigned long pfn = PFN_DOWN(phys); //get page number

	/* If page is RAM, check for highmem, and eventualy do nothing. 
	   Otherwise need to iounmap. */
	if ((*guess_page_is_ram)(phys >> PAGE_SHIFT)) {
	
		if (PageHighMem(pfn_to_page(pfn))) { 
		/* Need to kunmap kmaped memory*/
		        kunmap(pfn_to_page(pfn));
			//dbgprint ("unxlate: Highmem detected");
		}
		return;
	}
	
	// Not RAM, so it is some device (can be bios for example)
	iounmap((void __iomem *)((unsigned long)addr & PAGE_MASK));

}


/*-- original (stripped) linux/drivers/char/mem.c starts here ---
   only one mem device (fmem) was left
   only read operation is supported
   some not necessary pieces may survived, feel free to clean them
  --------------------------------------------------------------*/

/*
 * Architectures vary in how they handle caching for addresses
 * outside of main memory.
 *
 */
static inline int uncached_access(struct file *file, unsigned long addr)
{
#if defined(CONFIG_IA64)
	/*
	 * On ia64, we ignore O_SYNC because we cannot tolerate memory attribute aliases.
	 */
	return !(efi_mem_attributes(addr) & EFI_MEMORY_WB);
#elif defined(CONFIG_MIPS)
	{
		extern int __uncached_access(struct file *file,
					     unsigned long addr);

		return __uncached_access(file, addr);
	}
#else
	/*
	 * Accessing memory above the top the kernel knows about or through a file pointer
	 * that was marked O_SYNC will be done non-cached.
	 */
	if (file->f_flags & O_SYNC)
		return 1;
	return addr >= __pa(high_memory);
#endif
}

/*
 * This function reads the *physical* memory. The f_pos points directly to the 
 * memory location. 
 */
static ssize_t read_mem(struct file * file, char __user * buf,
			size_t count, loff_t *ppos)
{
	unsigned long p = *ppos;
	ssize_t read, sz;
	char *ptr;

//	if (!valid_phys_addr_range(p, count))  //good bye;)
//		return -EFAULT;
//	XXX solve here problem of RAM maximum?
	
	read = 0;
#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
	/* we don't have page 0 mapped on sparc and m68k.. */
	if (p < PAGE_SIZE) {
		sz = PAGE_SIZE - p;
		if (sz > count) 
			sz = count; 
		if (sz > 0) {
			if (clear_user(buf, sz))
				return -EFAULT;
			buf += sz; 
			p += sz; 
			count -= sz; 
			read += sz; 
		}
	}
#endif

	while (count > 0) {
		/*
		 * Handle first page in case it's not aligned
		 */
		if (-p & (PAGE_SIZE - 1))
			sz = -p & (PAGE_SIZE - 1);
		else
			sz = PAGE_SIZE;

		sz = min_t(unsigned long, sz, count);

		/*
		 * On ia64 if a page has been mapped somewhere as
		 * uncached, then it must also be accessed uncached
		 * by the kernel or data corruption may occur
		 */
		ptr = my_xlate_dev_mem_ptr(p);

		if (!ptr){
			dbgprint ("xlate FAIL, p: %lX",p);
			return -EFAULT;
		}

		if (copy_to_user(buf, ptr, sz)) {
			dbgprint ("copy_to_user FAIL, ptr: %p",ptr);
			my_unxlate_dev_mem_ptr(p, ptr);
			return -EFAULT;
		}

		my_unxlate_dev_mem_ptr(p, ptr);

		buf += sz;
		p += sz;
		count -= sz;
		read += sz;
	}

	*ppos += read;
	return read;
}

static ssize_t write_mem(struct file * file, const char __user * buf, 
			 size_t count, loff_t *ppos)
{
	return 0;
}

#ifndef CONFIG_MMU
static unsigned long get_unmapped_area_mem(struct file *file,
					   unsigned long addr,
					   unsigned long len,
					   unsigned long pgoff,
					   unsigned long flags)
{
	if (!valid_mmap_phys_addr_range(pgoff, len))
		return (unsigned long) -EINVAL;
	return pgoff << PAGE_SHIFT;
}

/* can't do an in-place private mapping if there's no MMU */
static inline int private_mapping_ok(struct vm_area_struct *vma)
{
	return vma->vm_flags & VM_MAYSHARE;
}
#else
#define get_unmapped_area_mem	NULL

static inline int private_mapping_ok(struct vm_area_struct *vma)
{
	return 1;
}
#endif

static int mmap_mem(struct file * file, struct vm_area_struct * vma)
{
	return 0;
}

/*
 * The memory devices use the full 32/64 bits of the offset, and so we cannot
 * check against negative addresses: they are ok. The return value is weird,
 * though, in that case (0).
 *
 * also note that seeking relative to the "end of file" isn't supported:
 * it has no meaning, so it returns -EINVAL.
 */
static loff_t memory_lseek(struct file * file, loff_t offset, int orig)
{
	loff_t ret;

//Older kernels (<20) uses f_dentry instead of f_path.dentry
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	mutex_lock(&file->f_dentry->d_inode->i_mutex);
#else
	mutex_lock(&file->f_path.dentry->d_inode->i_mutex);
#endif 

	switch (orig) {
		case 0:
			file->f_pos = offset;
			ret = file->f_pos;
			force_successful_syscall_return();
			break;
		case 1:
			file->f_pos += offset;
			ret = file->f_pos;
			force_successful_syscall_return();
			break;
		default:
			ret = -EINVAL;
	}
//Older kernels (<20) uses f_dentry instead of f_path.dentry
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	mutex_unlock(&file->f_dentry->d_inode->i_mutex);
#else
	mutex_unlock(&file->f_path.dentry->d_inode->i_mutex);
#endif 

	return ret;
}

static int open_port(struct inode * inode, struct file * filp)
{
	return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}

#define full_lseek      null_lseek
#define read_full       read_zero
#define open_mem	open_port
#define open_fmem	open_port

static const struct file_operations mem_fops = {
	.llseek		= memory_lseek,
	.read		= read_mem,
	.write		= write_mem,
	.mmap		= mmap_mem,
	.open		= open_mem,
	.get_unmapped_area = get_unmapped_area_mem,
};

static int memory_open(struct inode * inode, struct file * filp)
{
	// no more kernel locking,
	// let's hope it is safe;)
	int ret = 0;

	switch (iminor(inode)) {
		case 1:
			filp->f_op = &mem_fops;

//Older kernels (<19) does not have directly_mappable_cdev_bdi
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#else
			filp->f_mapping->backing_dev_info =
				&directly_mappable_cdev_bdi;
#endif 
			break;

		default:
			return -ENXIO;
	}
	if (filp->f_op && filp->f_op->open)
		ret = filp->f_op->open(inode,filp);
	return ret;
}

static const struct file_operations memory_fops = {
	.open		= memory_open,	/* just a selector for the real open */
};

static const struct {
	unsigned int		minor;
	char			*name;
	umode_t			mode;
	const struct file_operations	*fops;
} devlist[] = { /* list of minor devices */
	{1, "fmem",     S_IRUSR | S_IWUSR | S_IRGRP, &mem_fops},
};

static struct class *mem_class;


// This function actually creates device itself.
static int __init chr_dev_init(void)
{
	int i;

	if (register_chrdev(FMEM_MAJOR,"fmem",&memory_fops))
		printk("unable to get major %d for memory devs\n", FMEM_MAJOR);

	mem_class = class_create(THIS_MODULE, "fmem");
	for (i = 0; i < ARRAY_SIZE(devlist); i++){

//Older kernels have one less parameter
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
		device_create(mem_class, NULL,MKDEV(FMEM_MAJOR, devlist[i].minor), devlist[i].name);
#else
		device_create(mem_class, NULL,MKDEV(FMEM_MAJOR, devlist[i].minor), NULL, devlist[i].name);
#endif 
	}

	return 0;
}


#if 0
/* Function that gets addresses for functions, we need for /dev/fmem.
   (page_is_ram)

   Change implementation, if you need. 
   version 1.- Use func_callback on => 2.6.30 (the best method)
   version 2.- Implement searching in /proc/kallsyms from kernel mode (ble)
   version 3.- Get values by yourself, and give them to module as parameters. (actual)
 */

//----------------------------------------------------------------------------------
/* 1.version
This works only on 2.6.30 and newer, so cannot be used in general;(
But does not require ugly /proc/kallsyms hack.
*/

//	kallsyms_on_each_symbol(func_callback,NULL); 

static int func_callback(void *data, const char *name, struct module *module, unsigned long addr) 
{
	if (strcmp(name,"page_is_ram") == 0 && module == NULL) {
		guess_page_is_ram = (void *)addr;
		dbgprint ("set guess_page_is_ram: %p, %p",guess_page_is_ram, module);
	}
	if (strcmp(name,"unxlate_dev_mem_ptr") == 0 && module == NULL){
                guess_unxlate_dev_mem_ptr = (void *)addr;
		dbgprint ("set guess_unxlate_dev_mem_ptr: %p, %p",guess_unxlate_dev_mem_ptr,module);
        }
	return 0;
}

#endif


int find_symbols(void) 
{
/*      3.version, take addresses from command line */

	guess_page_is_ram=(void *)a1;
	dbgprint ("set guess_page_is_ram: %p",guess_page_is_ram);

	return 0;
}

/// Function executed upon loading module
int __init
init_module (void)
{

	dbgprint("init");	
	find_symbols(); 

	// Create device itself (/dev/fmem)
	chr_dev_init();  

	return 0;
}

/// Function executed when unloading module
void __exit
cleanup_module (void)
{
	
	dbgprint ("destroying fmem device");
	
	// Clean up
	unregister_chrdev(FMEM_MAJOR, "fmem");
	device_destroy(mem_class, MKDEV(FMEM_MAJOR, FMEM_MINOR));
	class_destroy(mem_class);

	dbgprint ("exit");

}
