#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

struct file_node {
	int file_desc;
	struct list_elem file_elem;
	struct file *f;
};

static struct lock file_lock;

static void syscall_handler(struct intr_frame *);

void *check_safe_access(int *esp);

void make_thread_exit(int status_code);

bool is_valid_buffer(int *ptr, int size);

static struct file_node * get_file(int fd);

static int file_descriptor = 2;

static int increment_file_descriptor() {
    return file_descriptor++;
}

static struct file_node *
get_file(int fd) {
	struct file_node *f_node = NULL;
	struct thread *t = thread_current();
	for (struct list_elem * i = list_begin(&t -> thread_files_list);
			i != list_end(&t -> thread_files_list); i = list_next(i)) {
		f_node = list_entry(i, struct file_node, file_elem);
		if((f_node -> file_desc)== file_descriptor)
			return f_node;
	}
	return f_node;
}

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&file_lock);
}

bool is_valid_buffer(int *ptr, int size) {
    for (int *i = ptr; i < ptr + size; i++) {
        if (!check_safe_access(i)) {
            return false;
        }
    }
    return true;
}

static void
syscall_handler(struct intr_frame *f) {
    //printf ("system call!\n");
    int *stack_ptr = f->esp;
    if (!check_safe_access(stack_ptr)) {
        // Kill the process , need to check this
        make_thread_exit(-1);
    } else {
        int syscall = *(int *) (stack_ptr);
        if (syscall == SYS_HALT) {
            //printf("In SYS_HALT implementaion\n");
            shutdown_power_off();
        }
        if (syscall == SYS_EXIT) {
            //printf("In System wait implementaion\n");
            if (!check_safe_access(stack_ptr + 1)) {
                make_thread_exit(-1);
            }
            struct thread *t = thread_current();
            for (;!list_empty(&t -> thread_files_list); ) {
            	struct list_elem * i = list_begin(&t -> thread_files_list);
            	struct file_node *f_node = list_entry(i, struct file_node, file_elem);
            	list_remove(&f_node->file_elem);
				file_close(f_node -> f);
				free(f_node);
            }
            int arg0 = *(int *) ((stack_ptr) + 1);
            make_thread_exit(arg0);
        }
        if (syscall == SYS_EXEC) {
            //printf("In SYS_EXEC implementaion\n");
            if (!check_safe_access(*(stack_ptr + 1))) {
                make_thread_exit(-1);
            }
            char *file_name = (char *) *(uintptr_t * )(stack_ptr + 1);
            if (!file_name) {
				make_thread_exit(-1);
			}
            f -> eax = process_execute(file_name);
        }
        if (syscall == SYS_WAIT) {
            //printf("In SYS_WAIT implementaion\n");
        	if (!check_safe_access(*(stack_ptr + 1))) {
				make_thread_exit(-1);
			}
        	int arg0 = *(int *) ((stack_ptr) + 1); // Fd
        	f -> eax = process_wait (arg0);
        	;//f -> eax = process_wait (tid_t child_);
        }
        if (syscall == SYS_CREATE) {
            //printf("In SYS_CREATE implementaion\n");
            if (!check_safe_access(*(stack_ptr + 1))) {
                make_thread_exit(-1);
            }
            char *file_name = (char *) *(uintptr_t * )(stack_ptr + 1);
            int arg1 = *(int *) ((stack_ptr) + 2);
            if (!file_name) {
                make_thread_exit(-1);
            }
            f->eax = filesys_create(file_name, (unsigned) arg1);
        }
        if (syscall == SYS_REMOVE) {
            //printf("In SYS_REMOVE implementaion\n");
            if (!check_safe_access(*(stack_ptr + 1))) {
                make_thread_exit(-1);
            }
            char *file_name = (char *) *(uintptr_t * )(stack_ptr + 1);
            int arg1 = *(int *) ((stack_ptr) + 2);
            if (!file_name) {
                make_thread_exit(-1);
            }
            f->eax = filesys_remove(file_name);
        }
        if (syscall == SYS_OPEN) {
            //printf("In SYS_OPEN implementaion\n");
        	f->eax = -1;
        	if (!check_safe_access(*(stack_ptr + 1))) {
            	make_thread_exit(-1);
            }
            char *file_name = (char *) *(uintptr_t * )(stack_ptr + 1);
            int arg1 = *(int *) ((stack_ptr) + 2);
            if (!file_name) {
                make_thread_exit(-1);
            }
            struct file *file_opened = filesys_open(file_name);
            if (file_opened) {
                struct thread *t = thread_current();
                struct file_node *f_node = (struct file_node *)malloc( sizeof(struct file_node));
				f_node -> file_desc = increment_file_descriptor();
				f_node -> f = file_opened;
				list_push_back(&t -> thread_files_list, &f_node -> file_elem);
				f->eax = f_node -> file_desc;
            }
        }
        if (syscall == SYS_FILESIZE) {
            //printf("In SYS_FILESIZE implementaion\n");
        	int arg0 = *(int *) ((stack_ptr) + 1); // Fd
        	struct file_node *f_node = get_file(arg0);
        	f -> eax = -1;
        	if(f_node) {
        		f -> eax = file_length(f_node -> f);
        	}
        }
        if (syscall == SYS_READ) {
            // printf("In SYS_READ implementaion\n");
            int fd = *(int *) ((stack_ptr) + 1); // Fd - arg0
            int block = *(int *) ((stack_ptr) + 2); // block - arg1
            unsigned block_size = *(unsigned *) ((stack_ptr) + 3); // block size - arg2
            f->eax = -1;
            //lock_acquire(&file_lock);
            if (fd == STDIN_FILENO) {
                f->eax = input_getc();
            } else {
            	if (!check_safe_access(*(stack_ptr + 2))) {
					make_thread_exit(-1);
				}
            	struct file_node *f_node = get_file(fd);
            	if(f_node) {
            		f->eax = file_read(f_node -> f, block, block_size);
            	}
            }
            //lock_release(&file_lock);
        }
        if (syscall == SYS_WRITE) {
            //printf("In System Write Implementation\n");
            // Expect 2 arguments
        	int fd = *(int *) ((stack_ptr) + 1); // Fd - arg0
			int block = *(int *) ((stack_ptr) + 2); // block - arg1
			unsigned block_size = *(unsigned *) ((stack_ptr) + 3); // block size - arg2
            // Validate that arg2 is a valid address and that all addresses in the allocated buffer are valid.
            if (!check_safe_access(stack_ptr + 2) && is_valid_buffer(stack_ptr + 2, block_size)) {
                make_thread_exit(-1);
            }
            f->eax = -1;
            if (fd == STDOUT_FILENO) {
                putbuf((char *) block, block_size);
                f->eax = block_size;
            } else {
            	if (!check_safe_access(*(stack_ptr + 2))) {
					make_thread_exit(-1);
				}
            	struct file_node *f_node = get_file(fd);
            	if(f_node) {
            		f->eax = file_write(f_node -> f, block, block_size);
            	}
                //if (!check_safe_access(*(stack_ptr + 2))) {
                  //  make_thread_exit(-1);
                //}
                //f->eax = file_write (struct file *file, const void *buffer, off_t size);
            }
        }
        if (syscall == SYS_SEEK) {
            //printf("In SYS_SEEK implementaion\n");
            int arg0 = *(int *) ((stack_ptr) + 1); // Fd
            unsigned arg1 = *(unsigned *) ((stack_ptr) + 2); // new_position
            struct file_node *f_node = get_file(arg0);
			f -> eax = -1;
			if(f_node) {
				file_seek(f_node -> f, arg1);
				f -> eax = 0;
			}
        }
        if (syscall == SYS_TELL) {
            //printf("In SYS_TELL implementaion\n");
            int arg0 = *(int *) ((stack_ptr) + 1); // Fd
            struct file_node *f_node = get_file(arg0);
			f -> eax = -1;
			if(f_node) {
				f -> eax = file_tell(f_node -> f);
			}
        }
        if (syscall == SYS_CLOSE) {
            //printf("In SYS_CLOSE implementaion\n");
            int arg0 = *(int *) ((stack_ptr) + 1); // Fd
            f -> eax = -1;
            struct file_node *f_node = get_file(arg0);
            if (f_node) {
            	list_remove(&f_node->file_elem);
				file_close(f_node -> f);
				free(f_node);
	            f -> eax = 0;
            }
        }
    }
    // thread_exit ();
}

/*Check whether if it's safe to access the memory based on the 3 conditions
    1. Check if it's a Null Pointer
    2/ If it is referencing above PHYS_BASE
    3. Check for Unmapped Memory
    If any one of the above is true, then we need to kill the process
  */

void *check_safe_access(int *esp) {
    void *stack_ptr = NULL;
    if (!(esp)) {
        return 0;
    } else if (!(is_user_vaddr(esp))) {
        return 0;
    } else if (!(stack_ptr = pagedir_get_page(thread_current()->pagedir, esp))) {
        return 0;
    }
    return esp;
}

void
make_thread_exit(int status_code) {
    struct thread *t = thread_current();
    t->exit_code = status_code;
    thread_exit();
}
