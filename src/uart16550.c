// uart16550.c - UART Driver
//  */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/kfifo.h>
#include <linux/moduleparam.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>

#include "uart16550.h"

MODULE_DESCRIPTION("UART DRIVER");
MODULE_AUTHOR("Veliscu Robert-Valentin <robert.veliscu@stud.acs.upb.ro");
MODULE_LICENSE("GPL");

#define LOG_LEVEL	KERN_INFO

#define DEFAULT_MAJOR		42
#define MODULE_NAME		"uart16550"
#define IRQ_COM1			4
#define IRQ_COM2			3

#ifndef KFIFO_SIZE
#define KFIFO_SIZE		1024
#endif

struct uart_device_data {
	struct cdev cdev;
	size_t size;
	int com_id;
	atomic_t access;
	wait_queue_head_t wq_rx; // in laborator scrie ca se declara altcumva cu macro
	wait_queue_head_t wq_tx;
	DECLARE_KFIFO(kfifo_rx, char, KFIFO_SIZE); //banuiesc ca le declar statice si nu stau sa le aloc dinamic. mai vedem!
	DECLARE_KFIFO(kfifo_tx, char, KFIFO_SIZE);
};

struct uart_device_data devs[MAX_NUMBER_DEVICES];

static int port_addr[] = {0x3f8, 0x2f8};

static int major = DEFAULT_MAJOR;
static int option = OPTION_BOTH;
static int num_minors = 1;

module_param(major, int, 0);
MODULE_PARM_DESC(major, "The major needed for device registering");
module_param(option, int, 0);
MODULE_PARM_DESC(option, "Which serial ports");

static int uart_open(struct inode *inode, struct file *file)
{
	struct uart_device_data *data;
	printk(LOG_LEVEL "open called!\n");
	data = container_of(inode->i_cdev, struct uart_device_data, cdev);

	if (atomic_cmpxchg(&data->access, 0, 1) != 0)
		return -EBUSY;

	file->private_data = data;

	
	// configure FCR - registru din datasheet
	// set_current_state(TASK_INTERRUPTIBLE); nush daca trebuie???
	return 0;
}

static int
uart_release(struct inode *inode, struct file *file)
{
	printk(LOG_LEVEL "close called!\n");
	struct uart_device_data *data =
	(struct uart_device_data *) file->private_data;
	atomic_set(&data->access, 0);
	return 0;
}

static ssize_t
uart_read(struct file *file,
		char __user *user_buffer,
		size_t size, loff_t *offset)
{
	struct uart_device_data *data =
		(struct uart_device_data *) file->private_data;
	size_t to_read, avail, len;

	wait_event_interruptible(data->wq_rx, !kfifo_is_empty(&data->kfifo_rx)); // probabil trebuie is_empty_noirqsave??? ca sa poata sa si scrie in kfifo cu intrerupere ca daca nu e deadlock
	//poate fac ceva cu ret
	avail = kfifo_len(&data->kfifo_rx);
	len = (size < avail)? size : avail;
	kfifo_to_user(&data->kfifo_rx, user_buffer, len, to_read);
	offset += to_read;
	data->size = *offset; //asa era im laborator??
	//aici si la read activez dezactivez intreruperile cu registrul din datasheet ca sa nu imi zica toata ziua

	return to_read;
}

static ssize_t
uart_write(struct file *file,
		const char __user *user_buffer,
		size_t size, loff_t *offset)
{
	struct uart_device_data *data =
		(struct uart_device_data *) file->private_data;
	size_t avail, len, bytes_written;

	//write to write_kfifo chars from userspace
	// check if there is space to write
	// if there is, write as much as possible using kfifo_from_user
	// return not_bytes written
	wait_event_interruptible(data->wq_tx, !kfifo_is_full(&data->kfifo_tx));
	//poate fac ceva cu ret
	avail = kfifo_avail(&data->kfifo_tx);
	len = (size < avail)? size : avail;
	kfifo_from_user(&data->kfifo_tx, user_buffer, len, bytes_written);
	offset += bytes_written;
	data->size = *offset; //asa era im laborator??
	//aici si la read activez dezactivez intreruperile cu registrul din datasheet ca sa nu imi zica toata ziua

	return bytes_written;
}

static long
uart_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct uart_device_data *data =
		(struct uart_device_data *) file->private_data;
	int ret = 0;
	int remains;

	return ret;
}

static const struct file_operations uart_fops = {
	.owner = THIS_MODULE,
/* TODO 2/2: add open and release functions */
	.open = uart_open,
	.release = uart_release,
/* TODO 4/1: add read function */
	.read = uart_read,
/* TODO 5/1: add write function */
	.write = uart_write,
/* TODO 6/1: add ioctl function */
	.unlocked_ioctl = uart_ioctl,
};

static irqreturn_t uart_interrupt_handler(int irq_no, void *dev_id) {
    return IRQ_HANDLED;
}

static int uart_init(void)
{
	int err_chrdev, err_irq;
	struct resource *res1, *res2;
	int i;

	// schimb request irq si req region numele in numele modulului..

	if(option == OPTION_COM1) {
		err_chrdev = register_chrdev_region(MKDEV(major, 0), 1, MODULE_NAME);
		res1 = request_region(port_addr[0], 8, MODULE_NAME);
		err_irq = request_irq(IRQ_COM1, uart_interrupt_handler, IRQF_SHARED, MODULE_NAME, &devs[0]);
	} else {
		if (option == OPTION_COM2) {
			err_chrdev = register_chrdev_region(MKDEV(major, 1), 1, MODULE_NAME);
			res2= request_region(0x2f8, 8, MODULE_NAME);
			err_irq = request_irq(IRQ_COM2, uart_interrupt_handler, IRQF_SHARED	, MODULE_NAME, &devs[1]);
		} else {
			num_minors = 2;
			err_chrdev = register_chrdev_region(MKDEV(major, 0), 2, MODULE_NAME);
			res1 = request_region(port_addr[0], 8, MODULE_NAME);
			res2 = request_region(port_addr[1], 8, MODULE_NAME);
			err_irq  = request_irq(IRQ_COM1, uart_interrupt_handler, IRQF_SHARED, MODULE_NAME, &devs[0]);
			err_irq += request_irq(IRQ_COM2, uart_interrupt_handler, IRQF_SHARED, MODULE_NAME, &devs[1]);
		}
	}

	if (err_chrdev < 0) {	
		pr_info("register_chrdev_region error");
		return err_chrdev;
	}

	if (err_irq < 0) {
		pr_info("request_irq error");
		return err_irq;
	}

	if (!res1 || !res2) {
		pr_info("request_region error");
		return -ENODEV;
	}
	
	if (option == OPTION_COM1 || option == OPTION_BOTH) {
		devs[0].com_id = 0;
		INIT_KFIFO(devs[0].kfifo_rx);
		INIT_KFIFO(devs[0].kfifo_tx);
		
		init_waitqueue_head(&devs[0].wq_rx);
		init_waitqueue_head(&devs[0].wq_tx);
		
		cdev_init(&devs[0].cdev, &uart_fops);
		cdev_add(&devs[0].cdev, MKDEV(DEFAULT_MAJOR, 0), 1); //posibil sa am eroare aici
		
	}

	if (option == OPTION_COM2 || option == OPTION_BOTH) {
		devs[1].com_id = 1;
		INIT_KFIFO(devs[1].kfifo_rx);
		INIT_KFIFO(devs[1].kfifo_tx);

		init_waitqueue_head(&devs[1].wq_rx);
		init_waitqueue_head(&devs[1].wq_tx);

		cdev_init(&devs[1].cdev, &uart_fops);
		cdev_add(&devs[1].cdev, MKDEV(DEFAULT_MAJOR, 1), 1); //posibil sa am eroare aici
	}
	
	// trebuie sa dau enable la interrupts in device cu registrii din dataasheet

	return 0;
}

static void uart_exit(void)
{
	int i;
	for(i = 0; i < num_minors; i++) {
		kfifo_free(&devs[i].kfifo_rx);
		kfifo_free(&devs[i].kfifo_tx);
		cdev_del(&devs[i].cdev);
    }

	if(option == OPTION_COM1) {
		free_irq (IRQ_COM1, &devs[0]);
		release_region(port_addr[0], 8);
		unregister_chrdev_region(MKDEV(major, 0), 1);
	} else {
		if (option == OPTION_COM2) {
			free_irq (IRQ_COM2, &devs[1]);
			release_region(port_addr[1], 8);
			unregister_chrdev_region(MKDEV(major, 1), 1);
		} else {
			free_irq (IRQ_COM1, &devs[0]);
			free_irq (IRQ_COM2, &devs[1]);
			release_region(port_addr[0], 8);
			release_region(port_addr[1], 8);
			unregister_chrdev_region(MKDEV(major, 0), 2);
		}
	}
}

module_init(uart_init);
module_exit(uart_exit);