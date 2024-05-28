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
	wait_queue_head_t wq_rx;
	wait_queue_head_t wq_tx;
	DECLARE_KFIFO(kfifo_rx, char, KFIFO_SIZE);
	DECLARE_KFIFO(kfifo_tx, char, KFIFO_SIZE);
	struct work_struct rx_work;
	struct work_struct tx_work;
};

struct uart_device_data devs[MAX_NUMBER_DEVICES];
static int port_addr[] = {0x3f8, 0x2f8};

static int major = 42;
static int option = OPTION_BOTH;
static int num_minors = 1;

module_param(major, int, 0);
MODULE_PARM_DESC(major, "The major needed for device registering");
module_param(option, int, 0);
MODULE_PARM_DESC(option, "Which serial ports");

static int uart_open(struct inode *inode, struct file *file)
{
	struct uart_device_data *data;
	data = container_of(inode->i_cdev, struct uart_device_data, cdev);

	if (atomic_cmpxchg(&data->access, 0, 1) != 0)
		return -EBUSY;

	file->private_data = data;

	outb(0b11000111, port_addr[data->com_id] + 2);
	return 0;
}

static int uart_release(struct inode *inode, struct file *file)
{
	struct uart_device_data *data = (struct uart_device_data *) file->private_data;
	atomic_set(&data->access, 0);
	return 0;
}

static ssize_t uart_read(struct file *file, char __user *user_buffer, size_t size, loff_t *offset)
{
    struct uart_device_data *data = (struct uart_device_data *)file->private_data;
    size_t to_read, avail, len;
    int ret;

    ret = wait_event_interruptible(data->wq_rx, !kfifo_is_empty(&data->kfifo_rx));
    if (ret)
        return ret;

    outb(0, port_addr[data->com_id] + 1);

    avail = kfifo_len(&data->kfifo_rx);
    len = (size < avail) ? size : avail;
    kfifo_to_user(&data->kfifo_rx, user_buffer, len, &to_read);
    *offset += to_read;
    data->size = *offset;

    if (!kfifo_is_full(&data->kfifo_rx)) {
        outb(1, port_addr[data->com_id] + 1);
    }

    return to_read;
}

static void uart_rx_work(struct work_struct *work)
{
    struct uart_device_data *data = container_of(work, struct uart_device_data, rx_work);
    unsigned char lsr, data_byte;

    lsr = inb(port_addr[data->com_id] + 5);

    while (lsr & 1) {
        data_byte = inb(port_addr[data->com_id]);
        kfifo_in(&data->kfifo_rx, &data_byte, 1);
        lsr = inb(port_addr[data->com_id] + 5);
    }

    wake_up_interruptible(&data->wq_rx);

    if (!kfifo_is_full(&data->kfifo_rx)) {
        outb(1, port_addr[data->com_id] + 1);
    }
}

static ssize_t uart_write(struct file *file, const char __user *user_buffer, size_t size, loff_t *offset)
{
    struct uart_device_data *data = (struct uart_device_data *)file->private_data;
    size_t avail, len, bytes_written;
    int ret;

    ret = wait_event_interruptible(data->wq_tx, !kfifo_is_full(&data->kfifo_tx));
    if (ret)
        return ret;

    outb(0, port_addr[data->com_id] + 1);

    avail = kfifo_avail(&data->kfifo_tx);
    len = (size < avail) ? size : avail;
    kfifo_from_user(&data->kfifo_tx, user_buffer, len, &bytes_written);
    *offset += bytes_written;
    data->size = *offset;

    if (!kfifo_is_empty(&data->kfifo_tx)) {
        outb(2, port_addr[data->com_id] + 1);
    }

    return bytes_written;
}

static void uart_tx_work(struct work_struct *work)
{
    struct uart_device_data *data = container_of(work, struct uart_device_data, tx_work);
    unsigned char data_byte;

    while (!kfifo_is_empty(&data->kfifo_tx)) {
        kfifo_out(&data->kfifo_tx, &data_byte, 1);

        while (!(inb(port_addr[data->com_id] + 5) & 0b00100000));
        outb(data_byte, port_addr[data->com_id]);
    }

    wake_up_interruptible(&data->wq_tx);

    if (!kfifo_is_empty(&data->kfifo_tx)) {
        outb(2, port_addr[data->com_id] + 1);
    }
}

static long uart_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct uart_device_data *data = (struct uart_device_data *)file->private_data;
    struct uart16550_line_info line_info;
    unsigned char lcr;

    switch (cmd) {
		case UART16550_IOCTL_SET_LINE:
			if (copy_from_user(&line_info, (struct uart16550_line_info __user *)arg, sizeof(struct uart16550_line_info)))
				return -EFAULT;

			lcr = line_info.len | line_info.stop | line_info.par;

			outb(0b10000000, port_addr[data->com_id] + 3);
			outb(line_info.baud, port_addr[data->com_id] + 0);
			outb(0, port_addr[data->com_id] + 3); 
			outb(lcr, port_addr[data->com_id] + 3);

			break;

		default:
			return -1;
    }

    return 0;
}

static irqreturn_t uart_interrupt_handler(int irq_no, void *dev_id)
{
    struct uart_device_data *data = (struct uart_device_data *)dev_id;
    unsigned char iir;

    iir = inb(port_addr[data->com_id] + 2);

    if (iir & 1)
        return IRQ_NONE;

    outb(0, port_addr[data->com_id] + 1);

    schedule_work(&data->rx_work);
    schedule_work(&data->tx_work);

    return IRQ_HANDLED;
}

static const struct file_operations uart_fops = {
	.owner = THIS_MODULE,
	.open = uart_open,
	.release = uart_release,
	.read = uart_read,
	.write = uart_write,
	.unlocked_ioctl = uart_ioctl,
};

static int uart_init(void)
{
	int err_chrdev, err_irq;
	struct resource *res1, *res2;

	if(option == OPTION_COM1) {
		err_chrdev = register_chrdev_region(MKDEV(major, 0), 1, MODULE_NAME);
		res1 = request_region(port_addr[0], 8, MODULE_NAME);
		err_irq = request_irq(IRQ_COM1, uart_interrupt_handler, IRQF_SHARED, MODULE_NAME, &devs[0]);
	} else {
		if (option == OPTION_COM2) {
			err_chrdev = register_chrdev_region(MKDEV(major, 1), 1, MODULE_NAME);
			res2= request_region(port_addr[1], 8, MODULE_NAME);
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

	if ((!res1 && option != OPTION_COM2) || (!res2 && option != OPTION_COM1)) {
		pr_info("request_region error");
		return -ENODEV;
	}
	
	if (option == OPTION_COM1 || option == OPTION_BOTH) {
		cdev_init(&devs[0].cdev, &uart_fops);
		devs[0].com_id = 0;
		devs[0].size = 0;
		atomic_set(&devs[0].access, 0);

		init_waitqueue_head(&devs[0].wq_rx);
		init_waitqueue_head(&devs[0].wq_tx);

		INIT_KFIFO(devs[0].kfifo_rx);
		INIT_KFIFO(devs[0].kfifo_tx);

        INIT_WORK(&devs[0].rx_work, uart_rx_work);
        INIT_WORK(&devs[0].tx_work, uart_tx_work);
		
		cdev_add(&devs[0].cdev, MKDEV(major, 0), 1);

        outb(0, port_addr[0] + 1);
        outb(0b11000111, port_addr[0] + 2);
        outb(0b00001011, port_addr[0] + 4);
        outb(1, port_addr[0] + 1);
	}

	if (option == OPTION_COM2 || option == OPTION_BOTH) {
		cdev_init(&devs[1].cdev, &uart_fops);
		devs[1].com_id = 1;
		devs[0].size = 0;
		atomic_set(&devs[1].access, 0);

		init_waitqueue_head(&devs[1].wq_rx);
		init_waitqueue_head(&devs[1].wq_tx);

		INIT_KFIFO(devs[1].kfifo_rx);
		INIT_KFIFO(devs[1].kfifo_tx);

        INIT_WORK(&devs[1].rx_work, uart_rx_work);
        INIT_WORK(&devs[1].tx_work, uart_tx_work);

		cdev_add(&devs[1].cdev, MKDEV(major, 1), 1);

        outb(0, port_addr[1] + 1);
        outb(0b11000111, port_addr[1] + 2);
        outb(0b00001011, port_addr[1] + 4);
        outb(1, port_addr[1] + 1);
	}

	return 0;
}

static void uart_exit(void)
{
	if(option == OPTION_COM1) {
		free_irq (IRQ_COM1, &devs[0]);
		release_region(port_addr[0], 8);
		cdev_del(&devs[0].cdev);
		unregister_chrdev_region(MKDEV(major, 0), 1);
	} else {
		if (option == OPTION_COM2) {
			free_irq (IRQ_COM2, &devs[1]);
			release_region(port_addr[1], 8);
			cdev_del(&devs[1].cdev);
			unregister_chrdev_region(MKDEV(major, 1), 1);
		} else {
			free_irq (IRQ_COM1, &devs[0]);
			free_irq (IRQ_COM2, &devs[1]);
			release_region(port_addr[0], 8);
			release_region(port_addr[1], 8);
			cdev_del(&devs[0].cdev);
			cdev_del(&devs[1].cdev);
			unregister_chrdev_region(MKDEV(major, 0), 2);
		}
	}
}

module_init(uart_init);
module_exit(uart_exit);