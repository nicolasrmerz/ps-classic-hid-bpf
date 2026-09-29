// SPDX-License-Identifier: GPL-2.0
/* Create virtual HID mouse and modify its input with BPF
 *
 * This program:
 * 1. Creates a virtual HID mouse using uhid
 * 2. Attaches a BPF program that doubles movement
 * 3. Sends synthetic mouse events
 * 4. Shows the BPF modification in action
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <linux/uhid.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "hid-input-modifier.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

#define BYTE_0(x) x >> 8
#define BYTE_1(x) x & 0xFF

// /* Original controller rdesc */
// static unsigned char rdesc[] = {
// 	0x05, 0x01,
// 	0x09, 0x05,
// 	0xA1, 0x01,
// 	0x15, 0x00,
// 	0x25, 0x01,
// 	0x75, 0x01,
// 	0x95, 0x0A,
// 	0x05, 0x09,
// 	0x19, 0x01,
// 	0x29, 0x0A,
// 	0x81, 0x02,
// 	0x05, 0x01,
// 	0x09, 0x30,
// 	0x09, 0x31,
// 	0x15, 0x00,
// 	0x25, 0x02,
// 	0x35, 0x00,
// 	0x45, 0x02,
// 	0x75, 0x02,
// 	0x95, 0x02,
// 	0x81, 0x02,
// 	0x75, 0x01,
// 	0x95, 0x02,
// 	0x81, 0x01,
// 	0xC0
// };


// Sample working pad
static unsigned char rdesc[] = {
    0x05, 0x01,        // Usage Page (Generic Desktop)
    0x09, 0x05,        // Usage (Game Pad)
    0xA1, 0x01,        // Collection (Application)

    // Buttons 1-10
    0x15, 0x00,        // Logical Minimum (0)
    0x25, 0x01,        // Logical Maximum (1)
    0x75, 0x01,        // Report Size (1)
    0x95, 0x0A,        // Report Count (10)
    0x05, 0x09,        // Usage Page (Button)
    0x19, 0x01,        // Usage Minimum (Button 1)
    0x29, 0x0A,        // Usage Maximum (Button 10)
    0x81, 0x02,        // Input (Data, Variable, Absolute)

    // D-pad / Hat Switch
    0x05, 0x01,        // Usage Page (Generic Desktop)
    0x09, 0x39,        // Usage (Hat Switch)
    0x15, 0x00,        // Logical Minimum (0)
    0x25, 0x07,        // Logical Maximum (7)
    0x35, 0x00,        // Physical Minimum (0)
    0x46, 0x3B, 0x01,  // Physical Maximum (315)
    0x65, 0x14,        // Unit (English Rotation: Angular Position)
    0x75, 0x04,        // Report Size (4)
    0x95, 0x01,        // Report Count (1)
    0x81, 0x42,        // Input (Data, Variable, Absolute, Null State)

    // Padding: 2 bits
    0x75, 0x01,        // Report Size (1)
    0x95, 0x02,        // Report Count (2)
    0x81, 0x01,        // Input (Constant)

    0xC0               // End Collection
};

// Sample working pad reports
#define DPAD_UP 0x0000
#define DPAD_UP_RIGHT 0x0004
#define DPAD_RIGHT 0x0008
#define DPAD_DOWN_RIGHT 0x000C
#define DPAD_DOWN 0x0010
#define DPAD_DOWN_LEFT 0x0014
#define DPAD_LEFT 0x0018
#define DPAD_UP_LEFT 0x001C
#define DPAD_RELEASED 0x0020
#define BTN_X 0x0100
#define BTN_CIRCLE 0x0200
#define BTN_SQUARE 0x0400
#define BTN_TRIANGLE 0x0800
#define BTN_L1 0x1000
#define BTN_R1 0x2000
#define BTN_L2 0x4000
#define BTN_R2 0x8000
#define BTN_SELECT 0x0001
#define BTN_START 0x0002


static int uhid_fd = -1;

static int uhid_write(int fd, const struct uhid_event *ev)
{
	ssize_t ret;
	ret = write(fd, ev, sizeof(*ev));
	if (ret < 0) {
		fprintf(stderr, "Cannot write to uhid: %m\n");
		return -errno;
	} else if (ret != sizeof(*ev)) {
		fprintf(stderr, "Wrong size written to uhid: %zd != %zu\n",
			ret, sizeof(*ev));
		return -EFAULT;
	}
	return 0;
}

static int create_uhid_device(void)
{
	struct uhid_event ev;
	int fd;

	fd = open("/dev/uhid", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open /dev/uhid: %m\n");
		return -errno;
	}

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_CREATE;
	strcpy((char*)ev.u.create.name, "BPF Virtual PS Classic Controller");
	ev.u.create.rd_data = rdesc;
	ev.u.create.rd_size = sizeof(rdesc);
	ev.u.create.bus = BUS_USB;
	ev.u.create.vendor = 0x054C;
	ev.u.create.product = 0x0CDA;
	ev.u.create.version = 0;
	ev.u.create.country = 0;

	if (uhid_write(fd, &ev)) {
		close(fd);
		return -1;
	}

	printf("Created virtual HID device\n");
	return fd;
}

static int destroy_uhid_device(int fd)
{
	struct uhid_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_DESTROY;
	uhid_write(fd, &ev);
	close(fd);
	printf("Destroyed virtual HID device\n");
	return 0;
}

static int send_controller_event(int fd, __s16 in)
{
	struct uhid_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_INPUT;
	ev.u.input.size = 2;
	ev.u.input.data[0] = BYTE_0(in);	/* Buttons */
	ev.u.input.data[1] = BYTE_1(in);	/* X movement */

	return uhid_write(fd, &ev);
}

/* Find our virtual HID device */
static int find_hid_device(void)
{
	char path[256];
	FILE *fp;
	int i;

	/* Wait a bit for device to appear */
	sleep(1);

	for (i = 0; i < 100; i++) {
		snprintf(path, sizeof(path), "/sys/bus/hid/devices/0003:054C:0CDA.%04X/uevent", i);
		fp = fopen(path, "r");
		if (fp) {
			fclose(fp);
			printf("Found HID device ID: %d\n", i);
			return i;
		}
	}

	return -1;
}

int main(int argc, char **argv)
{
	struct hid_input_modifier_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	int err, hid_id;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Create virtual HID device */
	uhid_fd = create_uhid_device();
	if (uhid_fd < 0)
		return 1;

	/* Find the HID device ID */
	hid_id = find_hid_device();
	if (hid_id < 0) {
		fprintf(stderr, "Cannot find virtual HID device\n");
		destroy_uhid_device(uhid_fd);
		return 1;
	}

	// /* Open and load BPF program */
	// skel = hid_input_modifier_bpf__open();
	// if (!skel) {
	// 	fprintf(stderr, "Failed to open BPF skeleton\n");
	// 	destroy_uhid_device(uhid_fd);
	// 	return 1;
	// }

	// skel->struct_ops.input_modifier->hid_id = hid_id;

	// err = hid_input_modifier_bpf__load(skel);
	// if (err) {
	// 	fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
	// 	goto cleanup;
	// }

	// /* Attach BPF program */
	// link = bpf_map__attach_struct_ops(skel->maps.input_modifier);
	// if (!link) {
	// 	fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
	// 	err = -1;
	// 	goto cleanup;
	// }

	// printf("BPF program attached successfully!\n");
	// printf("The BPF program will DOUBLE all mouse movements\n\n");
	// printf("Sending test mouse events:\n");
	// printf("View trace with: sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");

	// /* Send some test events */
	// for (int i = 0; i < 5 && !exiting; i++) {
	// 	__s8 x = 11, y = 23;
	// 	printf("Sending: X=%d, Y=%d (BPF will double to X=%d, Y=%d)\n",
	// 	       x, y, x*2, y*2);
	// 	send_mouse_event(uhid_fd, x, y);
	// 	sleep(1);
	// }

	// send_controller_event(uhid_fd, 0x00, 0x14);
	// sleep(1);
	// send_controller_event(uhid_fd, 0x00, 0x04);
	// sleep(1);
	// send_controller_event(uhid_fd, 0x00, 0x14);
	// sleep(1);
	// send_controller_event(uhid_fd, 0x00, 0x24);
	// sleep(1);
	// send_controller_event(uhid_fd, 0x00, 0x14);
	// sleep(1);
	// send_controller_event(uhid_fd, 0x00, 0x18);
	// sleep(1);
	// send_controller_event(uhid_fd, 0x00, 0x14);
	// sleep(1);
	// send_controller_event(uhid_fd, 0x00, 0x10);
	// sleep(1);
	// send_controller_event(uhid_fd, 0x00, 0x14);
	// sleep(1);

	send_controller_event(uhid_fd, DPAD_RELEASED);
	sleep(1);
	send_controller_event(uhid_fd, DPAD_UP);
	sleep(1);
	send_controller_event(uhid_fd, DPAD_RELEASED);
	sleep(1);
	send_controller_event(uhid_fd, DPAD_RIGHT);
	sleep(1);
	send_controller_event(uhid_fd, DPAD_RELEASED);
	sleep(1);
	send_controller_event(uhid_fd, DPAD_DOWN);
	sleep(1);
	send_controller_event(uhid_fd, DPAD_RELEASED);
	sleep(1);
	send_controller_event(uhid_fd, DPAD_LEFT);
	sleep(1);
	send_controller_event(uhid_fd, DPAD_RELEASED);
	sleep(1);


	printf("\nPress Ctrl-C to exit...\n");
	while (!exiting)
		sleep(1);

cleanup:
	// bpf_link__destroy(link);
	// hid_input_modifier_bpf__destroy(skel);
	destroy_uhid_device(uhid_fd);
	return err < 0 ? -err : 0;
}
