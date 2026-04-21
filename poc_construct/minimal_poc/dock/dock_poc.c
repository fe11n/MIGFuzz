#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define the message structure
typedef struct {
    mach_msg_header_t header;
    uint8_t body[12];
} dock_message_t;

int main() {
    kern_return_t kr;
    mach_port_t bootstrap_port;
    mach_port_t service_port;
    dock_message_t msg;

    // 1. Get bootstrap port
    kr = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get bootstrap port: %s\n", mach_error_string(kr));
        return 1;
    }

    // 2. Look up the service
    kr = bootstrap_look_up(bootstrap_port, "com.apple.dock.server", &service_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to look up service com.apple.dock.server: %s\n", mach_error_string(kr));
        return 1;
    }
    printf("Got service port: 0x%x\n", service_port);

    // 3. Construct the message
    memset(&msg, 0, sizeof(msg));

    // Header
    // msg_bits: 0x13 -> MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0)
    msg.header.msgh_bits = 0x13; 
    msg.header.msgh_size = 36;
    msg.header.msgh_remote_port = service_port;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_voucher_port = MACH_PORT_NULL;
    msg.header.msgh_id = 96520;

    // Body
    // 0x00 0x00 0x50 0x69
    // 0x34 0x8c 0x2c 0x9a
    // 0x04 0x00 0x00 0x00
    uint8_t body_bytes[] = {
        0x00, 0x00, 0x50, 0x69,
        0x34, 0x8c, 0x2c, 0x9a,
        0x04, 0x00, 0x00, 0x00
    };
    memcpy(msg.body, body_bytes, sizeof(body_bytes));

    // 4. Send the message
    printf("Sending message...\n");
    kr = mach_msg(
        &msg.header,
        MACH_SEND_MSG,
        msg.header.msgh_size,
        0,              // receive limit
        MACH_PORT_NULL, // receive name
        MACH_MSG_TIMEOUT_NONE,
        MACH_PORT_NULL
    );

    if (kr != KERN_SUCCESS) {
        printf("Failed to send message: %s (0x%x)\n", mach_error_string(kr), kr);
        return 1;
    }

    printf("Message sent successfully.\n");
    return 0;
}
