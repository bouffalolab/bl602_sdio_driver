#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>     /* for IFNAMSIZ and co... */
#include <linux/types.h>
#include <linux/wireless.h>
#include "bl_util.h"

int sockfd;
char iface_name[IFNAMSIZ];

static int bl_util_version(int argc, char ** argv)
{
    int i = 0, ret = 0;
    u8 * buf = NULL, * pos = NULL;
    struct iwreq wrq;

    pos = buf = (u8 *)malloc(BL_UTIL_BUFF_LEN);
    if (!buf) {
        printf("Error:%s, can't alloc command buf.\n", __func__);
        ret = BL_UTIL_FAIL;
        goto end;
    }

    memset(buf, 0, BL_UTIL_BUFF_LEN);
    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_ifrn.ifrn_name, iface_name, IFNAMSIZ);
    wrq.ifr_ifrn.ifrn_name[IFNAMSIZ - 1] = '\0';

    wrq.u.data.pointer = (void *) buf;
    wrq.u.data.length = sizeof(buf);

    for (i = 2; i < argc; i++) {
        strncpy((char *)pos, argv[i], strlen(argv[i]));
        //printf("usr fill %s, %d Byte\n", argv[i], strlen(argv[i]));
        pos += strlen(argv[i]);
        if (i < (argc - 1)) {
            strncpy((char *)pos, " ", strlen(" "));
            pos += 1;
        }
    }
    ret = ioctl(sockfd, BL_IOCTL_VERSION, &wrq);
    if (ret) {
        printf("Error: blutl version fail %d\n", ret);
        ret = BL_UTIL_FAIL;
        goto end;
    }

end:
    if (buf)
        free(buf);

    return ret;
}


struct util_cmd_node bl_util_cmd_table[] = {
    {"version",    bl_util_version},
};

int main(int argc, char * argv [ ])
{
    int i = 0, ret = -1;
    struct util_cmd_node * util_cmd = NULL;

    if(argc < 3) {
        fprintf(stderr, "input params num is %d, should >= 3\n", argc);
         return -1;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("creat global socket fail\n");
        return -1;
    }

    strncpy(iface_name, argv[1], IFNAMSIZ);

    printf("argc=%d, interface %s\n", argc, iface_name);
    //for (i = 0; i < argc; i++)
    //    printf("input[%d]=%s\n", i, argv[i]);
    
    for (i = 0; i < (int)ARRAY_SIZE(bl_util_cmd_table); i++) {
        util_cmd = &bl_util_cmd_table[i];
        if (!strcasecmp(util_cmd->name, argv[2])) {
            ret = util_cmd->hdl(argc, argv);
            break;
        }
    }

    if(i == ARRAY_SIZE(bl_util_cmd_table)) {
        printf("command(%s) handler not found\n", argv[2]);
    }

    return ret;
}
