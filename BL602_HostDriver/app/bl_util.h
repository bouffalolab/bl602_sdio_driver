#ifndef _BL_UTIL_H_
#define _BL_UTIL_H_

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define BL_UTIL_FAIL        (-1)
#define BL_UTIL_SUCCESS     (0)
#define BL_UTIL_BUFF_LEN    (2048)
#define BL_IOCTL_VERSION     (SIOCIWFIRSTPRIV + 1)
//#define SIOCDEVPRIVATE   0x89F0  /* to 89FF */
//#define SIOCIWFIRST       0x8B00
//#define SIOCIWLAST        SIOCIWLASTPRIV      /* 0x8BFF */
//#define SIOCIWFIRSTPRIV   0x8BE0
//#define SIOCIWLASTPRIV    0x8BFF

typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;
typedef signed char         s8;
typedef short               s16;
typedef int                 s32;
typedef long long           s64;

struct util_cmd_node {
    char *name;
    int (*hdl) (int argc, char ** argv);
};

static int bl_util_version(int argc, char ** argv);

#endif /* _BL_UTIL_H_ */

