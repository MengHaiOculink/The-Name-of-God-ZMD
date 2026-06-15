#define SIZE 20ULL * 1024 * 1024 * 1024

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "md5.h"
#include "tools.h"

/* 跨平台创建文件夹 */
#ifdef _WIN32
#include <direct.h>
#define MKDIR(x) _mkdir(x)
#else
#include <sys/stat.h>
#define MKDIR(x) mkdir(x, 0755)
#endif

int main() {
    /* 确保“终末地”文件夹存在 */
    MKDIR("终末地");

    const unsigned long long MAX_SIZE = SIZE;
    printf("开始穷举生\n");

    for (unsigned long long L = 1; L <= MAX_SIZE; L++) {
        printf("=== 正在生成长度为 %llu 字节的所有文件 ===\n", L);

        unsigned char *data = (unsigned char *)calloc(L, 1);
        if (!data) {
            fprintf(stderr, "内存分配失败，大小：%llu 字节\n", L);
            return 1;
        }

        int overflow = 0;
        while (!overflow) {
            display_content(data, L);          /* 显示当前内容  */
            save_file(data, L);                /* 保存到“终末地”*/
            overflow = increment_asm(data, L); 
        }

        free(data);
    }

    printf("穷举生成已完成\n");
    return 0;
}
