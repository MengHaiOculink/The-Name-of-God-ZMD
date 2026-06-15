/* 工具函数 */

/*
 * 从 data 数组末尾向前扫描，将连续的 0xFF 变为 0x00，
 * 然后将第一个不是 0xFF 的字节加 1。
 * 如果所有字节都是 0xFF 则返回 1（溢出），否则返回 0。
 */
static int increment_asm(unsigned char *data, unsigned long long len) {
    int overflow = 0;
    __asm__ __volatile__ (
        "mov %[len], %%rcx\n\t"        /* rcx = len                 */
        "add %[data], %%rcx\n\t"       /* rcx = data + len          */
        "dec %%rcx\n\t"                /* rcx = 最后一个字节的地址  */
        "1:\n\t"
        "movb (%%rcx), %%al\n\t"
        "cmp $255, %%al\n\t"
        "jne 2f\n\t"                   /* 若不是 0xFF 则跳转到 2    */
        "movb $0, (%%rcx)\n\t"         /* 将当前字节置 0            */
        "dec %%rcx\n\t"                /* 指针前移                  */
        "cmp %[data], %%rcx\n\t"       /* 是否已越过起始地址？      */
        "jae 1b\n\t"                   /* 若未越过则继续循环        */
        "movl $1, %[overflow]\n\t"     /* 全部是 0xFF，溢出         */
        "jmp 3f\n\t"
        "2:\n\t"
        "incb (%%rcx)\n\t"             /* 第一个非 0xFF 字节加 1    */
        "3:\n\t"
        : [overflow] "=r" (overflow)
        : [data] "r" (data), [len] "r" (len)
        : "rax", "rcx", "memory", "cc"
    );
    return overflow;
}

/* 在控制台打印当前内容（十六进制，每行16字节） */
static void display_content(const unsigned char *data, unsigned long long L) {
    printf("当前内容（%llu 字节）：\n", L);
    for (unsigned long long i = 0; i < L; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0 || i == L - 1)
            printf("\n");
    }
}

/* 保存文件到“终末地”文件夹，文件名格式: YYYYMMDD_HHMMSS_<md5> */
static void save_file(const unsigned char *data, unsigned long long L) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y%m%d_%H%M%S", tm_info);

    char md5_str[33];
    md5_hash(data, L, md5_str);

    char filename[512];
    snprintf(filename, sizeof(filename), "终末地/%s_%s.zip", time_str, md5_str);

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "无法打开文件：%s\n", filename);
        exit(1);
    }
    fwrite(data, 1, L, fp);
    fclose(fp);
    printf("已保存为：%s\n\n", filename);
}
