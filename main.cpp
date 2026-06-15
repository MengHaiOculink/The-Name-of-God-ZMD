/* 0-20G程序自动穷举程序 无内联优化版*/
/* Copyright (C) 2026 YumesomeZakura <1552037053@qq.com>*/

/* 在这里设置最大穷举文件大小 */
#define FSIZE 20ULL * 1024 * 1024 * 1024

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* 跨平台创建文件夹 */
#ifdef _WIN32
#include <direct.h>
#define MKDIR(x) _mkdir(x)
#else
#include <sys/stat.h>
#define MKDIR(x) mkdir(x, 0755)
#endif

/* MD5 实现 */
typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    unsigned char buffer[64];
} MD5_CTX;

#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x ^ y ^ z)
#define I(x,y,z) (y ^ (x | ~z))
#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))

#define FF(a,b,c,d,x,s,ac) { a += F(b,c,d) + x + ac; a = ROTATE_LEFT(a,s); a += b; }
#define GG(a,b,c,d,x,s,ac) { a += G(b,c,d) + x + ac; a = ROTATE_LEFT(a,s); a += b; }
#define HH(a,b,c,d,x,s,ac) { a += H(b,c,d) + x + ac; a = ROTATE_LEFT(a,s); a += b; }
#define II(a,b,c,d,x,s,ac) { a += I(b,c,d) + x + ac; a = ROTATE_LEFT(a,s); a += b; }

static unsigned char PADDING[64] = {
    0x80, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

/* 前置声明 */
static void MD5Transform(uint32_t state[4], const unsigned char block[64]);
static void Encode(unsigned char *output, const uint32_t *input, unsigned int len);
static void Decode(uint32_t *output, const unsigned char *input, unsigned int len);

static void MD5Init(MD5_CTX *ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

static void MD5Update(MD5_CTX *ctx, const unsigned char *input, unsigned int inputLen) {
    unsigned int i, idx, partLen;
    idx = (unsigned int)((ctx->count[0] >> 3) & 0x3F);
    if ((ctx->count[0] += ((uint32_t)inputLen << 3)) < ((uint32_t)inputLen << 3))
        ctx->count[1]++;
    ctx->count[1] += ((uint32_t)inputLen >> 29);
    partLen = 64 - idx;
    if (inputLen >= partLen) {
        memcpy(&ctx->buffer[idx], input, partLen);
        MD5Transform(ctx->state, ctx->buffer);
        for (i = partLen; i + 63 < inputLen; i += 64)
            MD5Transform(ctx->state, &input[i]);
        idx = 0;
    } else i = 0;
    memcpy(&ctx->buffer[idx], &input[i], inputLen - i);
}

static void MD5Final(unsigned char digest[16], MD5_CTX *ctx) {
    unsigned char bits[8];
    unsigned int idx, padLen;
    Encode(bits, ctx->count, 8);
    idx = (unsigned int)((ctx->count[0] >> 3) & 0x3f);
    padLen = (idx < 56) ? (56 - idx) : (120 - idx);
    MD5Update(ctx, PADDING, padLen);
    MD5Update(ctx, bits, 8);
    Encode(digest, ctx->state, 16);
    memset(ctx, 0, sizeof(*ctx));
}

static void MD5Transform(uint32_t state[4], const unsigned char block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    Decode(x, block, 64);
    /* 第1轮 */
    FF(a,b,c,d,x[ 0], 7,0xd76aa478); FF(d,a,b,c,x[ 1],12,0xe8c7b756); FF(c,d,a,b,x[ 2],17,0x242070db); FF(b,c,d,a,x[ 3],22,0xc1bdceee);
    FF(a,b,c,d,x[ 4], 7,0xf57c0faf); FF(d,a,b,c,x[ 5],12,0x4787c62a); FF(c,d,a,b,x[ 6],17,0xa8304613); FF(b,c,d,a,x[ 7],22,0xfd469501);
    FF(a,b,c,d,x[ 8], 7,0x698098d8); FF(d,a,b,c,x[ 9],12,0x8b44f7af); FF(c,d,a,b,x[10],17,0xffff5bb1); FF(b,c,d,a,x[11],22,0x895cd7be);
    FF(a,b,c,d,x[12], 7,0x6b901122); FF(d,a,b,c,x[13],12,0xfd987193); FF(c,d,a,b,x[14],17,0xa679438e); FF(b,c,d,a,x[15],22,0x49b40821);
    /* 第2轮 */
    GG(a,b,c,d,x[ 1], 5,0xf61e2562); GG(d,a,b,c,x[ 6], 9,0xc040b340); GG(c,d,a,b,x[11],14,0x265e5a51); GG(b,c,d,a,x[ 0],20,0xe9b6c7aa);
    GG(a,b,c,d,x[ 5], 5,0xd62f105d); GG(d,a,b,c,x[10], 9,0x02441453); GG(c,d,a,b,x[15],14,0xd8a1e681); GG(b,c,d,a,x[ 4],20,0xe7d3fbc8);
    GG(a,b,c,d,x[ 9], 5,0x21e1cde6); GG(d,a,b,c,x[14], 9,0xc33707d6); GG(c,d,a,b,x[ 3],14,0xf4d50d87); GG(b,c,d,a,x[ 8],20,0x455a14ed);
    GG(a,b,c,d,x[13], 5,0xa9e3e905); GG(d,a,b,c,x[ 2], 9,0xfcefa3f8); GG(c,d,a,b,x[ 7],14,0x676f02d9); GG(b,c,d,a,x[12],20,0x8d2a4c8a);
    /* 第3轮 */
    HH(a,b,c,d,x[ 5], 4,0xfffa3942); HH(d,a,b,c,x[ 8],11,0x8771f681); HH(c,d,a,b,x[11],16,0x6d9d6122); HH(b,c,d,a,x[14],23,0xfde5380c);
    HH(a,b,c,d,x[ 1], 4,0xa4beea44); HH(d,a,b,c,x[ 4],11,0x4bdecfa9); HH(c,d,a,b,x[ 7],16,0xf6bb4b60); HH(b,c,d,a,x[10],23,0xbebfbc70);
    HH(a,b,c,d,x[13], 4,0x289b7ec6); HH(d,a,b,c,x[ 0],11,0xeaa127fa); HH(c,d,a,b,x[ 3],16,0xd4ef3085); HH(b,c,d,a,x[ 6],23,0x04881d05);
    HH(a,b,c,d,x[ 9], 4,0xd9d4d039); HH(d,a,b,c,x[12],11,0xe6db99e5); HH(c,d,a,b,x[15],16,0x1fa27cf8); HH(b,c,d,a,x[ 2],23,0xc4ac5665);
    /* 第4轮 */
    II(a,b,c,d,x[ 0], 6,0xf4292244); II(d,a,b,c,x[ 7],10,0x432aff97); II(c,d,a,b,x[14],15,0xab9423a7); II(b,c,d,a,x[ 5],21,0xfc93a039);
    II(a,b,c,d,x[12], 6,0x655b59c3); II(d,a,b,c,x[ 3],10,0x8f0ccc92); II(c,d,a,b,x[10],15,0xffeff47d); II(b,c,d,a,x[ 1],21,0x85845dd1);
    II(a,b,c,d,x[ 8], 6,0x6fa87e4f); II(d,a,b,c,x[15],10,0xfe2ce6e0); II(c,d,a,b,x[ 6],15,0xa3014314); II(b,c,d,a,x[13],21,0x4e0811a1);
    II(a,b,c,d,x[ 4], 6,0xf7537e82); II(d,a,b,c,x[11],10,0xbd3af235); II(c,d,a,b,x[ 2],15,0x2ad7d2bb); II(b,c,d,a,x[ 9],21,0xeb86d391);
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void Encode(unsigned char *output, const uint32_t *input, unsigned int len) {
    unsigned int i, j;
    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[j]   = (unsigned char)(input[i] & 0xff);
        output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
        output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
        output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
    }
}

static void Decode(uint32_t *output, const unsigned char *input, unsigned int len) {
    unsigned int i, j;
    for (i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j+1]) << 8) |
                    (((uint32_t)input[j+2]) << 16) | (((uint32_t)input[j+3]) << 24);
}

/* 计算 MD5 并返回 32 位十六进制字符串 */
static void md5_hash(const unsigned char *data, size_t len, char output[33]) {
    MD5_CTX ctx;
    unsigned char digest[16];
    MD5Init(&ctx);
    MD5Update(&ctx, data, len);
    MD5Final(digest, &ctx);
    for (int i = 0; i < 16; i++)
        sprintf(output + i * 2, "%02x", digest[i]);
    output[32] = '\0';
}

/* 工具函数 */

/* 将 data 视为 L 位 256 进制数，加 1。返回 1 表示溢出，否则返回 0 */
static int increment(unsigned char *data, unsigned long long L) {
    for (unsigned long long i = L; i-- > 0; ) {
        if (data[i] < 255) {
            data[i]++;
            return 0;
        }
        data[i] = 0;
    }
    return 1;
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
    // 获取当前时间
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y%m%d_%H%M%S", tm_info);

    // 计算 MD5
    char md5_str[33];
    md5_hash(data, L, md5_str);

    // 构造带文件夹的文件名
    char filename[512];
    snprintf(filename, sizeof(filename), "终末地/%s_%s.zip", time_str, md5_str);

    // 写入文件
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "无法打开文件：%s\n", filename);
        exit(1);
    }
    fwrite(data, 1, L, fp);
    fclose(fp);
    printf("已保存为：%s\n\n", filename);
}

/* 主程序 */
int main() {
    /* 确保“终末地”文件夹存在 */
    MKDIR("终末地");

    const unsigned long long MAX_SIZE = FSIZE;

    printf("开始穷举终末地所有可能版本...\n");

    for (unsigned long long L = 1; L <= MAX_SIZE; L++) {
        printf("=== 正在生成长度为 %llu 字节的所有文件 ===\n", L);

        // 分配内存（假设无穷内存）
        unsigned char *data = (unsigned char *)calloc(L, 1);
        if (!data) {
            fprintf(stderr, "内存分配失败，大小：%llu 字节\n", L);
            return 1;
        }

        // 从全 0 开始穷举
        int overflow = 0;
        while (!overflow) {
            display_content(data, L);   // 显示当前内容
            save_file(data, L);         // 保存到“终末地”文件夹
            overflow = increment(data, L); // 递增到下一个序列
        }

        free(data);
    }

    printf("穷举生成已完成\n");
    return 0;
}
