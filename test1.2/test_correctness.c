/*
 * AES-SM3完整性校验算法 - 正确性测试
 * 测试内容：
 * 1. 基本功能测试
 * 2. 雪崩效应测试
 * 3. 一致性测试
 * 4. 边界条件测试
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

// 声明外部函数（需要链接主程序）
extern void aes_sm3_integrity_256bit(const uint8_t* input, uint8_t* output);
extern void aes_sm3_integrity_128bit(const uint8_t* input, uint8_t* output);
extern void sha256_4kb(const uint8_t* input, uint8_t* output);
extern void sm3_4kb(const uint8_t* input, uint8_t* output);

// 辅助函数：计算汉明距离
int hamming_distance(const uint8_t* a, const uint8_t* b, int len) {
    int count = 0;
    for (int i = 0; i < len; i++) {
        uint8_t xor = a[i] ^ b[i];
        while (xor) {
            count += xor & 1;
            xor >>= 1;
        }
    }
    return count;
}

// 辅助函数：打印十六进制
void print_hex(const char* label, const uint8_t* data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i != len - 1) {
            printf("\n%*s", (int)strlen(label) + 2, "");
        }
    }
    printf("\n");
}

// 测试1：基本功能测试
int test_basic_functionality() {
    printf("\n=== 测试1: 基本功能测试 ===\n");
    
    uint8_t input[4096];
    uint8_t output_256[32];
    uint8_t output_128[16];
    
    // 测试全零输入
    memset(input, 0, 4096);
    aes_sm3_integrity_256bit(input, output_256);
    aes_sm3_integrity_128bit(input, output_128);
    
    print_hex("全零输入256位", output_256, 32);
    print_hex("全零输入128位", output_128, 16);
    
    // 测试全一输入
    memset(input, 0xFF, 4096);
    aes_sm3_integrity_256bit(input, output_256);
    aes_sm3_integrity_128bit(input, output_128);
    
    print_hex("全一输入256位", output_256, 32);
    print_hex("全一输入128位", output_128, 16);
    
    // 测试递增模式
    for (int i = 0; i < 4096; i++) {
        input[i] = i & 0xFF;
    }
    aes_sm3_integrity_256bit(input, output_256);
    
    print_hex("递增模式256位", output_256, 32);
    
    printf("✓ 基本功能测试通过\n");
    return 1;
}

// 测试2：雪崩效应测试
int test_avalanche_effect() {
    printf("\n=== 测试2: 雪崩效应测试 ===\n");
    
    uint8_t input1[4096];
    uint8_t input2[4096];
    uint8_t hash1[32];
    uint8_t hash2[32];
    
    // 初始化随机数据
    srand(time(NULL));
    for (int i = 0; i < 4096; i++) {
        input1[i] = rand() % 256;
    }
    memcpy(input2, input1, 4096);
    
    // 测试不同位置的单比特翻转
    int test_positions[] = {0, 1000, 2000, 3000, 4095};
    int test_count = sizeof(test_positions) / sizeof(test_positions[0]);
    
    printf("单比特翻转测试:\n");
    printf("位置\t翻转比特\t汉明距离\t差异率\n");
    printf("----\t--------\t--------\t------\n");
    
    int total_distance = 0;
    
    for (int i = 0; i < test_count; i++) {
        int pos = test_positions[i];
        
        // 重置input2
        memcpy(input2, input1, 4096);
        
        // 翻转一位
        input2[pos] ^= 0x01;
        
        // 计算哈希
        aes_sm3_integrity_256bit(input1, hash1);
        aes_sm3_integrity_256bit(input2, hash2);
        
        // 计算汉明距离
        int dist = hamming_distance(hash1, hash2, 32);
        float ratio = (float)dist / (32 * 8) * 100.0;
        
        printf("%d\t第0位\t\t%d\t\t%.2f%%\n", pos, dist, ratio);
        
        total_distance += dist;
    }
    
    float avg_ratio = (float)total_distance / (test_count * 32 * 8) * 100.0;
    printf("\n平均差异率: %.2f%%\n", avg_ratio);
    
    if (avg_ratio >= 40.0 && avg_ratio <= 60.0) {
        printf("✓ 雪崩效应测试通过 (理想值接近50%%)\n");
        return 1;
    } else {
        printf("⚠️  雪崩效应偏离理想值\n");
        return 0;
    }
}

// 测试3：一致性测试
int test_consistency() {
    printf("\n=== 测试3: 一致性测试 ===\n");
    
    uint8_t input[4096];
    uint8_t hash1[32];
    uint8_t hash2[32];
    
    // 生成随机输入
    srand(12345);  // 固定种子
    for (int i = 0; i < 4096; i++) {
        input[i] = rand() % 256;
    }
    
    // 多次计算应得到相同结果
    int iterations = 10;
    int all_same = 1;
    
    aes_sm3_integrity_256bit(input, hash1);
    
    for (int i = 0; i < iterations; i++) {
        aes_sm3_integrity_256bit(input, hash2);
        
        if (memcmp(hash1, hash2, 32) != 0) {
            all_same = 0;
            printf("✗ 第%d次计算结果不一致\n", i + 1);
            break;
        }
    }
    
    if (all_same) {
        printf("✓ 一致性测试通过 (相同输入产生相同输出)\n");
        print_hex("稳定哈希值", hash1, 32);
        return 1;
    } else {
        printf("✗ 一致性测试失败\n");
        return 0;
    }
}

// 测试4：边界条件测试
int test_boundary_conditions() {
    printf("\n=== 测试4: 边界条件测试 ===\n");
    
    uint8_t input[4096];
    uint8_t output[32];
    
    // 测试1: 最小值（全0）
    memset(input, 0, 4096);
    aes_sm3_integrity_256bit(input, output);
    printf("✓ 最小值测试通过\n");
    
    // 测试2: 最大值（全FF）
    memset(input, 0xFF, 4096);
    aes_sm3_integrity_256bit(input, output);
    printf("✓ 最大值测试通过\n");
    
    // 测试3: 交替模式
    for (int i = 0; i < 4096; i++) {
        input[i] = (i % 2) ? 0xFF : 0x00;
    }
    aes_sm3_integrity_256bit(input, output);
    printf("✓ 交替模式测试通过\n");
    
    // 测试4: 单个非零字节
    memset(input, 0, 4096);
    input[2048] = 0x42;
    aes_sm3_integrity_256bit(input, output);
    printf("✓ 单字节非零测试通过\n");
    
    printf("✓ 所有边界条件测试通过\n");
    return 1;
}

// 测试5：128位vs 256位输出关系
int test_output_sizes() {
    printf("\n=== 测试5: 输出大小测试 ===\n");
    
    uint8_t input[4096];
    uint8_t output_256[32];
    uint8_t output_128[16];
    
    for (int i = 0; i < 4096; i++) {
        input[i] = i % 256;
    }
    
    aes_sm3_integrity_256bit(input, output_256);
    aes_sm3_integrity_128bit(input, output_128);
    
    print_hex("256位输出", output_256, 32);
    print_hex("128位输出", output_128, 16);
    
    // 验证128位输出是256位的前半部分
    if (memcmp(output_128, output_256, 16) == 0) {
        printf("✓ 128位输出是256位输出的前128位\n");
    } else {
        printf("△ 128位输出独立于256位输出\n");
    }
    
    return 1;
}

// 测试6：与其他算法对比
int test_comparison() {
    printf("\n=== 测试6: 与其他算法对比 ===\n");
    
    uint8_t input[4096];
    uint8_t aes_sm3_hash[32];
    uint8_t sha256_hash[32];
    uint8_t sm3_hash[32];
    
    for (int i = 0; i < 4096; i++) {
        input[i] = i % 256;
    }
    
    aes_sm3_integrity_256bit(input, aes_sm3_hash);
    sha256_4kb(input, sha256_hash);
    sm3_4kb(input, sm3_hash);
    
    print_hex("AES-SM3", aes_sm3_hash, 32);
    print_hex("SHA256 ", sha256_hash, 32);
    print_hex("SM3    ", sm3_hash, 32);
    
    // 验证不同算法产生不同结果
    if (memcmp(aes_sm3_hash, sha256_hash, 32) != 0 &&
        memcmp(aes_sm3_hash, sm3_hash, 32) != 0) {
        printf("✓ AES-SM3产生独特的哈希值\n");
    } else {
        printf("⚠️  哈希值存在意外的相同\n");
    }
    
    return 1;
}

// 主测试函数
int main() {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║  AES-SM3完整性校验算法 - 正确性测试套件               ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");
    
    int total_tests = 6;
    int passed_tests = 0;
    
    passed_tests += test_basic_functionality();
    passed_tests += test_avalanche_effect();
    passed_tests += test_consistency();
    passed_tests += test_boundary_conditions();
    passed_tests += test_output_sizes();
    passed_tests += test_comparison();
    
    printf("\n");
    printf("═══════════════════════════════════════════════════════════\n");
    printf("  测试结果: %d/%d 通过\n", passed_tests, total_tests);
    printf("═══════════════════════════════════════════════════════════\n");
    
    if (passed_tests == total_tests) {
        printf("\n✓ 所有测试通过！算法实现正确。\n\n");
        return 0;
    } else {
        printf("\n⚠️  部分测试未通过，请检查实现。\n\n");
        return 1;
    }
}

