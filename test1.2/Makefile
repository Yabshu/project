# Makefile for AES-SM3 Integrity Check Algorithm
# Target Platform: ARMv8.2+ with crypto extensions

CC = gcc
# 优化版编译选项：针对单线程吞吐率最大化
CFLAGS = -O3 -funroll-loops -ftree-vectorize -finline-functions -ffast-math \
         -flto -fomit-frame-pointer -pthread -Wall -Wextra
# 激进优化选项（可选，进一步提升性能）
CFLAGS_AGGRESSIVE = -O3 -funroll-loops -ftree-vectorize -finline-functions \
                    -ffast-math -flto -fomit-frame-pointer -march=native \
                    -mtune=native -pthread -Wall
ARM_FLAGS = -march=armv8.2-a+crypto+aes+sha2+sm3+sm4
LIBS = -lm -lpthread

# 目标文件
TARGET = aes_sm3_integrity
SRC = aes_sm3_integrity.c
TEST_SRC = test_correctness.c
TEST_TARGET = test_correctness

# 默认目标
all: $(TARGET)

# ARMv8平台编译（华为云KC2）- 优化版
arm: $(SRC)
	$(CC) $(ARM_FLAGS) $(CFLAGS) -o $(TARGET)_arm $(SRC) $(LIBS)
	@echo "编译完成: $(TARGET)_arm (ARMv8优化版本)"
	@echo "支持指令集: AES, SM3, SM4, SHA2, NEON"
	@echo "优化级别: 标准优化 (O3 + LTO + inline + unroll)"

# ARMv8平台激进优化版（最大性能）
arm_aggressive: $(SRC)
	$(CC) $(CFLAGS_AGGRESSIVE) -o $(TARGET)_arm_opt $(SRC) $(LIBS)
	@echo "编译完成: $(TARGET)_arm_opt (ARMv8激进优化版本)"
	@echo "优化级别: 激进优化 (native + all optimizations)"
	@echo "警告: 此版本仅能在编译时的CPU架构上运行"

# 通用编译（兼容模式）
generic: $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET)_generic $(SRC) $(LIBS)
	@echo "编译完成: $(TARGET)_generic (通用版本)"

# 调试版本
debug: $(SRC)
	$(CC) $(ARM_FLAGS) -g -O0 -pthread -Wall -Wextra -o $(TARGET)_debug $(SRC) $(LIBS)
	@echo "编译完成: $(TARGET)_debug (调试版本)"

# 性能分析版本
profile: $(SRC)
	$(CC) $(ARM_FLAGS) $(CFLAGS) -pg -o $(TARGET)_profile $(SRC) $(LIBS)
	@echo "编译完成: $(TARGET)_profile (性能分析版本)"

# x86_64测试版本（用于开发测试）
x86: $(SRC)
	$(CC) -O3 -funroll-loops -pthread -o $(TARGET)_x86 $(SRC) $(LIBS)
	@echo "编译完成: $(TARGET)_x86 (x86_64测试版本)"

# 编译正确性测试
test_build: arm
	@echo "编译正确性测试..."
	$(CC) $(ARM_FLAGS) $(CFLAGS) -c $(SRC) -o $(TARGET).o $(LIBS)
	$(CC) $(ARM_FLAGS) $(CFLAGS) $(TEST_SRC) $(TARGET).o -o $(TEST_TARGET)_arm $(LIBS)
	@echo "编译完成: $(TEST_TARGET)_arm"

# 运行性能测试
test: arm
	@echo "运行性能测试..."
	./$(TARGET)_arm

# 运行正确性测试
test_correctness: test_build
	@echo "运行正确性测试..."
	./$(TEST_TARGET)_arm

# 运行所有测试
test_all: test_correctness test
	@echo "所有测试完成"

# 清理
clean:
	rm -f $(TARGET)_* $(TEST_TARGET)_* *.o gmon.out

# 安装
install: arm
	cp $(TARGET)_arm /usr/local/bin/$(TARGET)
	@echo "安装完成: /usr/local/bin/$(TARGET)"

# 帮助信息
help:
	@echo "可用目标:"
	@echo "  make arm              - 编译ARMv8优化版本（推荐用于华为云KC2）"
	@echo "  make arm_aggressive   - 编译ARMv8激进优化版本（最大性能，仅限当前CPU）"
	@echo "  make generic          - 编译通用兼容版本"
	@echo "  make debug            - 编译调试版本"
	@echo "  make profile          - 编译性能分析版本"
	@echo "  make x86              - 编译x86_64测试版本"
	@echo "  make test             - 编译并运行性能测试"
	@echo "  make test_build       - 编译正确性测试"
	@echo "  make test_correctness - 运行正确性测试"
	@echo "  make test_all         - 运行所有测试"
	@echo "  make clean            - 清理编译文件"
	@echo "  make install          - 安装到系统"
	@echo "  make help             - 显示此帮助信息"

.PHONY: all arm arm_aggressive generic debug profile x86 test test_build test_correctness test_all clean install help

