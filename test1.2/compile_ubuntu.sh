#!/bin/bash

# Ubuntu/Linux 编译脚本 - AES-SM3完整性校验算法
# SHA2硬件加速版本

set -e  # 遇到错误立即退出

echo "============================================================"
echo "   编译 AES-SM3 完整性校验算法（SHA2硬件加速版）"
echo "============================================================"
echo ""

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 检查是否在ARM平台
ARCH=$(uname -m)
echo -e "${YELLOW}[1] 检测系统架构${NC}"
echo "    架构: $ARCH"

if [[ "$ARCH" == "aarch64" ]]; then
    echo -e "    ${GREEN}✓ ARM64 平台检测成功${NC}"
else
    echo -e "    ${YELLOW}⚠ 警告: 不是ARM64平台，硬件加速可能不可用${NC}"
fi
echo ""

# 检查GCC版本
echo -e "${YELLOW}[2] 检查编译器${NC}"
if command -v gcc &> /dev/null; then
    GCC_VERSION=$(gcc --version | head -n1)
    echo "    $GCC_VERSION"
    echo -e "    ${GREEN}✓ GCC可用${NC}"
else
    echo -e "    ${RED}✗ 错误: 未找到GCC编译器${NC}"
    echo "    请安装: sudo apt-get install build-essential"
    exit 1
fi
echo ""

# 检查CPU特性（仅限ARM）
if [[ "$ARCH" == "aarch64" ]]; then
    echo -e "${YELLOW}[3] 检查CPU硬件特性${NC}"
    if [ -f /proc/cpuinfo ]; then
        FEATURES=$(grep "Features" /proc/cpuinfo | head -1 | cut -d: -f2)
        echo "    CPU特性:$FEATURES"
        
        # 检查关键特性
        if echo "$FEATURES" | grep -q "aes"; then
            echo -e "    ${GREEN}✓ AES 硬件加速支持${NC}"
        else
            echo -e "    ${RED}✗ 无 AES 硬件加速${NC}"
        fi
        
        if echo "$FEATURES" | grep -q "sha2"; then
            echo -e "    ${GREEN}✓ SHA2 硬件加速支持${NC}"
        else
            echo -e "    ${YELLOW}⚠ 无 SHA2 硬件加速（编译可能失败）${NC}"
        fi
        
        if echo "$FEATURES" | grep -q "sm3"; then
            echo -e "    ${GREEN}✓ SM3 硬件加速支持${NC}"
        else
            echo -e "    ${YELLOW}⚠ 无 SM3 硬件加速${NC}"
        fi
        
        if echo "$FEATURES" | grep -q "asimd"; then
            echo -e "    ${GREEN}✓ NEON SIMD 支持${NC}"
        else
            echo -e "    ${YELLOW}⚠ 无 NEON 支持${NC}"
        fi
    fi
    echo ""
fi

# 清理旧文件
echo -e "${YELLOW}[4] 清理旧编译文件${NC}"
make clean > /dev/null 2>&1 || rm -f aes_sm3_integrity_arm aes_sm3_integrity_arm_opt *.o
echo -e "    ${GREEN}✓ 清理完成${NC}"
echo ""

# 编译
echo -e "${YELLOW}[5] 开始编译${NC}"
echo "    编译选项: -march=armv8.2-a+crypto+aes+sha2+sm3+sm4"
echo "    优化级别: -O3 -funroll-loops -ftree-vectorize -flto"
echo ""

# 方法1: 使用Makefile
if [ -f Makefile ]; then
    echo "    使用 Makefile 编译..."
    if make arm; then
        echo ""
        echo -e "    ${GREEN}✓ 标准优化版本编译成功${NC}"
        echo "    生成文件: aes_sm3_integrity_arm"
        COMPILE_SUCCESS=1
    else
        echo ""
        echo -e "    ${RED}✗ 编译失败${NC}"
        COMPILE_SUCCESS=0
    fi
else
    # 方法2: 手动编译
    echo "    使用直接编译命令..."
    if gcc -march=armv8.2-a+crypto+aes+sha2+sm3+sm4 \
           -O3 -funroll-loops -ftree-vectorize -finline-functions \
           -ffast-math -flto -fomit-frame-pointer -pthread \
           -Wall -Wextra \
           -o aes_sm3_integrity_arm aes_sm3_integrity.c \
           -lm -lpthread; then
        echo ""
        echo -e "    ${GREEN}✓ 编译成功${NC}"
        COMPILE_SUCCESS=1
    else
        echo ""
        echo -e "    ${RED}✗ 编译失败${NC}"
        COMPILE_SUCCESS=0
    fi
fi
echo ""

# 编译激进优化版本（可选）
if [ $COMPILE_SUCCESS -eq 1 ] && [ -f Makefile ]; then
    echo -e "${YELLOW}[6] 编译激进优化版本（可选）${NC}"
    if make arm_aggressive 2>/dev/null; then
        echo -e "    ${GREEN}✓ 激进优化版本编译成功${NC}"
        echo "    生成文件: aes_sm3_integrity_arm_opt"
        HAS_AGGRESSIVE=1
    else
        echo -e "    ${YELLOW}⚠ 激进优化版本编译失败（可能不支持-march=native）${NC}"
        HAS_AGGRESSIVE=0
    fi
    echo ""
fi

# 显示编译结果
if [ $COMPILE_SUCCESS -eq 1 ]; then
    echo "============================================================"
    echo -e "   ${GREEN}编译完成！${NC}"
    echo "============================================================"
    echo ""
    echo "生成的可执行文件:"
    echo "  ✓ aes_sm3_integrity_arm (标准优化版)"
    if [ -f aes_sm3_integrity_arm_opt ]; then
        echo "  ✓ aes_sm3_integrity_arm_opt (激进优化版)"
    fi
    echo ""
    echo "程序特性:"
    echo "  • SHA256: 使用ARMv8 SHA2硬件指令加速 ⚡"
    echo "  • SM3:    使用ARMv8 SM3硬件指令加速 ⚡"
    echo "  • SIMD:   使用NEON向量化优化"
    echo "  • 多线程: 支持并行处理"
    echo ""
    echo "运行测试:"
    echo "  ./aes_sm3_integrity_arm"
    if [ -f aes_sm3_integrity_arm_opt ]; then
        echo "  ./aes_sm3_integrity_arm_opt (最大性能)"
    fi
    echo ""
    echo "性能对比说明:"
    echo "  - SHA256使用硬件SHA2指令加速（公平对比）"
    echo "  - SM3使用硬件SM3指令加速"
    echo "  - 多线程测试会自动运行"
    echo ""
else
    echo "============================================================"
    echo -e "   ${RED}编译失败！${NC}"
    echo "============================================================"
    echo ""
    echo "可能的原因:"
    echo "  1. CPU不支持所需的硬件指令集"
    echo "  2. GCC版本过低（需要8.0+）"
    echo "  3. 缺少必要的编译工具"
    echo ""
    echo "解决方法:"
    echo "  1. 检查CPU特性: cat /proc/cpuinfo | grep Features"
    echo "  2. 升级GCC: sudo apt-get install gcc-10"
    echo "  3. 安装工具: sudo apt-get install build-essential"
    echo ""
    exit 1
fi

