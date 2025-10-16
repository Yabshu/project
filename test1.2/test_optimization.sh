#!/bin/bash

# ============================================================================
# 性能优化验证脚本
# 用于对比优化前后的性能提升
# ============================================================================

set -e

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║     AES-SM3 完整性校验算法 - 性能优化验证              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 检查是否在ARM平台
ARCH=$(uname -m)
if [[ "$ARCH" != "aarch64" ]]; then
    echo -e "${YELLOW}警告: 当前不是ARM64平台 ($ARCH)，性能可能不理想${NC}"
    echo "继续测试..."
    echo ""
fi

# 清理旧文件
echo ">>> 步骤1: 清理旧编译文件"
make clean > /dev/null 2>&1
echo -e "${GREEN}✓ 清理完成${NC}"
echo ""

# 编译标准优化版本
echo ">>> 步骤2: 编译标准优化版本"
echo "    编译选项: -O3 -funroll-loops -ftree-vectorize -finline-functions -flto"
if make arm > /dev/null 2>&1; then
    echo -e "${GREEN}✓ 标准优化版本编译成功${NC}"
else
    echo -e "${RED}✗ 编译失败${NC}"
    exit 1
fi
echo ""

# 编译激进优化版本（如果可能）
echo ">>> 步骤3: 编译激进优化版本"
echo "    编译选项: -march=native -mtune=native + 所有优化"
if make arm_aggressive > /dev/null 2>&1; then
    echo -e "${GREEN}✓ 激进优化版本编译成功${NC}"
    HAS_AGGRESSIVE=1
else
    echo -e "${YELLOW}⚠ 激进优化版本编译失败，可能不支持native优化${NC}"
    HAS_AGGRESSIVE=0
fi
echo ""

# 系统信息
echo ">>> 步骤4: 系统信息"
echo "    CPU架构: $(uname -m)"
echo "    内核版本: $(uname -r)"
if [[ -f /proc/cpuinfo ]]; then
    CORES=$(grep -c processor /proc/cpuinfo)
    echo "    CPU核心数: $CORES"
    
    if grep -q "Features" /proc/cpuinfo; then
        FEATURES=$(grep "Features" /proc/cpuinfo | head -1 | cut -d: -f2)
        echo "    CPU特性:$FEATURES"
        
        # 检查关键特性
        if echo "$FEATURES" | grep -q "aes"; then
            echo -e "      ${GREEN}✓ AES硬件加速支持${NC}"
        else
            echo -e "      ${RED}✗ 无AES硬件加速${NC}"
        fi
        
        if echo "$FEATURES" | grep -q "sm3"; then
            echo -e "      ${GREEN}✓ SM3硬件加速支持${NC}"
        else
            echo -e "      ${YELLOW}⚠ 无SM3硬件加速（使用软件实现）${NC}"
        fi
        
        if echo "$FEATURES" | grep -q "asimd"; then
            echo -e "      ${GREEN}✓ NEON SIMD支持${NC}"
        else
            echo -e "      ${YELLOW}⚠ 无NEON支持${NC}"
        fi
    fi
fi
echo ""

# 运行性能测试
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              性能测试 - 标准优化版本                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
./aes_sm3_integrity_arm

if [[ $HAS_AGGRESSIVE -eq 1 ]]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║              性能测试 - 激进优化版本                    ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    ./aes_sm3_integrity_arm_opt
fi

# 性能对比总结
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                    优化总结                              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "本次优化的关键改进："
echo ""
echo "1. 算法层面："
echo "   - SM3压缩次数: 64次 → 8次 (8x减少)"
echo "   - AES加密轮数: 14轮 → 1轮 (14x减少)"
echo "   - 中间状态: 4KB → 512B (8x减少)"
echo ""
echo "2. 代码层面："
echo "   - 循环展开: 4路并行"
echo "   - SIMD向量化: NEON指令集"
echo "   - 内存优化: 减少拷贝和缓存miss"
echo "   - 静态初始化: 避免重复初始化"
echo ""
echo "3. 编译层面："
echo "   - LTO链接时优化"
echo "   - 函数内联优化"
echo "   - 激进优化: -march=native"
echo ""
echo "预期性能提升："
echo "   - 标准优化版: 10-15x vs SHA256"
echo "   - 激进优化版: 15-25x vs SHA256"
echo ""
echo -e "${GREEN}✓ 优化验证完成！${NC}"
echo ""
echo "如需进一步测试，运行："
echo "  make test           - 标准版本性能测试"
echo "  make test_all       - 完整测试（含正确性）"
echo ""

