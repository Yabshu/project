#!/bin/bash
# 华为云KC2平台部署脚本
# ARMv8.2 AES-SM3完整性校验算法

set -e  # 遇到错误立即退出

echo "============================================================"
echo "  华为云KC2平台 - AES-SM3完整性校验算法部署"
echo "============================================================"
echo ""

# 检查运行环境
echo "[1/6] 检查运行环境..."

# 检查架构
ARCH=$(uname -m)
if [ "$ARCH" != "aarch64" ]; then
    echo "⚠️  警告: 当前架构为 $ARCH，非ARMv8架构"
    echo "   程序将使用软件实现，性能会显著下降"
else
    echo "✓ 架构检查通过: $ARCH"
fi

# 检查CPU特性
echo ""
echo "检查CPU特性..."
if [ -f /proc/cpuinfo ]; then
    CPU_FEATURES=$(cat /proc/cpuinfo | grep Features | head -n 1)
    echo "CPU特性: $CPU_FEATURES"
    
    # 检查关键特性
    REQUIRED_FEATURES=("aes" "sha2" "asimd")
    OPTIONAL_FEATURES=("sm3" "sm4")
    
    for feature in "${REQUIRED_FEATURES[@]}"; do
        if echo "$CPU_FEATURES" | grep -q "$feature"; then
            echo "  ✓ $feature 支持"
        else
            echo "  ✗ $feature 不支持 (性能会下降)"
        fi
    done
    
    for feature in "${OPTIONAL_FEATURES[@]}"; do
        if echo "$CPU_FEATURES" | grep -q "$feature"; then
            echo "  ✓ $feature 支持 (可选)"
        else
            echo "  △ $feature 不支持 (将使用软件实现)"
        fi
    done
else
    echo "⚠️  无法读取CPU信息"
fi

# 检查编译器
echo ""
echo "[2/6] 检查编译环境..."

if ! command -v gcc &> /dev/null; then
    echo "✗ GCC未安装，正在安装..."
    sudo apt-get update
    sudo apt-get install -y build-essential
else
    GCC_VERSION=$(gcc --version | head -n 1)
    echo "✓ GCC已安装: $GCC_VERSION"
fi

# 检查必要的库
echo ""
echo "[3/6] 检查依赖库..."

if ! ldconfig -p | grep -q libpthread; then
    echo "✗ pthread库未找到，正在安装..."
    sudo apt-get install -y libc6-dev
else
    echo "✓ pthread库已安装"
fi

# 编译程序
echo ""
echo "[4/6] 编译程序..."

if [ -f "Makefile" ]; then
    echo "使用Makefile编译..."
    make clean
    
    if [ "$ARCH" = "aarch64" ]; then
        make arm
        BINARY="aes_sm3_integrity_arm"
    else
        make generic
        BINARY="aes_sm3_integrity_generic"
    fi
    
    if [ -f "$BINARY" ]; then
        echo "✓ 编译成功: $BINARY"
    else
        echo "✗ 编译失败"
        exit 1
    fi
else
    echo "Makefile未找到，使用直接编译..."
    
    if [ "$ARCH" = "aarch64" ]; then
        gcc -march=armv8.2-a+crypto+aes+sm3+sm4 -O3 -funroll-loops \
            -ftree-vectorize -pthread -o aes_sm3_integrity_arm \
            aes_sm3_integrity.c -lm -lpthread
        BINARY="aes_sm3_integrity_arm"
    else
        gcc -O3 -pthread -o aes_sm3_integrity_generic \
            aes_sm3_integrity.c -lm -lpthread
        BINARY="aes_sm3_integrity_generic"
    fi
    
    echo "✓ 编译成功: $BINARY"
fi

# 性能调优
echo ""
echo "[5/6] 系统性能调优..."

# 设置CPU调度器为性能模式
if command -v cpupower &> /dev/null; then
    echo "设置CPU为性能模式..."
    sudo cpupower frequency-set -g performance 2>/dev/null || echo "  需要root权限，跳过"
else
    echo "cpupower未安装，跳过CPU调优"
fi

# 检查透明大页
if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
    THP_STATUS=$(cat /sys/kernel/mm/transparent_hugepage/enabled)
    echo "透明大页状态: $THP_STATUS"
    
    if [[ ! "$THP_STATUS" =~ "always" ]]; then
        echo "尝试启用透明大页..."
        sudo sh -c 'echo always > /sys/kernel/mm/transparent_hugepage/enabled' 2>/dev/null || \
            echo "  需要root权限，跳过"
    fi
fi

# 运行测试
echo ""
echo "[6/6] 运行性能测试..."
echo "============================================================"
echo ""

./$BINARY

# 测试完成
echo ""
echo "============================================================"
echo "  部署和测试完成"
echo "============================================================"
echo ""
echo "可执行文件: ./$BINARY"
echo ""
echo "使用方法:"
echo "  1. 单次运行:  ./$BINARY"
echo "  2. 重复测试:  for i in {1..5}; do ./$BINARY; done"
echo "  3. 后台运行:  nohup ./$BINARY > output.log 2>&1 &"
echo ""
echo "性能优化建议:"
echo "  - 确保CPU频率锁定在最高频率"
echo "  - 关闭不必要的后台进程"
echo "  - 使用taskset绑定CPU核心"
echo ""

