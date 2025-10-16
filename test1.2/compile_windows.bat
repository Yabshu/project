@echo off
REM Windows编译脚本 - AES-SM3完整性校验算法
REM 包含SHA2硬件加速支持

echo ============================================================
echo    编译 AES-SM3 完整性校验算法（SHA2硬件加速版）
echo ============================================================
echo.

REM 设置编译选项
set CC=gcc
set CFLAGS=-O3 -funroll-loops -ftree-vectorize -finline-functions -ffast-math -flto -fomit-frame-pointer -pthread -Wall -Wextra
set ARM_FLAGS=-march=armv8.2-a+crypto+aes+sha2+sm3+sm4
set LIBS=-lm -lpthread

echo [1] 清理旧文件...
if exist aes_sm3_integrity.exe del aes_sm3_integrity.exe
if exist aes_sm3_integrity_arm.exe del aes_sm3_integrity_arm.exe
if exist *.o del *.o
echo    ✓ 清理完成
echo.

echo [2] 检测编译环境...
gcc --version
echo.

echo [3] 编译程序...
echo    使用选项: %ARM_FLAGS% %CFLAGS%
echo.

REM ARM平台编译（如果在ARM Windows上）
%CC% %ARM_FLAGS% %CFLAGS% -o aes_sm3_integrity_arm.exe aes_sm3_integrity.c %LIBS%

if %ERRORLEVEL% EQU 0 (
    echo    ✓ 编译成功！生成: aes_sm3_integrity_arm.exe
    echo.
    echo [4] 程序信息
    echo    - SHA256: 使用ARMv8 SHA2硬件指令加速
    echo    - SM3:    使用ARMv8 SM3硬件指令加速  
    echo    - 多线程: 支持（pthread）
    echo.
    echo ============================================================
    echo    编译完成！可以运行测试了
    echo ============================================================
    echo.
    echo 运行命令: aes_sm3_integrity_arm.exe
    echo.
) else (
    echo    ✗ 编译失败！
    echo.
    echo 可能原因:
    echo    1. 不在ARM平台上
    echo    2. GCC版本不支持ARM指令集
    echo    3. 缺少必要的库
    echo.
    echo 尝试通用编译（无硬件加速）...
    %CC% %CFLAGS% -o aes_sm3_integrity.exe aes_sm3_integrity.c %LIBS%
    
    if %ERRORLEVEL% EQU 0 (
        echo    ✓ 通用版本编译成功！
        echo    ⚠  注意: 此版本不包含硬件加速
        echo.
        echo 运行命令: aes_sm3_integrity.exe
    ) else (
        echo    ✗ 编译失败！请检查编译环境
    )
)

pause

