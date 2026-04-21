#!/bin/bash

# 获取 macOS 版本号
get_macos_version() {
    local version
    version=$(sw_vers -productVersion)
    echo "$version"
}

# 主函数
main() {
    echo "🔍 macOS Launchd 服务信息提取脚本"
    echo "=" * 50

    # 获取 macOS 版本
    MACOS_VERSION=$(get_macos_version)
    if [ -z "$MACOS_VERSION" ]; then
        echo "❌ 无法获取 macOS 版本号"
        exit 1
    fi

    echo "📱 当前 macOS 版本: $MACOS_VERSION"

    # 检查是否已存在当前版本的文件
    RESOURCE_ROOT="$(pwd)/SystemResource"
    FOLDER_NAME="${RESOURCE_ROOT}/macOS-${MACOS_VERSION}"
    ARCHIVE_NAME="${RESOURCE_ROOT}/macOS-${MACOS_VERSION}.tar.gz"

    if [ -d "$FOLDER_NAME" ] || [ -f "$ARCHIVE_NAME" ]; then
        echo "ℹ️  当前版本 $MACOS_VERSION 的文件已存在，跳过抓取"
        echo "📂 现有文件位置: $FOLDER_NAME"
        if [ -f "$ARCHIVE_NAME" ]; then
            echo "📦 压缩包位置: $ARCHIVE_NAME"
        fi
        exit 0
    fi

    # 创建 SystemResource 下的版本文件夹
    mkdir -p "$FOLDER_NAME"

    echo "📁 创建文件夹: $FOLDER_NAME"

    # 设置输出文件路径（保存到版本文件夹）
    OUTPUT_FILE="${FOLDER_NAME}/launchd_summary.json"

    # 调用 Python 脚本
    echo "🚀 调用 extract_service.py..."
    if python3 extract_service.py "$OUTPUT_FILE"; then
        echo "✅ 成功生成文件: $OUTPUT_FILE"

        # 显示文件信息
        if [ -f "$OUTPUT_FILE" ]; then
            FILE_SIZE=$(stat -f%z "$OUTPUT_FILE")
            echo "📄 文件大小: $FILE_SIZE 字节 ($((FILE_SIZE / 1024)) KB)"
        fi

        echo "📂 文件位置: $(pwd)/$OUTPUT_FILE"

        # 压缩版本文件夹到 SystemResource 下的归档文件
        ARCHIVE_NAME="${RESOURCE_ROOT}/macOS-${MACOS_VERSION}.tar.gz"
        echo "📦 正在压缩: $FOLDER_NAME -> $ARCHIVE_NAME"
        if tar -czf "$ARCHIVE_NAME" -C "$RESOURCE_ROOT" "macOS-${MACOS_VERSION}"; then
            ARCHIVE_SIZE=$(stat -f%z "$ARCHIVE_NAME")
            echo "✅ 压缩成功: $ARCHIVE_NAME"
            echo "📦 压缩包大小: $ARCHIVE_SIZE 字节 ($((ARCHIVE_SIZE / 1024 / 1024)) MB)"
        else
            echo "❌ 压缩失败"
        fi
    else
        echo "❌ Python 脚本执行失败"
        exit 1
    fi

    echo ""
    echo "🎉 完成！"
}

# 执行主函数
main "$@"