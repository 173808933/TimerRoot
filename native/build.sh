#!/bin/sh
# Build the conf-driven exploit for arm64 Android.
#
#   NDK=/opt/android-ndk sh native/build.sh          # -> app/src/main/assets/timer
#   NDK=... sh native/build.sh /tmp/timer            # 自定义输出
#   CC=aarch64-linux-android35-clang sh native/build.sh
#
# 静态链接、无 libc++ 依赖，直接 push 到 /data/local/tmp 就能跑。
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
out=${1:-$root/app/src/main/assets/timer}

if [ -n "${CC:-}" ]; then
    cc=$CC
else
    : "${NDK:?set NDK=/path/to/android-ndk (or pass CC=aarch64-linux-android*-clang)}"
    case "$(uname -s)" in
        Linux*)               host=linux-x86_64 ;;
        Darwin*)              host=darwin-x86_64 ;;
        MINGW*|MSYS*|CYGWIN*) host=windows-x86_64 ;;
        *) echo "unsupported host: $(uname -s)" >&2; exit 1 ;;
    esac
    bin=$NDK/toolchains/llvm/prebuilt/$host/bin
    api=${API:-35}
    cc=$bin/aarch64-linux-android${api}-clang
    if [ ! -x "$cc" ] && [ -x "$cc.cmd" ]; then
        cc=$cc.cmd           # Windows 的包装器是 .cmd
    fi
fi

"$cc" -O2 -std=gnu11 -static -fno-stack-protector -fno-pic \
    -ffunction-sections -fdata-sections -I"$here" \
    "$here/timer.c" -o "$out" \
    -Wl,--gc-sections -Wl,-s -Wl,--build-id=none -Wl,-z,norelro -pthread

echo "built $out ($(wc -c < "$out" | tr -d ' ') bytes)"
