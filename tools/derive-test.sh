#!/bin/sh
# 在桌面 JVM 上跑设备端的推导逻辑，用来在改完 ota/ 之后先对拍、再上机。
#
#   sh tools/derive-test.sh boot.img [out.conf]
#
# Kotlin 那三个文件只依赖 java.*，所以不需要 Android SDK 也能编、能跑。
# 编译器与 stdlib 从 Gradle 缓存里取（和 scripts/build.ps1 同一套来源），
# 也可以用 KOTLIN_COMPILER / KOTLIN_STDLIB 显式指定。
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
img=${1:?usage: sh tools/derive-test.sh <boot.img|Image> [out.conf]}
out=${2:-}

m2=${GRADLE_M2:-$HOME/.gradle/caches/modules-2/files-2.1}
pick() { # pick <dir> <name-glob>
    [ -d "$1" ] || return 0
    ls -1t $(find "$1" -name "$2" -type f 2>/dev/null) 2>/dev/null | head -1
}

KC=${KOTLIN_COMPILER:-$(pick "$m2/org.jetbrains.kotlin/kotlin-compiler-embeddable" 'kotlin-compiler-embeddable-*.jar')}
ST=${KOTLIN_STDLIB:-$(pick "$m2/org.jetbrains.kotlin/kotlin-stdlib" 'kotlin-stdlib-*.jar')}
CO=$(pick "$m2/org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm" 'kotlinx-coroutines-core-jvm-*.jar')
TR=$(pick "$m2/org.jetbrains.intellij.deps/trove4j" 'trove4j-*.jar')
AN=$(pick "$m2/org.jetbrains/annotations" 'annotations-*.jar')

[ -n "$KC" ] && [ -n "$ST" ] || {
    echo "找不到 Kotlin 编译器/标准库；用 KOTLIN_COMPILER=... KOTLIN_STDLIB=... 指定" >&2
    exit 1
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

JAVA=${JAVA:-java}
JAVAC=${JAVAC:-javac}

echo "[1/3] kotlinc"
"$JAVA" -cp "$KC:$ST:$CO:$TR:$AN" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
    -no-stdlib -no-reflect -classpath "$ST:$AN" -d "$work/classes" \
    "$root/app/src/main/kotlin/com/kpgc/timerroot/ota"

echo "[2/3] harness"
cat > "$work/DeriveMain.java" <<'EOF'
public class DeriveMain {
    public static void main(String[] a) throws Exception {
        Class<?> c = Class.forName("com.kpgc.timerroot.ota.Deriver");
        System.out.print(c.getMethod("derive", String.class).invoke(null, a[0]));
    }
}
EOF
"$JAVAC" -d "$work/classes" "$work/DeriveMain.java"

# 把 stdlib 摊进 classes，这样 -cp 只有一个路径 —— Git Bash 下多段
# POSIX 类路径（a:b:c）传给 Windows 的 java 时不会被正确转换。
( cd "$work/classes" && unzip -oq "$ST" )

echo "[3/3] derive $img"
if [ -n "$out" ]; then
    "$JAVA" -Xmx3g -cp "$work/classes" DeriveMain "$img" > "$out"
    echo "-> $out"
else
    "$JAVA" -Xmx3g -cp "$work/classes" DeriveMain "$img"
fi
