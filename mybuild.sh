#!/bin/bash
set -euo pipefail

# 固定记录编译开始时间，按北京时间生成文件名。
BUILD_TIMESTAMP="$(date +%s)"
export BUILD_TIMESTAMP
build_started_at="$(TZ=Asia/Shanghai date -r "$BUILD_TIMESTAMP" '+%Y%m%d_%H%M%S')"

source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
build_dir="$(dirname "$source_dir")/__build_roothide/$(basename "$source_dir")"

clean_build=false
# 默认四任务并行，排查编译错误时可传入 -j1。
make_jobs="-j4"
while (( $# > 0 )); do
    case "$1" in
        --clean) clean_build=true ;;
        -j|-j?*)
            if [[ "$1" == -j ]]; then
                shift
                job_count="${1:-}"
            else
                job_count="${1#-j}"
            fi
            if [[ ! "$job_count" =~ ^[1-9][0-9]*$ ]]; then
                printf '并行任务数必须为正整数，例如 -j4 或 -j 4\n' >&2
                exit 2
            fi
            make_jobs="-j$job_count"
            ;;
        *) printf '用法：%s [--clean] [-jN | -j N]（默认 -j4，排错可用 -j1）\n' "$0" >&2; exit 2 ;;
    esac
    shift
done

# 使用 xcode-select 选中的默认 Xcode。
unset DEVELOPER_DIR
export BUILD_STANDALONE=0
export NIGHTLY=0
for tool in make xcodebuild xcrun ldid trustcache unzip plutil rsync; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf '缺少构建工具：%s\n' "$tool" >&2
        exit 1
    fi
done
xcodebuild -version
printf '编译开始（北京时间）：%s\n' "$build_started_at"

# 同步到独立目录，排除版本库、签名资料和不能跨目录复用的缓存。
mkdir -p "$build_dir"
build_dir="$(cd "$build_dir" && pwd -P)"
case "$build_dir/" in
    "$source_dir/"*) printf '构建目录不能位于原项目内：%s\n' "$build_dir" >&2; exit 1 ;;
esac
case "$source_dir/" in
    "$build_dir/"*) printf '构建目录不能包含原项目：%s\n' "$build_dir" >&2; exit 1 ;;
esac
printf '源码目录：%s\n构建目录：%s\n' "$source_dir" "$build_dir"
rsync -a --delete \
    --exclude='.git' --exclude='.DS_Store' --exclude='.sign/' \
    --exclude='/worker/' --exclude='/docs/' \
    --exclude='build/' --exclude='.build/' --exclude='.include/' \
    --exclude='.theos/' --exclude='output/' --exclude='*.dSYM/' \
    --exclude='DerivedData/' --exclude='xcuserdata/' \
    --exclude='/Application/Payload/' \
    --exclude='/Application/Dopamine.ipa' --exclude='/Application/Dopamine.tipa' \
    --exclude='/.build-location' \
    "$source_dir/" "$build_dir/"
cd "$build_dir"

# 由项目根 Makefile 统一安排编译和打包。
make "$make_jobs"

# 仅发布构建成功且压缩校验通过的 IPA。
ipa_path="$build_dir/Application/Dopamine.ipa"
unzip -tq "$ipa_path"
# 从本次生成的 IPA 读取实际版本，避免文件名与包内版本不一致。
version="$(unzip -p "$ipa_path" Payload/Dopamine.app/Info.plist | plutil -extract CFBundleShortVersionString raw -o - -)"
if [[ ! "$version" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]*$ ]]; then
    printf '无法用于文件名的版本号：%s\n' "$version" >&2
    exit 1
fi
destination_dir="${HOME:?HOME 未设置}/www/html/TS"
destination_path="$destination_dir/Dopamine_roothide_zqbb_${version}_${build_started_at}.ipa"
mkdir -p "$destination_dir"

# 在目标目录内原子替换，避免下载到复制了一半的文件。
temporary_ipa="$(mktemp "$destination_dir/.Dopamine.ipa.XXXXXX")"
trap 'rm -f -- "$temporary_ipa"' EXIT
cp "$ipa_path" "$temporary_ipa"
chmod 644 "$temporary_ipa"
mv -f -- "$temporary_ipa" "$destination_path"
# 使用同目录相对链接，并在 IPA 完整复制后原子更新 latest。
latest_path="$destination_dir/Dopamine_roothide_zqbb_latest.ipa"
ln -s "$(basename "$destination_path")" "$temporary_ipa"
mv -fh -- "$temporary_ipa" "$latest_path"
trap - EXIT

# IPA 与 latest 都已就绪后，离开并删除临时构建目录。
cd "$source_dir"
rm -rf -- "$build_dir"
printf '\n编译完成，IPA 已复制到：%s\n' "$destination_path"
printf '最新版本软链接：%s\n' "$latest_path"
printf '临时构建目录已删除：%s\n' "$build_dir"
