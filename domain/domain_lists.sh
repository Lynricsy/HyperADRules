#!/bin/sh

set -e  # 在命令出错时立即退出脚本，并返回非零退出码
set -x  # 输出每一条命令在执行时的状态

# 定义要处理的 URL 列表
urls="
https://raw.githubusercontent.com/Cats-Team/AdRules/script/script/allowlist.txt
https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-list.txt
"

# 定义临时文件和输出文件的名称
temp_file="all_domains.txt"
output_file="allow1.txt"  # 修改输出文件名为 allow1.txt

# 清空临时文件和输出文件
> "$temp_file"
> "$output_file"

# 下载、过滤并合并所有域名列表
for url in $urls; do
  echo "Processing URL: $url"
  curl -s "$url" | awk 'NF && !/^#|^!/' >> "$temp_file" || { echo "Failed to process $url"; exit 1; }
done

# 创建最终的 allow1.txt 文件，添加 @@||...^ 格式
awk '{ print "@@||" $0 "^" }' "$temp_file" > "$output_file" || { echo "Failed to create $output_file"; exit 1; }

# 输出生成的文件路径
echo "Generated file: $output_file"  # 这里关闭引号

# 可选：查看生成的文件内容
cat "$output_file"
