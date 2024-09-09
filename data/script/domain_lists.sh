#!/bin/sh

set -e  # 在命令出错时立即退出脚本，并返回非零退出码
set -x  # 输出每一条命令在执行时的状态

# Define the URLs
urls="
https://raw.githubusercontent.com/Cats-Team/AdRules/script/script/allowlist.txt
https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-list.txt
"

# Temporary file to hold all domains
temp_file="all_domains.txt"
filtered_file="filtered_domains.txt"

# Step 1: Download, filter, and merge domain lists
for url in $urls; do
  echo "Processing URL: $url"
  curl -s "$url" | awk 'NF && !/^#|^!/' >> "$temp_file" || { echo "Failed to process $url"; exit 1; }
done

# Step 2: Save raw domains to filtered_domains.txt
cp "$temp_file" "$filtered_file" || { echo "Failed to copy to filtered file"; exit 1; }

# Step 3: Create allow.txt with @@||...^ format from the filtered file
awk '{ print "@@||" $0 "^" }' "$filtered_file" > allow.txt || { echo "Failed to create allow.txt"; exit 1; }

# Create the target directory if it does not exist
mkdir -p data/rules || { echo "Failed to create directory"; exit 1; }

# Move the generated file to the processed folder
mv allow.txt data/rules/ || { echo "Failed to move allow.txt"; exit 1; }

echo "Script executed successfully."
