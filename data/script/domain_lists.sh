#!/bin/sh

# Define the URLs
urls="
https://raw.githubusercontent.com/Cats-Team/AdRules/script/script/allowlist.txt
https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-list.txt
# Add other URLs here if needed
"

# Temporary file to hold all domains
temp_file="all_domains.txt"
filtered_file="filtered_domains.txt"

# Step 1: Download, filter, and merge domain lists
for url in $urls; do
  curl -s "$url" | awk 'NF && !/^#|^!/' >> "$temp_file"
done

# Step 2: Save raw domains to filtered_domains.txt
cp "$temp_file" "$filtered_file"

# Step 3: Create allow.txt with @@||...^ format from the filtered file
awk '{ print "@@||" $0 "^" }' "$filtered_file" > allow.txt

# Create the target directory if it does not exist
mkdir -p data/rules

# Move the generated file to the processed folder
mv allow.txt data/rules/
