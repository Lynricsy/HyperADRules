#!/bin/sh
LC_ALL='C'

# Clean up old files
rm *.txt

wait
echo '创建临时文件夹'
mkdir -p ./tmp/

# Copy supplementary rules
# cp ./data/rules/adblock.txt ./tmp/rules01.txt
# cp ./data/rules/whitelist.txt ./tmp/allow01.txt

cd tmp

# Download yhosts rules
curl -s https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts | \
    sed '/0.0.0.0 /!d; /#/d; s/0.0.0.0 /||/; s/$/\^/' > rules001.txt

# Download 大圣净化 rules
curl -s https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts > rules002.txt
sed -i '/视频/d;/奇艺/d;/微信/d;/localhost/d' rules002.txt
sed -i '/127.0.0.1 /!d; s/127\.0\.0\.1 /||/; s/$/\^/' rules002.txt

# Download 乘风视频过滤 rules
curl -s https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt | \
    awk '!/^$/{if($0 !~ /[#^|\/\*\]\[\!]/){print "||"$0"^"} else if($0 ~ /[#\$|@]/){print $0}}' | sort -u > rules003.txt

echo '下载规则'
rules=(
  "https://filters.adtidy.org/android/filters/2_optimized.txt"   # adg基础过滤器
  "https://filters.adtidy.org/android/filters/11_optimized.txt"  # adg移动设备过滤器
  "https://filters.adtidy.org/android/filters/17_optimized.txt"  # adgURL过滤器
  "https://filters.adtidy.org/android/filters/3_optimized.txt"   # adg防跟踪
  "https://filters.adtidy.org/android/filters/224_optimized.txt"  # adg中文过滤器
  "https://perflyst.github.io/PiHoleBlocklist/SmartTV-AGH.txt"    # Tv规则
  "https://easylist-downloads.adblockplus.org/easyprivacy.txt"    # EasyPrivacy隐私保护规则
  "https://raw.githubusercontent.com/Noyllopa/NoAppDownload/master/NoAppDownload.txt"  # 去APP下载提示规则
  "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.adblock"  # d3ward规则
  "https://small.oisd.nl/"                                      # oisd规则
  "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt"  # 秋风规则
  "https://anti-ad.net/easylist.txt"                             # Anti-AD规则
  "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt"  # adblockfilters规则
  "https://mirror.ghproxy.com/raw.githubusercontent.com/8680/GOODBYEADS/master/dns.txt"  # GOODBYEADS规则
)

allow=(
  "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/allowlist.txt"
  "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/GermanFilter/sections/allowlist.txt"
  "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TurkishFilter/sections/allowlist.txt"
  "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/allowlist.txt"
  "https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-list.txt"
  "https://raw.githubusercontent.com/hl2guide/Filterlist-for-AdGuard/master/filter_whitelist.txt"
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt"
  "https://raw.githubusercontent.com/ChengJi-e/AFDNS/master/QD.txt"
  "https://raw.githubusercontent.com/8680/GOODBYEADS/master/allow.txt"
)

# Download rules
for i in "${!rules[@]}"
do
  curl -m 60 --retry-delay 2 --retry 5 -k -L -C - -o "rules${i}.txt" --connect-timeout 60 -s "${rules[$i]}" | iconv -t utf-8 &
done

# Download allow lists
for i in "${!allow[@]}"
do
  curl -m 60 --retry-delay 2 --retry 5 -k -L -C - -o "allow${i}.txt" --connect-timeout 60 -s "${allow[$i]}" | iconv -t utf-8 &
done

# Special handling for additional allow rules
curl -s https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-list.txt | \
    sed 's/^/@@||/g; s/$/&^/g' > allow_special.txt &

wait
echo '规则下载完成'

# Add spaces to files
for i in *.txt; do
  echo -e '\n' >> "$i" &
done
wait

echo '处理规则中'

# Process and clean rules
cat | sort -n | grep -v -E "^((#.*)|(\s*))$" \
  | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|local|loopback)$" \
  | grep -Ev "local.*\.local.*$" \
  | sed s/127.0.0.1/0.0.0.0/g | sed s/::/0.0.0.0/g | grep '0.0.0.0' | grep -Ev '.0.0.0.0 ' | sort \
  | uniq > base-src-hosts.txt &
wait

cat base-src-hosts.txt | grep -Ev '#|\$|@|!|/|\\|\*' \
  | grep -v -E "^((#.*)|(\s*))$" \
  | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|loopback)$" \
  | sed 's/127.0.0.1 //' | sed 's/0.0.0.0 //' \
  | sed "s/^/||&/g" | sed "s/$/&^/g" | sed '/^$/d' \
  | grep -v '^#' \
  | sort -n | uniq | awk '!a[$0]++' \
  | grep -E "^((\|\|)\S+\^)" &  # Hosts rules to ABP rules

cat | sed '/^$/d' | grep -v '#' \
  | sed "s/^/@@||&/g" | sed "s/$/&^/g" \
  | sort -n | uniq | awk '!a[$0]++' &  # Convert allowed domains to ABP rules

cat | sed '/^$/d' | grep -v "#" \
  | sed "s/^/@@||&/g" | sed "s/$/&^/g" | sort -n \
  | uniq | awk '!a[$0]++' &  # Convert allowed domains to ABP rules

cat | sed '/^$/d' | grep -v "#" \
  | sed "s/^/0.0.0.0 &/g" | sort -n \
  | uniq | awk '!a[$0]++' &  # Convert allowed domains to ABP rules

cat *.txt | sed '/^$/d' \
  | grep -E "^\/[a-z]([a-z]|\.)*\.$" \
  | sort -u > l.txt &

cat | sed "s/^/||&/g" | sed "s/$/&^/g" &
cat | sed "s/^/0.0.0.0 &/g" &

echo '开始合并'

# Merge rules
cat rules*.txt \
  | grep -Ev "^((\!)|(\[)).*" \
  | sort -n | uniq | awk '!a[$0]++' > tmp-rules.txt &  # Process AdGuard rules

cat | grep -E "^[(\@\@)|(\|\|)][^\/\^]+\^$" \
  | grep -Ev "([0-9]{1,3}.){3}[0-9]{1,3}" \
  | sort | uniq > ll.txt &
wait

cat *.txt | grep '^@' \
  | sort -n | uniq > tmp-allow.txt &  # Allow list processing

# Combine allow lists
cat tmp-allow.txt allow_special.txt > .././allow.txt

# Combine all rules
cat tmp-rules.txt .././rules.txt > .././rules.txt

echo '规则合并完成'

# Python processing
python .././data/python/rule.py
python .././data/python/filter-dns.py

# Add title and date
python .././data/python/title.py

wait
echo '更新成功'

exit
