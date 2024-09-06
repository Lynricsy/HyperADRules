#!/bin/sh
LC_ALL='C'

rm *.txt

wait
echo '创建临时文件夹'
mkdir -p ./tmp/

#添加补充规则
cp ./data/rules/adblock.txt ./tmp/rules01.txt
cp ./data/rules/whitelist.txt ./tmp/allow01.txt

cd tmp
#下载yhosts规则
curl https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts | sed '/0.0.0.0 /!d; /#/d; s/0.0.0.0 /||/; s/$/\^/' > rules001.txt

#下载大圣净化规则
curl https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts > rules002.txt
sed -i '/视频/d;/奇艺/d;/微信/d;/localhost/d' rules002.txt
sed -i '/127.0.0.1 /!d; s/127\.0\.0\.1 /||/; s/$/\^/' rules002.txt

#下载乘风视频过滤规则
curl https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt | awk '!/^$/{if($0 !~ /[#^|\/\*\]\[\!]/){print "||"$0"^"} else if($0 ~ /[#\$|@]/){print $0}}' | sort -u > rules003.txt


echo '下载规则'
rules=(
  "https://filters.adtidy.org/android/filters/2_optimized.txt" #adg基础过滤器
  "https://filters.adtidy.org/android/filters/11_optimized.txt" #adg移动设备过滤器
  "https://filters.adtidy.org/android/filters/17_optimized.txt"  #adgURL过滤器
  "https://filters.adtidy.org/android/filters/3_optimized.txt" #adg防跟踪
  "https://filters.adtidy.org/android/filters/224_optimized.txt" #adg中文过滤器
  "https://perflyst.github.io/PiHoleBlocklist/SmartTV-AGH.txt" #Tv规则
  "https://easylist-downloads.adblockplus.org/easyprivacy.txt" #EasyPrivacy隐私保护规则
  "https://raw.githubusercontent.com/Noyllopa/NoAppDownload/master/NoAppDownload.txt" #去APP下载提示规则
  "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.adblock" #d3ward规则
  "https://small.oisd.nl/" #oisd规则
  "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt" #秋风规则
  "https://anti-ad.net/easylist.txt" #Anti-AD规则
  "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt" #adblockfilters规则
  "https://mirror.ghproxy.com/raw.githubusercontent.com/8680/GOODBYEADS/master/dns.txt" #GOODBYEADS规则
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

for i in "${!rules[@]}" "${!allow[@]}"
do
  curl -m 60 --retry-delay 2 --retry 5 --parallel --parallel-immediate -k -L -C - -o "rules${i}.txt" --connect-timeout 60 -s "${rules[$i]}" |iconv -t utf-8 &
  curl -m 60 --retry-delay 2 --retry 5 --parallel --parallel-immediate -k -L -C - -o "allow${i}.txt" --connect-timeout 60 -s "${allow[$i]}" |iconv -t utf-8 &
done
wait
echo '规则下载完成'

# 添加空格
file="$(ls|sort -u)"
for i in $file; do
  echo -e '\n' >> $i &
done
wait

echo '处理规则中'

cat | sort -n| grep -v -E "^((#.*)|(\s*))$" \
 | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|local|loopback)$" \
 | grep -Ev "local.*\.local.*$" \
 | sed s/127.0.0.1/0.0.0.0/g | sed s/::/0.0.0.0/g |grep '0.0.0.0' |grep -Ev '.0.0.0.0 ' | sort \
 |uniq >base-src-hosts.txt &
wait
cat base-src-hosts.txt | grep -Ev '#|\$|@|!|/|\\|\*'\
 | grep -v -E "^((#.*)|(\s*))$" \
 | grep -v -E "^[0-9f\.:]+\s+(ip6\-)|(localhost|loopback)$" \
 | sed 's/127.0.0.1 //' | sed 's/0.0.0.0 //' \
 | sed "s/^/||&/g" |sed "s/$/&^/g"| sed '/^$/d' \
 | grep -v '^#' \
 | sort -n | uniq | awk '!a[$0]++' \
 | grep -E "^((\|\|)\S+\^)" & #Hosts规则转ABP规则

cat | sed '/^$/d' | grep -v '#' \
 | sed "s/^/@@||&/g" | sed "s/$/&^/g"  \
 | sort -n | uniq | awk '!a[$0]++' & #将允许域名转换为ABP规则

cat | sed '/^$/d' | grep -v "#" \
 |sed "s/^/@@||&/g" | sed "s/$/&^/g" | sort -n \
 | uniq | awk '!a[$0]++' & #将允许域名转换为ABP规则

cat | sed '/^$/d' | grep -v "#" \
 |sed "s/^/0.0.0.0 &/g" | sort -n \
 | uniq | awk '!a[$0]++' & #将允许域名转换为ABP规则

cat *.txt | sed '/^$/d' \
 |grep -E "^\/[a-z]([a-z]|\.)*\.$" \
 |sort -u > l.txt &

cat \
 | sed "s/^/||&/g" | sed "s/$/&^/g" &

cat \
 | sed "s/^/0.0.0.0 &/g" &


echo 开始合并

cat rules*.txt \
 |grep -Ev "^((\!)|(\[)).*" \
 | sort -n | uniq | awk '!a[$0]++' > tmp-rules.txt & #处理AdGuard的规则

cat \
 | grep -E "^[(\@\@)|(\|\|)][^\/\^]+\^$" \
 | grep -Ev "([0-9]{1,3}.){3}[0-9]{1,3}" \
 | sort | uniq > ll.txt &
wait


cat *.txt | grep '^@' \
 | sort -n | uniq > tmp-allow.txt & #允许清单处理
wait

cp tmp-allow.txt .././allow.txt
cp tmp-rules.txt .././rules.txt

echo 规则合并完成

# Python 处理重复规则
python .././data/python/rule.py
python .././data/python/filter-dns.py

# Start Add title and date
python .././data/python/title.py


wait
echo '更新成功'

exit
