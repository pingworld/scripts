#!/bin/bash
# v2ray centos系统一键安装脚本
# Author: hijk<https://www.hijk.pw>

echo "#############################################################"
echo "#         CentOS 7/8 v2ray 带伪装一键安装脚本               #"
echo "# 网址: https://www.hijk.pw                                 #"
echo "# 作者: hijk                                                #"
echo "#############################################################"
echo ""

red='\033[0;31m'
green="\033[0;32m"
plain='\033[0m'

sites=(
http://www.zhuizishu.com/
http://xs.56dyc.com/
http://www.xiaoshuosk.com/
https://www.x33xs.com/
http://www.wutuxs.com/
https://www.23xsw.cc/
https://www.44pq.cc/
https://www.23us.us/
https://www.quledu.net/
http://www.ddxsku.com/
http://www.biqu6.com/
https://www.abcxs.com/
https://www.23hh.la/
)

function checkSystem()
{
    result=$(id | awk '{print $1}')
    if [ $result != "uid=0(root)" ]; then
        echo "run as root"
        exit 1
    fi

    if [ ! -f /etc/centos-release ];then
        echo "system is not CentOS"
        exit 1
    fi
    
    result=`cat /etc/centos-release|grep -oE "[0-9.]+"`
    main=${result%%.*}
    if [ $main -lt 7 ]; then
        echo "unsupport CentOS version!"
        exit 1
    fi
}

function getData()
{
    yum install -y bind-utils curl
    IP=`curl -s -4 icanhazip.com`
    echo " "
    echo " check conditions："
    echo -e "  ${red}1. domain${plain}"
    echo -e "  ${red}2. server IP which domain will be resolved to(${IP})${plain}"
    echo " "
    read -p "YES/NO?" answer
    if [ "${answer}" != "y" ]; then
        exit 0
    fi

    while true
    do
        read -p "domain name:" domain
        if [ -z "${domain}" ]; then
            echo "Wrong domain name, retry again!"
        else
            break
        fi
    done
    
    res=`host ${domain}`
    res=`echo -n ${res} | grep ${IP}`
    if [ -z "${res}" ]; then
        echo -n "${domain} Resolved result:"
        host ${domain}
        echo "Domain can't be resolved to IP(${IP})!"
        exit 1
    fi

    while true
    do
        read -p "Input masquerading path, begin with/:" path
        if [ -z "${path}" ]; then
            echo "Input masquerading path, begin with/ !!"
        elif [ "${path:0:1}" != "/" ]; then
            echo "Masquerading path must be begin with/ !!"
        elif [ "${path}" = "/" ]; then
            echo  "Can't be root path !!"
        else
            break
        fi
    done
    
    len=${#sites[@]}
    ((len--))
    index=`shuf -i0-${len} -n1`
    site=$sites[$index]
}

function preinstall()
{
    sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 60/' /etc/ssh/sshd_config
    systemctl restart sshd
    ret=`nginx -t`
    if [ "$?" != "0" ]; then
        echo "Update system..."
        yum update -y
    fi
    echo "Install neccessary dependancy..."
    yum install -y epel-release telnet wget vim net-tools ntpdate unzip

    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
        setenforce 0
    fi
}

function installV2ray()
{
    echo "Install v2ray..."
    bash <(curl -L -s https://install.direct/go.sh)

    if [ ! -f /etc/v2ray/config.json ]; then
        echo "Install failed !!!"
        exit 1
    fi

    logsetting=`cat /etc/v2ray/config.json|grep loglevel`
    if [ "${logsetting}" = "" ]; then
        sed -i '1a\  "log": {\n    "loglevel": "info",\n    "access": "/var/log/v2ray/access.log",\n    "error": "/var/log/v2ray/error.log"\n  },' /etc/v2ray/config.json
    fi
    alterid=`shuf -i50-90 -n1`
    sed -i -e "s/alterId\":.*[0-9]*/alterId\": ${alterid}/" /etc/v2ray/config.json
    uid=`cat /etc/v2ray/config.json | grep id | cut -d: -f2 | tr -d \",' '`
    port=`cat /etc/v2ray/config.json | grep port | cut -d: -f2 | tr -d \",' '`
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
    ntpdate -u time.nist.gov
    res=`cat /etc/v2ray/config.json | grep streamSettings`
    if [ "$res" = "" ]; then
        line=`grep -n '}]' /etc/v2ray/config.json  | head -n1 | cut -d: -f1`
        line=`expr ${line} - 1`
        sed -i "${line}s/}/},/" /etc/v2ray/config.json
        sed -i "${line}a\    \"streamSettings\": {\n      \"network\": \"ws\",\n      \"wsSettings\": {\n        \"path\": \"${path}\",\n        \"headers\": {\n          \"Host\": \"${domain}\"\n        }\n      }\n    },\n    \"listen\": \"127.0.0.1\"" /etc/v2ray/config.json
    else
        sed -i -e "s/path\":.*/path\": \"\\${path}\",/" /etc/v2ray/config.json
    fi
    systemctl enable v2ray && systemctl restart v2ray
    sleep 3
    res=`netstat -nltp | grep ${port} | grep v2ray`
    if [ "${res}" = "" ]; then
        echo "v2ray start failed. Check whether the port available !!"
        exit 1
    fi
    echo "Install v2ray SUCCESS !!"
}

function installNginx()
{
    yum install -y nginx
    systemctl stop nginx
    res=`netstat -ntlp| grep -E ':80|:443'`
    if [ "${res}" != "" ]; then
        echo " 80 OR 443 Is in used, please check again !!"
        echo " Who are using such ports: "
        echo ${res}
        exit 1
    fi
    res=`which pip3`
    if [ "$?" != "0" ]; then
        yum install -y python3 python3-pip
    fi
    res=`which pip3`
    if [ "$?" != "0" ]; then
        echo -e " Install pip3 failed !!"
        exit 1
    fi
    pip3 install certbot
    res=`which certbot`
    if [ "$?" != "0" ]; then
        export PATH=$PATH:/usr/local/bin
    fi
    certbot certonly --standalone --agree-tos --register-unsafely-without-email -d ${domain}
    if [ "$?" != "0" ]; then
        echo -e " Accquire centification failed !!"
        exit 1
    fi

    if [ ! -f /etc/nginx/nginx.conf.bak ]; then
        mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
    fi
    cat > /etc/nginx/nginx.conf<<-EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

# Load dynamic modules. See /usr/share/doc/nginx/README.dynamic.
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    include /etc/nginx/conf.d/*.conf;
}
EOF

    mkdir -p /etc/nginx/conf.d;
    cat > /etc/nginx/conf.d/${domain}.conf<<-EOF
server {
    listen 80;
    server_name ${domain};
    rewrite ^(.*) https://\$server_name\$1 permanent;
}

server {
    listen       443 ssl http2;
    server_name ${domain};
    charset utf-8;

    # ssl配置
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
    ssl_ecdh_curve secp384r1;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;

    access_log  /var/log/nginx/${domain}.access.log;
    error_log /var/log/nginx/${domain}.error.log;

    root /usr/share/nginx/html;
    location / {
        proxy_pass $site;
    }

    location ${path} {
      proxy_redirect off;
      proxy_pass http://127.0.0.1:${port};
      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host;
      # Show real IP in v2ray access.log
      proxy_set_header X-Real-IP \$remote_addr;
      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
    res=`cat /etc/crontab | grep certbot`
    if [ "${res}" = "" ]; then
        echo '0 3 1 */2 0 root systemctl stop nginx && certbot renew && systemctl start nginx' >> /etc/crontab
    fi
    systemctl enable nginx && systemctl restart nginx
    sleep 3
    res=`netstat -nltp | grep 443 | grep nginx`
    if [ "${res}" = "" ]; then
        echo -e "Start nginx failed !!"
        exit 1
    fi
}

function setFirewall()
{
    systemctl status firewalld > /dev/null 2>&1
    if [ $? -eq 0 ];then
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --reload
    fi
}

function installBBR()
{
    result=$(lsmod | grep bbr)
    if [ "$result" != "" ]; then
        echo "BBR is installed !!"
        bbr=true
        echo "3" > /proc/sys/net/ipv4/tcp_fastopen
        echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf
        return;
    fi

    echo "Install BBR..."
    rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
    rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-4.el7.elrepo.noarch.rpm
    yum --enablerepo=elrepo-kernel install kernel-ml -y
    grub2-set-default 0
    echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    echo "3" > /proc/sys/net/ipv4/tcp_fastopen
    echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf
    bbr=false
}

function info()
{
    ip=`curl -s -4 icanhazip.com`
    port=443
    res=`netstat -nltp | grep v2ray`
    [ -z "$res" ] && v2status="${red}STOPED${plain}" || v2status="${green}RUNNING${plain}"
    res=`netstat -nltp | grep ${port} | grep nginx`
    [ -z "$res" ] && ngstatus="${red}STOPED${plain}" || ngstatus="${green}RUNNING${plain}"
    uid=`cat /etc/v2ray/config.json | grep id | cut -d: -f2 | tr -d \",' '`
    alterid=`cat /etc/v2ray/config.json | grep alterId | cut -d: -f2 | tr -d \",' '`
    network=`cat /etc/v2ray/config.json | grep network | cut -d: -f2 | tr -d \",' '`
    domain=`cat /etc/v2ray/config.json | grep Host | cut -d: -f2 | tr -d \",' '`
    path=`cat /etc/v2ray/config.json | grep path | cut -d: -f2 | tr -d \",' '`
    security="auto"
    
    echo ============================================
    echo -e " v2ray STATES: ${v2status}"
    echo -e " v2ray CONFIG: ${red}/etc/v2ray/config.json${plain}"
    echo -e " nginx STATES: ${ngstatus}"
    echo -e " nginx CONFIG: ${red}/etc/nginx/conf.d/${domain}.conf${plain}"
    echo ""
    echo -e "${red}v2rayCONFIG:${plain}               "
    echo -e " IP: ${red}${ip}${plain}"
    echo -e " Port: ${red}${port}${plain}"
    echo -e " Uuid: ${red}${uid}${plain}"
    echo -e " Alterid: ${red}${alterid}${plain}"
    echo -e " Security:  ${red}$security${plain}"
    echo -e " Network: ${red}${network}${plain}" 
    echo -e " HostName: ${red}${domain}${plain}"
    echo -e " Path: ${red}${path}${plain}"
    echo -e " TLS: ${red}TLS${plain}"
    echo  
    echo ============================================
}

function bbrReboot()
{
    if [ "${bbr}" == "false" ]; then
        echo  
        echo  "To make BBR effective, sys will be reboot after 30s."
        echo  
        echo -e "ctrl+c cancel it and reboot later."
        sleep 30
        reboot
    fi
}


function install()
{
    echo -n "System version: "
    cat /etc/centos-release

    checkSystem
    getData
    preinstall
    installBBR
    installV2ray
    setFirewall
    installNginx
    
    info
    bbrReboot
}

function uninstall()
{
    read -p "Are you sure to uninstall?? (y/n)" answer
    [ -z ${answer} ] && answer="n"

    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        systemctl stop v2ray
        systemctl disable v2ray
        rm -rf /etc/v2ray/*
        rm -rf /usr/bin/v2ray/*
        rm -rf /var/log/v2ray/*
        rm -rf /etc/systemd/system/v2ray.service

        yum remove -y nginx
        if [ -d /usr/share/nginx/html.bak ]; then
            rm -rf /usr/share/nginx/html
            mv /usr/share/nginx/html.bak /usr/share/nginx/html
        fi
        echo -e " ${red}Uninstall SUCCESS !!${plain}"
    fi
}

action=$1
[ -z $1 ] && action=install
case "$action" in
    install|uninstall|info)
        ${action}
        ;;
    *)
        echo "Invalid argument !!"
        echo "Usages: `basename $0` [install|uninstall]"
        ;;
esac

