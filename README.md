# msock

## 0、代理流程
```
PROXY --> socks4/5/https_proxy两大类代理协议
ssr_local 本机或者同一个局域网，不要跨公网网络
ssr_server 是在一个合适的公网网络


    web/app                      ssr_local                       ssr_server
=====================================================================================
                                                                   listening
                                  listening
    
    connect ------ PROXY  ----->   accept
            <-------------
    
    request ---PROXY connect-->     recv      
                                            ----- https_connect -->     SSL_Accept
                                                                        connect_real_server
                                            <----------------------
            <-----------------      send
    
    relay   --PROXY  ------>        recv
                                            -----https_data            SSL_Read
                                                                                -->send real_server

                                                                                <--recv real_server
                                            <----https_data            SSL_Write
    relay   <--PROXY -------        send

=====================================================================================
```

## 一、使用设置

```socks5```和```socks5h```的区别是：```socks5h```的域名解析在scoks5代理服务器中。
```socks4a```和```socks4```的区别是：```socks4a```的域名解析在scoks4代理服务器中。

### 1.1 Linux命令行设置环境变量

```
export ALL_PROXY=socks5h://username:password@127.0.0.1:1080
export ALL_PROXY=socks4://username:password@127.0.0.1:1080
export ALL_PROXY=socks4a://username:password@127.0.0.1:1080
```

### 1.2 Windows命令行设置环境变量
```
set http_proxy=socks5h://username:password@127.0.0.1:1080
set https_proxy=socks5h://username:password@127.0.0.1:1080
```

### 1.3 curl/wget命令行使用

curl支持https\socks4\socks4a\socks5\socks5h

wget支持https

```
curl -L -k -v -o a.html --socks5 username:123456@127.0.0.1:1080 https://www.bing.com/
```

```
curl -k -v -o a.html -x 127.0.0.1:1080 https://www.bing.com/
```

```
wget -e "https_proxy=http://127.0.0.1:1080" https://download.virtualbox.org/virtualbox/7.0.20/VirtualBox-7.0.20-163906-OSX.dmg
```

### 1.4 git
```
    git config --global http.proxy socks5h://username:password@127.0.0.1:1080
    git config --global https.proxy socks5h://username:password@127.0.0.1:1080
```
此方式仅支持https方式的git仓库.

### 1.5 pip
    
    设置系统代理环境变量即可使用。

### 1.6 docker

### 1.6 yum

    设置系统代理环境变量即可使用。

### 1.7 apt

## 二、 服务器功能

### 2.1 授权

```
curl -X POST -d'u=xiaochd&p=123456' -H 'SSR_VER:1' -H 'SSR_TYPE:0' -H 'Content-Type:application/x-www-form-urlencoded' -H 'Content-Length:18' -k -v -o a.html https://msock.duckdns.org/msock/data
```

### 2.2 请求连接

```
curl -X POST -d'h=www.google.com&p=443' -H 'SSR_VER:1' -H 'SSR_TYPE:1' -H 'Content-Type:application/x-www-form-urlencoded' -H 'Content-Length:21' -k -v -o a.html https://msock.duckdns.org/msock/data
```

### 2.3 转发数据

```
curl -X POST -d'xxxxx' -H 'SSR_VER:1' -H 'SSR_TYPE:2' -H 'Content-Type:application/x-www-form-urlencoded' -H 'Content-Length:21' -k -v -o a.html https://msock.duckdns.org/msock/data
```

## 三、letsencrypt申请证书

[letsencrypt](https://letsencrypt.org/)是一个可以免费使用SSL/TLS域名证书的结构，每次签发的证书有效期是90天。

### 3.1 安装工具

```
pip3 install certbot
```

使用命令行申请证书
```
certbot certonly --manual -d '{Domain Name}'
```

### 3.1 域名解析控制权

修改dns解析，内容是由```certbot```工具限定的。
```
_acme-challenge  TXT类型
```

### 3.2 服务器控制权

增加一个http的请求文件，并且文件内容是由```certbot```工具限定的。

请求的URL格式为:
```
http://{hostname}/.well-known/acme-challenge/*
```

实际的文件路径为:
```
{ROOT}/.well-known/acme-challenge/*
```
