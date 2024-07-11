# msock

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

### 1.3 curl命令行使用
```
curl -L -k -v -o a.html --socks5 username:123456@127.0.0.1:1080 https://www.bing.com/
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
    