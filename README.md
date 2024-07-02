# msock

## 一、使用设置

```socks5```和```socks5h```的区别是：```socks5h```的域名解析在scoks5代理服务器中。

### 1.1 Linux命令行设置环境变量

```
export ALL_PROXY=socks5h://username:password@127.0.0.1:1080
```

### 1.2 Windows命令行设置环境变量
```
set http_proxy=socks5h://username:password@127.0.0.1:1080
set https_proxy=socks5h://username:password@127.0.0.1:1080
```

### 1.3 curl命令行使用
```
curl -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0' -v -o a.html --socks5 username:123456@127.0.0.1:1080 https://www.baidu.com/
```

### 1.4 git

### 1.5 pip
