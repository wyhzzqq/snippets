# snippets
基于[老王vless](https://github.com/eooce/Cloudflare-proxy/blob/main/snippets.js)修改  
**区别:**  
1. `proxyip` 改为 `fdip`  
2. `fdip` 通过标记 `!txt` 支持 `TXT记录` 反代域名，例：`proxyip.example.com!txt`  
3. 移除前端及订阅，需手搓节点  
```
vless://495c7195-85b8-498a-bf20-2ea9ce9175b5@ip.sb:443?path=%2F%3Fed%3D2560%26fdip%3Dproxyip.example.com%21txt&security=tls&encryption=none&insecure=0&host=snippets.example.com&fp=firefox&type=ws&allowInsecure=0&sni=snippets.example.com#snippets
```
_TXT记录反代域名优点是一个反代域名不局限于同一个端口的proxyip，目前公开的似乎只有威廉的_
