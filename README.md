# snippets
**基于[老王vless](https://github.com/eooce/Cloudflare-proxy/blob/main/snippets.js)修改，TXT记录处理代码来自[CM](https://github.com/cmliu/edgetunnel)，HTTPS代理实现来自AK**  
**区别:**  
1. `proxyip` 改为 `fdip`  
2. `fdip` 通过标记 `!txt` 支持 `TXT记录` 反代域名，例：`proxyip.example.com!txt`  
3. 增加 `HTTPS` 代理支持  
4. 移除前端及订阅，需手搓节点  
```
vless://495c7195-85b8-498a-bf20-2ea9ce9175b5@ip.sb:443?path=%2F%3Fed%3D2560%26fdip%3Dproxyip.example.com%21txt&security=tls&encryption=none&insecure=0&host=snippets.example.com&fp=firefox&type=ws&allowInsecure=0&sni=snippets.example.com#snippets
```
_TXT记录反代域名相对A记录的有一个明显优势，不同端口的反代IP可以塞到同一个域名_
