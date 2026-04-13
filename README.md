# snippets
**基于[老王vless](https://github.com/eooce/Cloudflare-proxy/blob/main/snippets.js)修改，TXT记录处理代码来自[CM](https://github.com/cmliu/edgetunnel)，HTTPS代理实现来自[AK](https://t.me/Enkelte_notif/810)，SSTP实现来自[AK](https://t.me/Enkelte_notif/819)**  
**区别:**  
1. `proxyip` 改为 `fdip`  
2. `fdip` 通过标记 `!txt` 支持 `TXT记录` 反代域名，例：`/?ed=2560&fdip=proxyip.example.com!txt`  
3. 增加 `HTTPS` 代理支持，不支持ip（手搓tls太大了不好塞进来），例：`/?ed=2560&fdip=https://host:port`  
4. 增加 `SSTP` 支持，例: `/?ed=2560&fdip=sstp://host:port`  
5. 移除前端及订阅，需手搓节点  
```
vless://495c7195-85b8-498a-bf20-2ea9ce9175b5@ip.sb:443?path=%2F%3Fed%3D2560%26fdip%3Dproxyip.example.com%21txt&security=tls&encryption=none&insecure=0&host=snippets.example.com&fp=firefox&type=ws&allowInsecure=0&sni=snippets.example.com#snippets
```
_TXT记录反代域名相对A记录的有一个明显优势，不同端口的反代IP可以塞到同一个域名_  
**注：1101请删除全部片段后再部署**  
**文件夹 `AK` 为备份AK佬源码**  