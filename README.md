# snippets
基于[老王](https://github.com/eooce/Cloudflare-proxy/blob/main/snippets.js)修改  
**区别:**  
1. `proxyip` 改为 `fdip`  
2. `fdip` 通过标记 `!txt` 支持 `TXT记录` 反代域名，例：`proxyip.example.com!txt`  
3. 移除所有前端
