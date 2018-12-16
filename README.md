# 固件打包接口

## 特性
- bin与hex文件互相转换
- bin文件合并
- bin文件任意位置插入、替换数据
- bin文件加密（AES-CBC/ECB）
- bin文件校验（MD5/CRC32）

## pycryptodome安装说明：
- pip install pycryptodome
- 修改安装目录下./Lib/site-packages/crypto为Crypto即可