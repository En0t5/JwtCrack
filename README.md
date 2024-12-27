# JwtCrack

由于没有找到Java jjwt批量爆破的脚本，于是花一下午写了个jwt的爆破脚本，目前仅支持HMAC算法，RSA、ECDSA暂不支持

# 使用

默认jwt爆破

```shell
JwtCrack -token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJxxxxxx.SflKxxxxxx
```

默认+密钥base64解密爆破 （jjwt decode）

```shell
JwtCrack -base64 -token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJxxxxxx.SflKxxxxxx
```

指定字典爆破

```shell
JwtCrack -base64 -keys keys.txt -token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJxxxxxx.SflKxxxxxx
```