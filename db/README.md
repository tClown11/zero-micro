# 数据库表结构

本仓库使用的仓库为 pg

## 通用 model 代码生成命令

```shell
goctl model pg datasource --dir ./internal/model --table t_user --cache true --url "postgres://user:password@127.0.0.1:5432/zero_hero"  
```
