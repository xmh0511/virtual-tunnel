运行下面命令进行数据库实体生成
> sea-orm-cli generate entity -o src/model

然后再main.rs中引入
> mod model;