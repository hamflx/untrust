# untrust

删除 `Windows` 系统上，不受信任的根证书颁发机构。

## 使用

```powershell
# 清理证书。这一步会自动在当前目录生成“backup-*”的备份文件。
.\untrust.exe clean

# 将不受信任的证书导出。
.\untrust.exe dump

# 仅仅将不受信任的证书打印出来。
.\untrust.exe check
```
