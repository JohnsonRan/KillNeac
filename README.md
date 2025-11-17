# KillNeac

当国服守望先锋主进程已终止，自动关闭 Neac 反作弊

## 配置

编辑 `config.json` 文件：

```json
{
  "monitor_directory": "D:\\Games\\Battle.net\\Overwatch\\_retail_",
  "target_exe": "Overwatch.exe",
  "kill_exe": "OWNeacClient.exe",
  "check_interval_ms": 500,
  "auto_start": true
}
```
### 一般情况下只需修改 `monitor_directory` 即可

- `monitor_directory`: 要监控的目录路径
- `target_exe`: 要监控的目标进程名称
- `kill_exe`: 当目标进程关闭时要强制终止的进程名称
- `check_interval_ms`: 检查间隔（毫秒）
- `auto_start`: 开机自启