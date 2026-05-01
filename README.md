# UE-Universal-PostRender-Dumper

适用于UE4-UE5的通用PostRender转储方法，理论上适用于所有虚幻引擎游戏。

## 使用方法
### 确认配置
- 使用 [Dumper-7](https://github.com/Encryqed/Dumper-7) 生成SDK
- 将 [Dumper-7](https://github.com/Encryqed/Dumper-7) 生成的 `CppSDK` 文件夹复制到 `UE-Universal-PostRender-Dumper\PostRenderDumper\SDK`
- 确认 `TARGET_WIDTH` 和 `TARGET_HEIGHT` 与你的游戏客户端一致
- 确认 `SIZE_X_OFFSET` 与 `Dumper-7` 生成的 `SDK` 一致
- `生成解决方案`
>除非预设参数无法找到 `PostRender`，否则无需修改`SCAN_RANGE` 与 `STABLE_FRAME_THRESHOLD`

### 注入
- 将生成的`DLL`注入到目标进程
- 检查控制台输出的信息，如果成功，屏幕左上角应该会出现`Box`