# UE-Universal-PostRender-Dumper

适用于UE4-UE5的通用PostRender转储方法，理论上适用于所有虚幻引擎游戏。
<img width="1920" height="1040" alt="1" src="https://github.com/user-attachments/assets/33e5c2ca-855f-4e18-be93-b3a5be68b44b" />
<img width="1920" height="1040" alt="2" src="https://github.com/user-attachments/assets/46e81cca-b083-476c-b8f8-3b6cd4ffa8c8" />
<img width="1919" height="1038" alt="image" src="https://github.com/user-attachments/assets/92fae6eb-4dcb-4210-b29c-a4a277b207c7" />

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
