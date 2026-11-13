# UE-Universal-PostRender-Dumper

适用于 `UE4-UE5` 全版本的通用 `PostRender、Tick、ProcessEvent` 转储方法，理论上适用于所有虚幻引擎游戏。

<details open>
<img width="1919" height="1038" alt="image" src="https://github.com/user-attachments/assets/e8f54079-09ee-461f-a8a0-aa0365792b46" />
</details>

## 使用方法

### 确认配置
- 使用 [Dumper-7](https://github.com/Encryqed/Dumper-7) 生成SDK
- 将 [Dumper-7](https://github.com/Encryqed/Dumper-7) 生成的 `CppSDK` 文件夹复制到 `UE-Universal-PostRender-Dumper\PostRenderDumper\SDK`
- `以 x64/Release 生成解决方案`

> 除非预设参数无法找到 `PostRender`，否则无需修改 `SCAN_RANGE` 与 `STABLE_FRAME_THRESHOLD`

### 注入
- 将生成的 `DLL` 注入到目标进程
- 检查控制台输出的信息，如果成功，游戏窗口左上角应该会出现 `文本`

### ☕ 赞助 / Buy me a coffee

* 您可以通过赞助支持我们的开发，感谢大家的支持！
* If this project helps you, feel free to support my work!
* **USDT (TRC-20):** `THzBDDbBkDh3nXRkCEeG4p5r733tWeAdib`
