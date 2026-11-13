# UE-Universal-PostRender-Dumper

适用于UE4-UE5的通用PostRender、Tick、ProcessEvent转储方法，理论上适用于所有虚幻引擎游戏。

<img width="1919" height="1027" alt="1" src="https://github.com/user-attachments/assets/ffe8860e-5301-4367-88c5-07ef74604f96" />
<img width="1919" height="1026" alt="2" src="https://github.com/user-attachments/assets/de7ef655-c8ff-4c9b-8934-4d0fb6cd84a4" />
<img width="1919" height="1022" alt="3" src="https://github.com/user-attachments/assets/325bf2ac-4620-4331-8b78-0e0999f4f5c8" />
<img width="1919" height="1014" alt="4" src="https://github.com/user-attachments/assets/1a8c5cf7-5291-4948-81ff-b7681a3dfaa5" />
<img width="1919" height="1036" alt="5" src="https://github.com/user-attachments/assets/8f86973b-4a6f-4e9c-ad19-cd38d715bd46" />

## 使用方法

### 确认配置
- 使用 [Dumper-7](https://github.com/Encryqed/Dumper-7) 生成SDK
- 将 [Dumper-7](https://github.com/Encryqed/Dumper-7) 生成的 `CppSDK` 文件夹复制到 `UE-Universal-PostRender-Dumper\PostRenderDumper\SDK`
- `以 x64/Release 生成解决方案`

> 除非预设参数无法找到 `PostRender`，否则无需修改 `SCAN_RANGE` 与 `STABLE_FRAME_THRESHOLD`

### 注入
- 将生成的 `DLL` 注入到目标进程
- 检查控制台输出的信息，如果成功，屏幕左上角应该会出现 `Box`

### ☕ 赞助 / Buy me a coffee

* 您可以通过赞助支持我们的开发，感谢大家的支持！
* If this project helps you, feel free to support my work!
* **USDT (TRC-20):** `THzBDDbBkDh3nXRkCEeG4p5r733tWeAdib`