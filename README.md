
# 安装python
安装这里python.exe

# 安装pywin32
跑命令 pip install pywin32

# 配置固定执行的任务
在Windows系统中，要设置一个任务以管理员权限每60分钟执行一次Python脚本，你可以按照以下步骤操作：

打开任务计划程序：

按下Win + R键打开运行对话框。
输入taskschd.msc并按回车键，或者在搜索框中输入任务计划程序并打开它。
创建新的任务：

在任务计划程序中，点击右侧的“创建基本任务...”或者在左侧选择“任务计划程序库”，然后在右侧点击“创建基本任务...”。
设置任务名称和描述：

输入任务的名称和描述，然后点击“下一步”。
设置触发器：

选择“每日”作为触发器，点击“下一步”。
设置任务开始时间，然后选择“重复任务”。
设置重复的频率为“每小时”，并设置重复间隔为1次，点击“下一步”。
设置操作：

选择“启动程序”，点击“下一步”。
在“程序/脚本”输入框中，输入Python的可执行文件路径（例如C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe，因为直接在任务计划程序中设置以管理员权限运行可能不起作用）。
在“添加参数”输入框中，输入以下命令，使用PowerShell来以管理员权限运行Python脚本：
-Command "Start-Process 'C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe' -ArgumentList 'C:\winlogs\extract_log.py' -Verb RunAs"
请将C:\Python39\python.exe替换为你的Python可执行文件的实际路径，将C:\path\to\your\script.py替换为你的Python脚本的实际路径。
“起始于”留空即可。
配置设置：

点击“设置”按钮，勾选“如果任务运行超过以下时间，请停止”并设置一个合理的时间。
点击“确定”。
完成设置：

点击“下一步”，然后点击“完成”来创建任务。
以管理员权限运行任务计划程序：

为了确保任务计划程序能够以管理员权限运行，你需要以管理员权限打开任务计划程序。
右键点击任务栏上的开始按钮，选择“Windows PowerShell(管理员)”或者“命令提示符(管理员)”，在打开的窗口中输入taskschd.msc并回车。
测试任务：

你可以手动运行任务来测试它是否按预期工作。右键点击你创建的任务，选择“运行”来立即执行。
请注意，使用PowerShell来启动Python脚本是一种间接的方法，因为任务计划程序本身不提供直接以管理员权限运行的选项。通过这种方式，你可以确保Python脚本以管理员权限启动。

另外，确保你的Python脚本没有硬编码的路径，因为以管理员权限运行时，用户的主目录路径可能与普通用户权限时不同。

# 如何手动运行

假设代码在 c:\winlogs

执行
``` 
cd c:\winlogs
python extract_log.py
```
c:\blacklist和c:\whitelist是生成黑名单和白名单，windows防火墙会根据这两个名单建立规则。同时 c:\\login.log是中间数据，是脚本执行时过去两个小时的登录日志