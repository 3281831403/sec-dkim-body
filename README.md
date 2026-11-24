邮件正文只改了行尾的空白，签名就失效，把长度标签放宽之后，正文却又被追加了内容：宽松规范化只删行尾空格而不删行尾制表符；宽松规范化不折叠正文中的重复空行且末尾空行处理不符；严格规范化仍裁剪行尾空白而与宽松模式混同；长度标签先对未截断正文算摘要再截断；长度标签为负数或超过正文长度时静默截到零；头部折叠行不还原导致被签头部与原始内容不一致；头部列表中的重复头部只取第一个而忽略后续；头部列表包含签名头自身造成循环依赖；验签只绑定正文不绑定头部使头部可被改写；批量验签复用正文规范化结果使第二条消息沿用第一条消息的正文。dkim/body.py 是核心，tests/unit/test_body.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

运行方式
在仓库根目录执行 python -m pytest tests -q。预期输出末尾为 15 failed，且 15 条失败全部是 NotImplementedError，不应出现 collection error 或 import error。测试只依赖 pytest，不需要联网、启动服务或安装其他包。实现 dkim/body.py 的 8 个桩后，整套测试应变为 15 passed。

字段表

任务：Bugfix

难度：高

测试约束
tests 目录不可修改。验收以仓库根目录下的 pytest 结果为准，不以局部替换桩或修改测试为通过条件。

测试拆分布局
tests/unit/test_body.py：10 条契约测试，按顺序逐条对应首行列出的 10 个缺陷。
tests/behaviour/test_body_edge.py：5 条边界测试，覆盖严格模式原样正文、宽松模式追加行尾空白、长度标签截断后追加正文、头部改写失败，以及两批独立验签与单独验签一致。
tests 目录合计 15 条测试。首行末句按题目要求固定写作 tests/unit/test_body.py 15个红，其中 15 指 tests 目录合计的 15 条红测试。

接口约定
dkim/body.py 是唯一实现文件，恰好 8 个桩：split_headers、canonicalize_body、apply_length_tag、body_hash、parse_signature、header_hash、verify、dkim_batch。当前 8 个桩全部 raise NotImplementedError，因此 15 条测试全红。题面中的严格模式在实现里用 strict 表示，宽松模式用 relaxed 表示；正文与规范化结果均为 bytes，摘要均为 SHA-256 小写十六进制字符串。每条签名按自身声明的规范化类型选择 body_mode，多签名共享同一正文时各用各的模式，不允许互相覆盖。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

