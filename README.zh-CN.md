# cps-authz-bench

[English](README.md) | [简体中文](README.zh-CN.md)

面向信息物理系统授权分析器的确定性基准、故障注入和差分测试工具。它能够生成带参考真值的服务/物理效果图，注入命名缺陷，隔离运行外部分析器，并把失败样例缩减为便于调试的结构化反例。

## 核心能力

- 基于种子的可重复图与请求生成；
- 权限扩张、混淆代理、陈旧版本、孤立效果和解析破坏变异；
- 有界外部进程适配器与确定性超时/输出捕获；
- 严格、封闭、资源有界的 JSON 与结果模式；
- 参考预言机、差分比较、失败语料存储和结构化缩减；
- Windows Job Object 进程树控制与失败关闭行为。

## 快速开始

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m cps_authz_bench generate --seed 42 --services 6 --effects 10 --requests 16 --output graph.json
python -m unittest discover -s tests -v
```

运行时只依赖 Python 3.11+ 标准库，不需要 GPU、云服务、容器、网络或硬件。完整变异契约、运行器接口和语料格式见[英文说明](README.md)。

## 工程边界

参考预言机覆盖仓库定义的结构与授权规则，不是任意控制系统动力学的模型检查器。所有输入、输出、种子和子进程资源均有明确上限，超限或模式不一致时返回稳定失败结果。

## 协作

刘泽康负责总体设计与主要实现；史浩轩参与基准集成和文档核验。职责说明见 [CONTRIBUTORS.md](CONTRIBUTORS.md)。

采用 [MIT License](LICENSE)。
