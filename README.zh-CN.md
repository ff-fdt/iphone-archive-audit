# iPhone 照片归档检查器

[English](README.md)

检查从 iPhone 导出的照片、视频和侧车文件，生成 JSON、Markdown 报告与可选的
SHA-256 清单。适合在换机、整理移动硬盘和长期保存照片时使用。

## 演示

生成包含两张相同的单像素 PNG 和一个空 JPEG 的示例归档。

```sh
python3 examples/demo.py
```

```text
status=attention
files=3
bytes=138
json=demo-output/_audit/archive-audit.json
markdown=demo-output/_audit/archive-audit.md
sha256=demo-output/_audit/sha256-manifest.tsv
```

报告会列出空文件及一组内容相同的图片。[报告示例](examples/report.md) · [SHA-256 清单](examples/sha256-manifest.tsv)。

## 使用

需要 Python 3.10 及以上，扫描器使用标准库。

```sh
python3 audit_archive.py /path/to/Photos_Originals --skip-readability
python3 audit_archive.py /path/to/Photos_Originals --skip-readability --full-sha256
```

默认报告写入照片目录旁的 `_audit/`。用 `--audit-dir /path/to/reports` 指定其他目录。
报告目录须位于源照片目录之外。

检查内容包括文件数与容量、零字节和读失败、文件头与扩展名、大小写路径冲突、
AAE 配对、同名图片与视频的 Live Photo 候选，以及 Image Capture 产生的编号文件。
完整哈希模式另列字节相同的重复文件组。

macOS 上去掉 `--skip-readability` 可抽样检查媒体可读性；图片调用 `sips`，
视频调用 `ffprobe`。可用 `brew install ffmpeg` 安装视频检查工具。

退出码：`0` 检查通过，`1` 报告有需处理的项目，`2` 参数或读写错误。
将报告的文件数、容量与导出工具的源清单对账，可核对导出完整性。
报告含本地路径和文件名，请随私人档案保存。

## 开发

```sh
python3 -m unittest discover -v
```

采用 MIT 许可证。

[参与贡献](CONTRIBUTING.md)
