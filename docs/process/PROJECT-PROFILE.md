# 项目档案：sws-vault

- 仓库：/root/work/sws-vault（节点 wjy5010u），远端 git@github.com:kyaring/sws-vault.git（私有）。
- 语言：Go（go 和 gofmt 已软链到 /usr/local/bin；为保险起见，先 `export PATH=/usr/local/go/bin:$PATH`）。
- SQLite 用纯 Go 驱动 modernc.org/sqlite（与 vps-commander 一致，不用 cgo）。
- 节点上没有 node：面板只能用 Go 的 html/template 加 embed，前端测试用 Go 做字符串断言。
- 验收：`sh docs/process/acceptance.sh`。交付前自检：`sh docs/process/check-task.sh <任务编号>`（只在任务分支上跑）。
- 规模：默认上限为 600 行、12 个文件；任务书里写了「规模上限：N 行 / M 文件」的，以任务书为准。
- 交付通知：所有任务完成、受阻或失败都必须推送 task-reported，复用 vps-commander 的脚本。做法：先 cd /root/work/vps-commander，再 `set -a; . /root/.config/vps-commander/notify.env; set +a`（不要打印该文件），然后运行 `scripts/notify-agent-completion.sh task-reported --task-id <编号> --type 开发 --status done|blocked|failed --summary '…' --employee SWS-E002-gpt --project sws-vault --ref <commit>`。
- 铁律：任何密钥、令牌、密码、webhook 都不得进入仓库、任务书、日志、测试快照或命令行；测试只用明显的假值（如 SENTINEL-VALUE-xxxx）。
- 角色：Hark 负责主审核、规划和看板；开发者是 GPT（SWS-E002-gpt）和 RikkaHub-1；OPC（SWS-H000-opc）负责批准合并和部署。
