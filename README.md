# EmbodiedStudio releases

本仓库保存巨禾智控具身智能上位机的安装包、公开签名材料和受签名保护的更新目录；automation/仅包含目录维护所需最小源码，不承载完整上位机源码。

在线交付必须验证项目 P256 签名目录、HTTPS 安装包大小与 SHA-256、原生运行文件完整性，并保留可兼容的已验证恢复包。Windows Authenticode 和可信时间戳按已批准策略作为可选增强，签名状态如实记录。
完成这些条件和真实在线升级验收前，候选包保持 candidate 身份；发布草稿不作为稳定更新目录。


## 2026-10-26 项目签名交付

0.46.34 及历史 0.46.33 迁移/回退构建的固定身份见 release-metadata/。Windows 签名状态为 NotSigned；项目目录签名、安装包摘要及原生完整性检查保持必需。

签名目录：stable/catalog.json 与 stable/catalog.sig。目录序号 1，有效期至 2026-11-02T10:32:00+00:00。


## 2026-10-27 恢复修复交付

0.46.37 recoveryfix-20261027-r2 与修复后的0.46.36 migration-20261027-r1保留项目P256、安装包摘要及原生完整性门禁。Windows签名状态为NotSigned；旧0.46.33/0.46.34保持撤回。固定身份见release-metadata/及本次Release校验文件。

当前签名目录序号6，截止2026-11-03T06:30:37+00:00；目录按现有规则最多有效168小时，尚无自动续签。


## 2026-10-29 双产品在线更新

主版0.46.39和独立版0.46.38使用各自产品身份及更新目录。独立版另保留0.46.37受保护迁移回退包；主版保留现有0.46.37/0.46.36正式回退包。项目P256、HTTPS、安装包摘要和原生完整性验证保留，Windows Authenticode为NotSigned。冻结源不包含并行MAVLink Bootloader任务；新包身份见release-metadata/，旧版本和资产继续保留。

2026-10-29初次发布的签名目录（历史记录，当前序号和有效期以在线签名目录为准）：

- standalone: 序号1，有效期至2026-11-05T02:50:54+00:00。
- main: 序号7，有效期至2026-11-05T02:50:55+00:00。

目录有效期按现有安全规则为168小时；过期后检查更新仍保持失败关闭。


## 更新目录自动续签（2026-10-29）

主版与独立版已配置同一个本机受控续签任务，每12小时检查一次，剩余有效期不超过96小时时统一续签168小时并分别增加序号。两版目录及签名通过同一次原子提交发布，只更新签发时间、过期时间与序号，保留安装包身份、URL、大小、SHA-256、撤回标志和数据兼容范围。正常无变更不提醒；续签完成、失败或需要人工处理时通知。

项目P256私钥留在既有Windows用户证书存储中，不上传GitHub；本机Codex及当前用户执行环境需要可运行且联网，关机或长期离线期间无法执行。恢复后同一流程可补签已过期但仍可验证签名的原目录，客户端的HTTPS、签名、过期及序号校验保持开启。运行中断会先读回远端确认，CDN传播延迟只重试读取，不重复签发或覆盖安装包。


## GitHub托管自动续签与信任迁移（2026-10-29，当前配置）

前述本机续签方案已停用，Codex任务automation-2为PAUSED。当前由[Renew signed update catalogs](https://github.com/MXyyds666/embodied-studio-releases/actions/workflows/renew-update-catalogs.yml)在GitHub托管windows-2022运行器执行，无需本机开机或Codex运行。常规调度UTC01:17/13:17（北京时间09:17/21:17），剩余有效期≤96小时续签168小时；未到阈值仅检查，不重复签发。

新目录为cloud/stable/catalog.json、standalone/cloud/stable/catalog.json及各自catalog.sig。新P256目录私钥只保存在仓库Actions Secret ES_CATALOG_SIGNING_KEY_20261029；公钥见automation/public-trust.json。原Windows CNG私钥不可导出，未迁出。安装包仍必须验证HTTPS、目录签名/过期/序号、大小/SHA-256及原生完整性，Windows Authenticode如实为NotSigned。

主版0.46.40（cloud-20261029-main-r1）与独立版0.46.39（cloud-20261029-standalone-r1）信任新旧公钥并切换云端目录；两版已分别完成本机及公开HTTPS后台真实安装、升级、主动回滚、受控失败自动恢复和再次升级。新包身份与追加验收收据见release-metadata/；原有资产、失败事务及回退包保留，不替换安装包。

旧stable目录由原密钥签署一次性迁移入口，截止2026-11-05T04:48:51Z（北京时间11月5日12:48:51）；旧目录不再自动续签。超过窗口或回退旧版遇到过期/序号冲突时，手动安装迁移包；不得关闭过期校验或降低已见序号。

工作流只允许同仓库main受信任触发，签名步骤最小contents:write权限；续签只修改四个云端目录路径并原子提交，不更改安装包或发布身份。新发布条目另外校验原离线密钥签名的审核输入；并发提交冲突停止，提交后响应不明时由新作业独立读回，不盲目重签。

云端实测：[新密钥验证](https://github.com/MXyyds666/embodied-studio-releases/actions/runs/40815705422)、[刻意提交后中断（预期失败）](https://github.com/MXyyds666/embodied-studio-releases/actions/runs/40815909211)、[新作业独立恢复](https://github.com/MXyyds666/embodied-studio-releases/actions/runs/40816084009)、[两版迁移目录原子发布](https://github.com/MXyyds666/embodied-studio-releases/actions/runs/40819845807)。维护测试29项通过，恢复作业生成签名0；真实schedule触发的两版自动续签及后续无变化检查现已通过，具体证据见下方补充验收。


## 原生定时续签验收完成（2026-10-30）

通过[真实schedule续签](https://github.com/MXyyds666/embodied-studio-releases/actions/runs/40867556622)，两版均在正常96小时门槛内自动签署并原子发布168小时目录；随后[真实schedule无变化检查](https://github.com/MXyyds666/embodied-studio-releases/actions/runs/40962412546)生成目录签名0，序号与签名保持一致。两次均用各产品冻结源码客户端和实际包内配置从公网独立验签，过期及降序号拒绝仍有效。没有强制续签或合成时间，本机任务继续PAUSED。临时15分钟观察调度已移除，仅保留UTC01:17/13:17。

[完整原生定时验收收据](https://github.com/MXyyds666/embodied-studio-releases/blob/main/release-metadata/native-schedule-renewal-acceptance-20261029.json)。旧迁移目录与安装包未改动；旧迁移截止时间仍为北京时间2026-11-05 12:48:51，当前云端序号与有效期以签名目录为准。一次重新登记工作流是诊断操作，不能单凭之后出现事件断言平台根因。
