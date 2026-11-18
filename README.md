# 影像平台的增量合规扫描

## 现状

- `baseline/scan.py`：纯正则，凡是 exec.Command / db.Query / os.Open / http.Get 就报。召回够，误报高。
- `analyzer.py` + `scan.py`：跨包污点分析 + 按包缓存的增量引擎（本次复测整改产物）。
  全量 9/9、零误报；增量与全量逐条一致（45 条变更样本验证）。

## 语料

- `pkg/handlers/handlers.go`：8 真漏洞 + 6 decoy（同形状但过了净化）
- `pkg/handlers/extra.go` + `pkg/fileutil/`：跨包数据流（路由层 → handlers → fileutil 拼路径），
  复刻上次等保复测漏掉的 CWE-22 场景
- `main.go`：路由入口；`labels.json`：真漏洞标注；`eval.py`：算召回/误报（支持 SARIF）

## 增量引擎设计（analyzer.py）

**一致性不变式**：包 P 的 findings 只取决于「P 自己的文件内容」+「P 引用的外部符号的
summary」。因此只要失效集合 ⊇ {自有文件变了} ∪ {依赖的符号 summary 变了}，增量结果
必然与全量逐条一致。

- **按包建缓存**：目录即包，`.scancache/cache.json` 每包存 文件哈希表 / 符号 summary /
  跨包依赖边（deps）/ 接口与方法集 / findings。
- **summary**：每个函数算 `propagates`（参数是否污染返回值）与 `sanitizes`（是否净化），
  哈希只含语义 —— 改参数名、加注释不会误触发失效（样本 d3/d4 验证）。
- **失效规则**：
  1. 同包文件变更 → 重扫本包；
  2. 被调符号 summary 变更 → 沿反向依赖边重扫调用方（跨包传播，样本 d1/d2）；
  3. 接口方法集变更 → 重扫声明了同名方法的包（实现方，样本 f3）。
  传播迭代到不动点。

## 防脏读（「文件删了但缓存还在」）

1. **manifest 对账**：每轮扫描先 walk 磁盘，与缓存里的文件哈希表逐包对比。
   磁盘上消失的文件/整包，其缓存条目（findings、summary、依赖边）**先作废再分析**；
   被删包的符号记为「已删除」，沿反向依赖边触发调用方重扫（样本 e7/h1/h3/i3）。
2. **内容寻址**：缓存键是内容 SHA-256，不是路径或 mtime；同名文件被改写就是新键。
3. **原子落盘**：缓存写临时文件后 `os.replace`，崩溃不会留下半包缓存。
4. **版本号**：`CACHE_VERSION` 随分析器规则升级而 bump，旧格式整体失效，绝不混读。
5. **兜底**：CI  nightly 跑一次全量对账（`--mode full` 不读缓存），漂移即报警。

## 跑法

```
go build ./...
python scan.py --mode full --out findings.sarif   # 全量（不碰缓存）
python scan.py --mode incr  --out findings.sarif   # 增量（读写 .scancache/）
python eval.py findings.sarif                      # 召回/误报
python eval_samples.py                             # 45 条变更样本：一致性 + 指标
python -m pytest tests/ -q
```

## 复测指标（eval_samples.py）

- 45 条样本：同包/路由层/跨包被调符号/接口实现/文件删除/整包删除/净化器增删/符号重命名
- 增量 == 全量：**45/45 逐条一致**
- 脏读（finding 指向已删文件）：**0 起**
- 召回 **100%**（要求 ≥85%），误报 **0%**（要求 ≤15%）
- 产出 `findings.sarif`（SARIF 2.1.0，rules 含 CWE-22/78/89/918）供复测留档
