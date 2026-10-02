// Extract the ninth-round independent audit (docs/security-audit-9.md) into the
// fragment contract consumed by _merge.mjs.
//
// Run: node docs/issues/_fragments/_extract_round9.mjs
//
// The round-9 report is organised by severity (High/Medium/Low/Info) and by
// finding ID (Sxx-yy), not by the register's P0..P3 buckets, so this script is
// the single translation point:
//   * the 8 Highs become `## P0/P1` blocks (hand-written Chinese, faithful to
//     the report; six of them are the report's own "go-live blockers" -> P0,
//     the remaining two -> P1);
//   * the 30 Mediums become `P2` rows;
//   * the 95 Lows + 24 Info become `P3` rows (info marked as such);
//   * statuses come from the report's "修复状�? ledger (9 FIXED in 992710b);
//   * the report's own §5 de-duplication is recorded as `合并` notes and is
//     applied by _merge.mjs's ALIAS map.
//
// Titles of Low/Info rows are kept verbatim in English on purpose: the report is
// the evidence, and a paraphrase would risk drifting from it. Medium rows carry
// a hand-written Chinese summary because they are the ones a human triages.

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..', '..', '..');
const report = readFileSync(join(repo, 'docs', 'security-audit-9.md'), 'utf8');
const lines = report.split(/\r?\n/);

const idx = (re) => lines.findIndex((l) => re.test(l));
const S_HIGH = idx(/^## 1\. 高危发现/);
const S_MED = idx(/^## 2\. 中危发现/);
const S_LOW = idx(/^## 3\. 低危发现/);
const S_INFO = idx(/^## 4\. 信息�?);
const S_DEDUP = idx(/^## 5\. 去重与关�?);
if ([S_HIGH, S_MED, S_LOW, S_INFO, S_DEDUP].some((i) => i < 0)) {
  throw new Error('round-9 report: section headings not found');
}

const PIPE = '\u0000PIPE\u0000';
function splitRow(line) {
  const safe = line.trim().replace(/\\\|/g, PIPE);
  return safe.split('|').slice(1, -1)
    .map((c) => c.trim().split(PIPE).join('\\|').replace(/^`|`$/g, '').trim());
}

function table(start, end) {
  const rows = [];
  for (const line of lines.slice(start, end)) {
    if (!/^\|\s*S\d\d-\d+\s*\|/.test(line)) continue;
    rows.push(splitRow(line));
  }
  return rows;
}

// High block locations: `- **位置�?* \`a; b; c\`` under each `### Hn. Sxx-yy �?…`.
const highLocs = new Map();
for (const line of lines.slice(S_HIGH, S_MED)) {
  const h = /^### H\d+\.\s+(S\d\d-\d+)\s+�?.exec(line);
  if (h) { highLocs.set(h[1], ''); continue; }
  const loc = /^- \*\*位置：\*\*\s*(.*)$/.exec(line);
  if (loc && highLocs.size) {
    const id = [...highLocs.keys()].pop();
    if (!highLocs.get(id)) highLocs.set(id, loc[1].trim());
  }
}

const medium = table(S_MED, S_LOW);   // [id, category, title, location, brief]
const low = table(S_LOW, S_INFO);     // [id, category, title, location]
const info = table(S_INFO, S_DEDUP);  // [id, category, title, location]
if (medium.length !== 30 || low.length !== 95 || info.length !== 24) {
  throw new Error(
    `round-9 report: unexpected table sizes medium=${medium.length} low=${low.length} info=${info.length}`);
}

// --- statuses: the report's own fix ledger (section "修复状�?) ---------------
const fixedAt992710b = new Set(['S02-1', 'S02-2', 'S03-1', 'S06-1', 'S08-2', 'S10-1', 'S13-1', 'S13-5', 'S14-2']);
const HIGH_IDS = ['S02-1', 'S03-1', 'S06-1', 'S08-2', 'S10-1', 'S13-1', 'S13-5', 'S14-2'];
const P0_IDS = ['S02-1', 'S08-2', 'S10-1', 'S13-1', 'S14-2', 'S06-1'];
const statusOf = (id) => (fixedAt992710b.has(id)
  ? 'FIXED�?92710b�?
  : 'OPEN');

// --- §5 de-duplication, mirrored into _merge.mjs's ALIAS map -----------------
// alias -> canonical (canonical keeps the row; the alias ID is recorded in the
// row's 问题 cell so the finding is still searchable).
const MERGED = new Map(Object.entries({
  'S05-2': 'S14-2',
  'S04-1': 'S01-1',
  'S04-3': 'S01-2',
  'S14-8': 'S01-2',
  'S13-10': 'S01-2',
  'S13-3': 'S13-2',
  'S14-1': 'S13-2',
  'S14-6': 'S13-2',
  'S14-7': 'S13-2',
  'S14-9': 'S10-2',
  'S14-10': 'S04-8',
  'S11-5': 'S11-3',
}));
const mergedInto = new Map();
for (const [alias, canon] of MERGED) {
  if (!mergedInto.has(canon)) mergedInto.set(canon, []);
  mergedInto.get(canon).push(alias);
}
const mergeNote = (id) => {
  const a = mergedInto.get(id);
  return a && a.length ? `（�? 合并�?{a.join('�?)}）` : '';
};

// --- hand-written Chinese for the 8 Highs (report H1..H8) --------------------
const HIGH = {
  'S02-1': {
    title: 'prompt=login / max_age 不触发重新认证，OP 把同意时刻伪造成新的 auth_time',
    impact: '`RequiresReauthentication` 是唯一比较会话年龄与请求新鲜度的地方，但它的结果从不用于强制重登录：登录钩子只�?`sessions.AuthenticatedAt` 抄进 pending 请求并返回同�?URL，两�?store �?`RequiresReauthentication==true` 时反而用"同意决策时刻"覆盖 `AuthTime`。结果是一�?24h 的旧会话可以满足 RP �?step-up 要求，�?OP 用一个被签名的假 `auth_time` 为这次从未发生的认证背书�?,
    fix: '让登录边界真正执行该要求：pending 请求 `RequiresReauthentication(now)` 时把浏览器送回 IdP 登录（`/auth/{provider}/start?mode=login`），只有新的 `SignIn` 盖过时间戳后�?`CompleteLogin`；否则绝不覆�?`AuthTime`。`internal/oidcstore` 增加 `ErrReauthenticationRequired`，两后端 `CompleteLogin` 不再伪造�?,
    evidence: '`internal/oidcstore/zz_audit9_freshness_test.go`、`internal/store/memory/zz_audit9_reauth_test.go`、`internal/auth/zz_audit9_reauth_route_test.go`、`internal/zzprobe/protocol/audit9_basic_op_test.go`',
  },
  'S03-1': {
    title: 'return_to 无长度上限且被整段写进服务端 session',
    impact: '`safeurl.RelativePath` 只校验形状、无字节上限；scs 在响应结束时重写整个 session，于是任意匿�?`GET /auth/{provider}/start` 可为每条请求持久化约 60 KiB 的攻击者选定字节。内存模式进�?RAM 无界增长，Postgres 模式 `sessions.data` 无界增长（SweepExpired �?15 分钟最多删 1000 行，追不�?50/s 的到达率）。这与同文件�?handle 设的 128 字节上限�?session 整体重写，其字节不能由调用方决定"）自相矛盾�?,
    fix: '�?`return_to` �?`maxReturnToBytes`（如 2048），超长即替�?拒绝，再写入 session�?,
    evidence: '`safeurl.MaxRelativePathBytes`、`internal/auth/zz_audit9_returnto_test.go`',
  },
  'S06-1': {
    title: 'OIDC discovery / JWKS 用无上限 io.ReadAll 读取（自�?1 MiB 上限覆盖不到�?,
    impact: 'go-oidc �?discovery �?JWKS 时是�?`io.ReadAll(resp.Body)`，唯一约束�?10s 超时（限时不限字节），且 net/http 透明解压 gzip，一个压缩炸弹可在一次正常登录中把进�?OOM。adapter 自己�?1 MiB 上限只作用于 userinfo/QQ�?,
    fix: '把交�?`oidc.ClientContext` �?client 包一层限�?RoundTripper（既�?ContentLength 也硬�?`resp.Body`），复用已有�?1 MiB 上限�?,
    evidence: '`idp/zz_audit9_discovery_body_test.go`、`idp.maxDiscoveryBytes`',
  },
  'S08-2': {
    title: 'driver �?dsn_env 推断时，storage.dsn_env 从不被解�?�?静默内存模式',
    impact: '`databaseURL` 只从字面�?`DATABASE_URL` 预载。Driver 为空�?`dsn_env` 指向别的变量时，switch �?driver 定为 postgres 却从不解析该变量，`openStorage` 按空 URL 走内存分支：不要�?`RE0AUTH_AUDIT_KEY`、审计链退化为内存 ring、重启丢全部状态、`max_in_flight` 按内存标定，且启动日志的 `because=""` 掩盖了原因。显�?driver 下环境里残留�?`DATABASE_URL` 还会盖过文件声明的变量�?,
    fix: '推断分支用与显式分支相同的代码解�?DSN；声明了但未设置的变量按启动错误处理；文件的 `dsn_env` 优先于字面量 `DATABASE_URL`�?,
    evidence: '`cmd/re0auth/zz_audit9_dsnenv_test.go`',
  },
  'S10-1': {
    title: '并发上限�?单客户端半量"�?(平面,客户�? 计数，一个地址可吃满整个进程级信号�?,
    impact: '信号量是进程级的，但每客户端计数�?`plane|client`：一个源地址在两个命名空间各�?`maxInFlight/2`，合计等于整个上限（默认 512）。限流约束的是到达率而非占用槽位，探针又豁免两者，于是"一个地址打满全进程并发、其他客户端�?503，�?/healthz�?readyz 仍绿"这一正是该机制要防的 DoS 成立�?,
    fix: '并发计数改按客户端身份（不含平面）累计；限流桶键保持 (平面,客户�?�?,
    evidence: '`internal/httpapi/zz_audit9_inflight_planes_test.go`',
  },
  'S13-1': {
    title: '压缩 406 拒绝在限流器与并发上限之前返回，完全绕过两道边界',
    impact: '中间件链�?compressor 放在最外层，`negotiate` 不可接受时直接写 406 且不调用 `next`，于是限流令牌与并发槽位都不消耗，�?request-id、可信代理解析、访问日志与指标照付。任何匿名请求带 `Accept-Encoding: *;q=0` 即可无上限地驱动连接/goroutine 与日志洪泛�?,
    fix: '�?compressor 移到限流与并发上限之内（`withRateLimit`/`withInFlightLimit` 包在外层）�?,
    evidence: '`internal/httpapi/zz_audit9_compress_bypass_test.go`',
  },
  'S13-5': {
    title: '内存 OP 存储所�?map 无上限；refresh tombstone 每次轮换留一条、存�?30 天，�?5 分钟清扫持全局锁全表扫�?,
    impact: '每次 refresh 轮换写一条以被消费令牌自�?30 天到期时间为期限�?tombstone，速率�?per-subject/进程上限。默认限流下可达 ~1.3e8 条、数 GB，OOM �?GC 死亡；即便低速率，每 5 分钟�?`opJanitor` 也要�?`s.mu` 整表扫描，周期性冻结全部令牌操作�?,
    fix: '�?store 加总量/tombstone 上限（默�?65536），超出丢弃最旧；清扫尽量移出全局锁或分片�?,
    evidence: '`internal/store/memory/zz_audit9_tombstones_test.go`、`MaxRefreshTombstones`',
  },
  'S14-2': {
    title: 'CompleteBind 不取 per-binding 锁，在途绑定可复活刚被撤销的绑定与上游凭据',
    impact: 'per-binding keyedMutex �?同一绑定只有一个写�?的机制，Unbind/CascadeRevoke/shredBinding/refreshBinding 都持它；只有 CompleteBind 既写 vault 又无条件 `bindings.Put`（忽�?Version）且不持锁。因此绑定回调与撤销并发时，可以�?已解�?�?Kill Switch 扫过"之后重新造出可用的绑定行与上游令牌，而用户与运维被告知已断开�?,
    fix: 'CompleteBind 全程持同一�?per-binding 锁（必要时先重读行，确认未刚被解绑），或改成单个 CAS�?,
    evidence: '`internal/federation/zz_audit9_bind_unbind_race_test.go`',
  },
};

// --- hand-written Chinese for the 30 Mediums ---------------------------------
const MEDIUM = {
  'S01-1': ['已批准的 device_code 可无限次兑换：每次轮询都铸出全新令牌对，而非消费掉该授权', '轮询命中 DeviceApproved 后无条件 `s.issue`，从不标记消费或删除记录；撤销授权也会被静默撤销掉。属 `oauth` 包手�?AS（生产二进制未挂载该端点，嵌�?套件路径可达）�?, '�?approved 记录单次消费（置 spent/删除）后再签发；`DeviceStore` 增消费操作�?],
  'S01-2': ['MemoryDeviceStore 从不清理 pending/decided 记录，设备授权无界增�?, '`SaveDevice` 只插�?byDev/byUser，包内无删除、无过期清扫、无 `SweepExpired` 对应物；过期只在读时判�?, '加删�?清扫 API 并接入后台循环；给每用户与总量设上限�?],
  'S01-3': ['MemoryStore.ConsumeRefresh 忽略 tombstone 期限，过期已消费值仍触发家族撤销（PG 正确报未知）', 'tombstone �?`ExpiresAt` 且注释承诺按其自身期限到期，�?`ConsumeRefresh` 从不读该字段�?, '消费时比�?`tomb.ExpiresAt` �?store 时钟，过期按未知令牌处理�?],
  'S01-6': ['AuthenticateClient 把公开客户端当"已认�?，cascade 撤销闸门对公开客户端形同虚�?, '`client(..., auth=true)` 只在 `ClientConfidential` 时校�?secret，公开客户端忽�?secret 无条件成功�?, '公开客户端一律认证失败（或要求机密）；套件补"无认�?must 被拒"断言�?],
  'S02-2': ['prompt=none 有活会话时被送进交互同意 UI，而不是回 consent_required', '�?OP 不保存可复用同意，每次授权都是新 AuthRequest，只�?`Done` 不查历史授权�?, '有会话且无记忆同意时�?OIDC Core §3.1.2.1 �?`consent_required`�?, ],
  'S02-3': ['设备授权端点拒绝合规�?Basic secret：client_id 做了 form-unescape，secret 没有', '`basicSecret` 原样比对存储�?SHA-256，�?RFC 6749 §2.3.1 要求 client 对两者都�?form-urlencode�?, 'id �?secret 成对解码后再认证�?],
  'S02-4': ['ValidateSigner �?2048 位下限只作用于当前键，不覆盖 JWKS 里公布的 retired key', 'retired key �?Public 与当前键一起进 KeySet 并用�?id_token hint / access token 验证，弱键可继续验签�?, '�?KeySet 中全部签名键统一执行位数下限�?],
  'S04-1': ['已启用的设备授权永不被消费：一�?device_code 铸无限令牌对并静默撤销掉一�?grant 撤销', '（与 S01-1 同根、同位置，见 §5 合并表）', '�?S01-1�?],
  'S05-1': ['刷新拒绝把任�?400/401/403 都判�?授权已死"并加密销毁绑�?, '不看 OAuth error code 与响应体；`refreshRejected` 直接 `vault.Revoke` + `bindings.Delete`，连可重试的配置错误也一�?shred�?, '�?error code 分类（invalid_grant 才判死），可重试错误保留绑定并标冷却�?],
  'S05-2': ['（�? 合并�?S14-2）CompleteBind 绕过 per-binding �?],
  'S06-2': ['配置�?HTTP(S)_PROXY 时，SSRF 私网拦截作用在代理地址而非目标地址', '`http.ProxyFromEnvironment` �?DialContext（以�?Control 钩子）拿到代理地址，目标主机从未被解析或检查�?, '在拨号前解析并校验目标地址，或对配置了代理的部署禁用私网直连�?],
  'S06-3': ['oidcProvider �?providerMu 跨一次网�?discovery，失败又不缓�?�?一个死 issuer 串行化所有并发登�?, '锁覆盖整�?`oidc.NewProvider`�?0s 超时），失败不推�?`discoveredAt`，每次请求重试�?, '发现移出锁（double-checked）或 singleflight + 短超�?+ 负缓存�?],
  'S06-4': ['SocialLogin.states 无界 map，且每次未认�?start 都在锁下 O(n) 清扫', '无上限、无周期清扫，过期只靠每次新 start 的全表扫描执行�?, '给在途授权设上限 + 周期清扫（不随请求数线性）�?],
  'S06-5': ['TapTapLogin.attempts 同样无界、每 challenge 一�?O(n) 清扫，未认证可达', '每条 entry 还持�?DeviceAuth（含验证 URL/码），单条内存不小�?, '�?S06-4�?],
  'S07-1': ['凭据型出站请求完全依赖注�?Doer 的跳转策略；net/http 会把自定义认证头复制到跨主机跳转目标', 'X-LC-Session / X-LC-Key / 上游 MAC Authorization �?CheckRedirect �?nil（stdlib 默认）时会跟随跳转并携带�?, '客户端强制禁止跨主机跳转或在跳转时剥离认证头�?],
  'S07-2': ['vault.Enroll 先持久化凭据、后写审计事�?�?审计失败时对一次已发生的写入报错，留下未审计（federation 里还是孤儿）的秘�?, '�?`Use` �?fail-closed（先审计后交明文）相反�?, '先审计后写入，或写入失败时回滚并在错误里 Join 审计错误�?],
  'S08-1': ['Vault KEK 解析硬编�?RE0AUTH_KEK 优先�?vault.kek_env，重命名的键被静默忽�?, '其他设置都遵�?env > 文件约定或专�?RE0AUTH_ 覆盖，KEK 却先读死名字�?, '`kek_env` 存在时只读它；与 `RE0AUTH_KEK` 不一致时拒绝启动并点名�?],
  'S08-4': ['DeleteAccount 在本地移�?Failed>0 时仍报成功并�?outcome=ok', '`RevokeUserBindings` 只在无法枚举时返错；单条绑定的本地移除失败被折叠进结果�?, '�?Failed>0 反映�?outcome 与错误，别写 ok�?],
  'S09-1': ['迁移回退路径可把带密码的 DSN 写进日志：withMigrationLock 不过滤驱动的解析错误', '`MigrateDown` 直接�?`withMigrationLock`，从不经�?`poolConfig` �?`redactDSNParseError`�?, '对该路径的错误同样调�?`redactDSNParseError`�?],
  'S09-2': ['Tokens.RevokeTokens 并非事务，尽�?revokeMatching 注释声称在事务里 �?批量 Kill Switch/擦除可半执行', '`revokeMatching` 跑在 `s.pool`（autocommit），之后另有两条 DELETE 也在池上�?, '�?revokeMatching 与其后的 DELETE 包进同一事务�?],
  'S10-2': ['readiness 探针 panic 会把 /readyz 永久钉在 "checking"(503)', '`check` 在调用探针前�?`running=true`，只在正常返回路径复位；panic �?`settled` 永不关闭�?, '`defer` 复位 `running`/关闭 `settled`，panic 也走异常路径复位�?],
  'S11-6': ['/v1/admin/audit/verify 同步全表走链、无并发约束，最长持有池连接 45s', '开事务、抬 statement_timeout �?45s、整表扫描；�?per-endpoint 并发上限也无结果缓存�?, '加并发上限（或缓存结果），必要时改成可中断的分段校验�?],
  'S12-1': ['每次尝试的请求超时在读取响应体之前就被解�?, '`fetch` 在响应头到达�?resolve，唯一 deadline �?`res.text()` 之前�?clear，body 卡住�?abort 永不触发�?, '�?clearTimeout 移到 body 读取完成之后（或�?finally）�?],
  'S13-2': ['StoreDeviceAuthorization 每次公开请求都持 store 全局�?O(n) 扫描', '唯一 mutex 同时守所有令牌操作，设备授权端点公开可达�?, '为设备记录建索引/分桶，避免持全局锁扫描�?],
  'S13-3': ['DeleteAuthRequest 每次令牌兑换都在全局锁下扫描全部 pending code', '库在每次授权码铸令牌后调用它，按 requestID 线性查找�?, '�?requestID→code 索引并在同一临界区维护�?],
  'S14-3': ['内存 store 分页器每页重排全表：vault Rotate �?federation Kill Switch 变成 O(N²logN)', '每页都物化全部行、排序、再用游标过滤，游标不减少工作量�?, '让游标真正参与分页（持久有序索引或快照）�?],
  'S14-5': ['refresh 家族撤销与轮换非原子，并发重放可留下新世�?token', '`ConsumeRefresh` 原子，但 `ConsumeRefresh �?RevokeRefreshFamily` �?`ConsumeRefresh �?issue` 不是�?, '�?消费+撤销/签发"做成一个原子步骤（或家族级锁）�?],
  'S14-6': ['内存 OIDCStore 的重放与撤销在单一把全局锁下扫描全部令牌�?tombstone', '（与 S13-2 同根，见 §5 合并表）', '�?S13-2�?],
  'S15-1': ['age 加密失败�?scripts/backup.sh 把明文转储留在磁�?, '脚本 `set -euo pipefail`，`age` 非零即退出，后面�?shred/rm 永不执行�?, 'trap 清理 + 先写临时目录，失败也删明文�?],
  'S15-3': ['备份 CronJob �?activeDeadlineSeconds：一�?pg_dump 挂死会静默停掉之后所有备�?, '`concurrencyPolicy: Forbid` 会跳过新调度，jobTemplate 只有 backoffLimit�?, '�?activeDeadlineSeconds �?pg_dump �?timeout�?],
};

// --- assemble ----------------------------------------------------------------
const sevCell = (id) => (MEDIUM[id] ? 'P2' : 'P3');
const esc = (s) => String(s).replace(/\|/g, '\\|').replace(/\n+/g, ' ').trim();

function block(id) {
  const h = HIGH[id];
  const bucket = P0_IDS.includes(id) ? 'P0 · 阻断上线' : 'P1 · �?;
  return [
    `### ${id} ${h.title}`,
    `- **严重�?*�?{bucket}（第九轮 High；原�?high，对抗性验�?confirmed）`,
    `- **位置**�?{highLocs.get(id) || '�?`docs/security-audit-9.md` §1'}`,
    `- **影响**�?{h.impact}`,
    `- **修法**�?{h.fix}`,
    `- **状�?*�?{statusOf(id)}`,
    `- **证据**�?{h.evidence}；完整机制与验证备注�?\`docs/security-audit-9.md\` §1`,
    `- **来源**：\`docs/security-audit-9.md\` §1（第九轮独立审计）`,
  ].join('\n');
}

const highOrder = HIGH_IDS.filter((id) => P0_IDS.includes(id))
  .concat(HIGH_IDS.filter((id) => !P0_IDS.includes(id)));

const p2rows = [];
for (const row of medium) {
  const [id, cat, enTitle, loc, brief] = row;
  const m = MEDIUM[id];
  if (!m) throw new Error(`medium ${id} has no hand-written entry`);
  const note = mergeNote(id);
  const q = esc(`${m[0]}${note}`);
  const fix = esc(m[1] ?? '');
  // For rows whose canonical entry already carries the merge, keep detail in 修法.
  const detail = m[2] ?? '';
  p2rows.push(`| ${id} | P2 | ${q} | ${esc(loc)} | ${statusOf(id)} | ${fix}${detail ? '�? + esc(detail) : ''} |`);
}

const p3rows = [];
for (const [id, cat, title, loc] of low) {
  const note = mergeNote(id);
  p3rows.push(`| ${id} | P3 | ${esc(title + note)} | ${esc(loc)} | ${statusOf(id)} | �?\`docs/security-audit-9.md\` §3（类别：${esc(cat)}�?|`);
}
for (const [id, cat, title, loc] of info) {
  const note = mergeNote(id);
  p3rows.push(`| ${id} | P3 · 信息 | ${esc('[info] ' + title + note)} | ${esc(loc)} | ${statusOf(id)} | �?\`docs/security-audit-9.md\` §4（类别：${esc(cat)}�?|`);
}

const out = `# 第九轮独立审计抽取结果（${medium.length + low.length + info.length + HIGH_IDS.length} 条）

> 来源：[\`docs/security-audit-9.md\`](../../security-audit-9.md)（独立轮次，只读 HEAD 生产代码）�?> �?\`_extract_round9.mjs\` 生成�?*不要手改本文�?*，改脚本或报告�?> 严重度沿用报告的�?�?�?信息，映射到寄存器为 P0/P1（High）、P2（Medium）、P3（Low + Info）�?> Low/Info 标题保留报告原文（英文），以免改写引入偏差；Medium 为人工中文摘要�?> \`修复状态\` 只认报告 §0 的修复台账：本轮�?8 �?High �?S02-2 已在 \`992710b\` 收口�?
## P0/P1

${highOrder.map(block).join('\n\n')}

## P2/P3

| ID | 严重�?| 问题 | 位置 | 状�?| 修法要点 |
|---|---|---|---|---|---|
${p2rows.join('\n')}
${p3rows.join('\n')}

## 已修�?
- 第九�?8 �?High + S02-2 �?\`992710b\`（逐条修法与复现测试见 \`docs/security-audit-9.md\`「修复状态」）
  - S02-1 \`prompt=login\`/\`max_age\` 重认证、S02-2 \`prompt=none\` 有会话回 \`consent_required\`、S03-1 \`return_to\` 2048 字节上限�?    S06-1 discovery/JWKS 1 MiB 上限、S08-2 \`dsn_env\` 总是解析、S10-1 并发计数改按客户端�?    S13-1 压缩移入限流/并发上限之内、S13-5 refresh tombstone 上限、S14-2 \`CompleteBind\` 全程�?per-binding �?`;

writeFileSync(join(here, 'round9.md'), out, 'utf8');
console.log(JSON.stringify({
  highs: HIGH_IDS.length,
  p2: p2rows.length,
  p3: p3rows.length,
  mergedAway: [...MERGED.keys()].length,
}));
