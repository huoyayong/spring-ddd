---
id: GATE-PRECOMMIT-JAVA-ALL-IN-ONE
category: Pre-Commit-Guard
trigger: git-commit
enforcement: mixed (hard & soft)
detectable_by_python: true
config:
  # ==========================================
  # 【硬门禁】(Hard Gates): 命中立刻阻断 Commit
  # 包含：OOM、中间件雪崩、资损、并发安全、高危漏洞等
  # ==========================================
  hard_gates:
    # ---------------------------
    # 1. 致命：中间件与微服务陷阱 (防雪崩)
    # ---------------------------
    - pattern: '\.keys\(\s*["''][^"'']*["'']\s*\)'
      msg: "[Redis致命风险] 严禁在代码中使用 keys() 命令！Redis 是单线程模型，keys 会阻塞其他所有命令引发大面积雪崩。必须使用 scan() 或精确 key。"
    - pattern: '\.opsForValue\(\)\.set\([^,]+,\s*[^,]+\)'
      msg: "[Redis内存风险] 检测到 Redis set() 操作仅有2个参数，未设置过期时间 (TTL)！AI 常写出这种无界缓存，最终导致 Redis 内存爆满 (OOM)。必须使用含 timeout 参数的 set 方法。"
    - pattern: 'new\s+RestTemplate\(\s*\)'
      msg: "[微服务致命风险] 禁止直接 new RestTemplate()！其底层默认没有超时时间，一旦下游 API 变慢会导致当前服务线程池瞬间耗尽。必须通过 Builder 设置 Connect/Read Timeout。"

    # ---------------------------
    # 2. 致命：OOM 与资源耗尽
    # ---------------------------
    - pattern: 'Executors\.new(Fixed|Cached|SingleThread)'
      msg: "[OOM风险] 禁止使用 Executors 创建线程池！其底层使用无界队列，突发流量会导致OOM。请显式使用 ThreadPoolExecutor。"
    - pattern: 'new\s+Thread\('
      msg: "[资源风险] 禁止显式 new Thread()。必须交由 Spring 异步或全局受控的线程池管理。"

    # ---------------------------
    # 3. 致命：并发安全与资损
    # ---------------------------
    - pattern: 'static\s+(final\s+)?(java\.text\.)?SimpleDateFormat'
      msg: "[并发安全] SimpleDateFormat 非线程安全！声明为 static 高并发下会致日期错乱。请改用 DateTimeFormatter。"
    - pattern: 'new\s+BigDecimal\(\s*[0-9]+\.[0-9]+[df]?\s*\)'
      msg: "[资损风险] 禁止使用 new BigDecimal(double)！会导致严重精度丢失，必须使用 BigDecimal.valueOf() 或 new BigDecimal(String)。"

    # ---------------------------
    # 4. 致命：NPE 与低级逻辑死穴
    # ---------------------------
    - pattern: '\w+\.equals\(\s*["''][^"'']+["'']\s*\)'
      msg: "[NPE风险] 禁止 var.equals(\"常量\") 的写法。请倒置比较：\"常量\".equals(var)，或使用 Objects.equals() 防治空指针。"
    - pattern: '==\s*["''][^"'']*["'']|["''][^"'']*["'']\s*=='
      msg: "[逻辑错误] 禁止使用 == 比较字符串！这比较的是内存地址，请使用 .equals()。"

    # ---------------------------
    # 5. 健壮性：JVM 生命周期与内存泄漏
    # ---------------------------
    - pattern: 'System\.exit\('
      msg: "[健壮性致命] 禁止在业务代码中调用 System.exit()！这会导致整个 JVM 进程直接被强制杀死，引发重大生产事故。"
    - pattern: '\{\s*\{\s*(put|add)\s*\('
      msg: "[内存泄漏] 禁止使用双大括号初始化集合！它会创建隐式的匿名内部类，导致This引用逃逸及严重内存泄漏。请用 Arrays.asList 或 List.of。"

    # ---------------------------
    # 6. 安全底线：防 AI 绕过与高危漏洞
    # ---------------------------
    - pattern: 'Runtime\.getRuntime\(\)\.exec\('
      msg: "[安全漏洞-RCE] 严禁直接使用 Runtime.exec() 执行系统命令！易引发命令注入(RCE)漏洞，请使用 ProcessBuilder 并严审参数。"
    - pattern: '\.csrf\(\)\.disable\(\)'
      msg: "[安全漏洞-CSRF] 严禁随意关闭 Spring Security 的 CSRF 防护，除非确认为无状态 JWT 接口。"
    - pattern: 'check(Client|Server)Trusted\s*\([^)]*\)\s*(throws[^\{]+)?\{\s*\}'
      msg: "[安全漏洞-HTTPS] 检测到空的 TrustManager 实现！信任所有证书会导致中间人攻击 (MITM)。禁止入库！"
    - pattern: '@(Select|Update|Delete|Insert)\([^)]*\$\{[^}]+\}[^)]*\)'
      msg: "[安全漏洞-SQLi] 检测到 MyBatis 注解中使用了 ${...} 拼接 SQL！这会导致严重的 SQL 注入漏洞，必须改为 #{...} 预编译占位符！"
    - pattern: '(?i)(password|secret|token|key)\s*=\s*["''](123456|admin|test|dummy|YOUR_KEY|xxx)["'']'
      msg: "[安全底线] 检测到疑似硬编码的占位符弱密码或密钥，禁止入库。"
    - pattern: '(?i)(public|private|protected)?\s*(static\s+)?(final\s+)?String\s+(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*=\s*["''][^"'']+["'']'
      msg: "[安全底线] 类字段中检测到硬编码敏感信息（password/secret/token/key），禁止入库，请改为读取配置或环境变量。"

    # ---------------------------
    # 7. 异常处理规范
    # ---------------------------
    - pattern: 'catch\s*\([^\)]+\)\s*\{\s*\}'
      msg: "[异常规范] 禁止空的 catch 块！至少需要记录日志或写明注释原因，绝不允许生吞异常。"
    - pattern: 'throw\s+new\s+(RuntimeException|Exception)\('
      msg: "[异常规范] 禁止抛出宽泛的基础异常！请抛出具体的业务异常 (如 BusinessException 等)。"

    # ---------------------------
    # 8. AI 调试残留与测试规避
    # ---------------------------
    - pattern: 'System\.(out|err)\.print|e\.printStackTrace\(\)'
      msg: "[调试残留] 禁止直接使用 System.out 或 e.printStackTrace()，必须使用 Logger。"
    - pattern: '(?i)(http://)?(127\.0\.0\.1|localhost)(:\d+)?/'
      msg: "[AI幻觉] 检测到硬编码的 localhost/127.0.0.1！请改为从配置文件读取。"

  # ==========================================
  # 【软门禁】(Soft Gates): 命中仅警告，不阻断
  # ==========================================
  soft_gates:
    - pattern: '@Transactional\s*$'
      msg: "[事务隐患] @Transactional 未配置 rollbackFor。默认只回滚 RuntimeException，建议改为 @Transactional(rollbackFor = Exception.class)。"
    - pattern: '@Data'
      msg: "[Lombok陷阱] 若 @Data 用在 JPA Entity 上，极易引发死循环或延迟加载异常。建议改为 @Getter/@Setter。"
    - pattern: 'log\.(info|debug|warn|error)\([^,]+?\+[^,]+\)'
      msg: "[性能建议] 日志打印中检测到字符串拼接 (+)。建议使用占位符 {} 以节约内存和 CPU。"
    - pattern: '(?i)(delete|update)\s+[a-zA-Z0-9_]+\s*$'
      msg: "[SQL风险] 检测到疑似没有 WHERE 条件的 UPDATE/DELETE 语句。请再三确认是否真的需要全表更新/删除！"
    - pattern: '(?i)select\s+\*\s+from'
      msg: "[性能建议] SQL 尽量避免 SELECT *，建议指定具体列名以利用覆盖索引并减少网络开销。"
    - pattern: '^\s*import\s+[a-zA-Z0-9_\.]+\.\*;'
      msg: "[代码整洁] 检测到通配符导入 (.*)，建议明确导入具体类。"
    - pattern: '(MD5|MD5Utils|DigestUtils\.md5Hex)'
      msg: "[安全建议] MD5 已不安全。密码哈希请用 BCrypt/Argon2；文件防篡改请用 SHA-256。"

  # 依赖幻觉防护（监听文件）
  watch_files:
    - 'pom.xml'
    - 'build.gradle'
---
