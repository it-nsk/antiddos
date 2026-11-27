import { StrictMode, useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { createRoot } from "react-dom/client";
import { api, APIError } from "./api";
import type {
  Session,
  ConfigState,
  Config,
  Rule,
  LogSource,
  Dashboard,
  Point,
  User,
  Detection,
  ChallengeStatus,
  ChallengeMetric,
  SoftBlock,
  HistoryJob,
  HistoryJobRequest,
  HistoryPreview,
} from "./api";
import { Chart } from "./Chart";
import "./style.css";
import "./detections.css";
const fmt = new Intl.NumberFormat("ru", { maximumFractionDigits: 2 });
const dt = (n: number) => new Date(n * 1000).toLocaleString("ru");
const local = (n: number) => {
  const d = new Date(n * 1000);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 16);
};
const errorTranslations: Record<string, string> = {
  "Invalid username or password": "Неверное имя пользователя или пароль",
  "Too many login attempts; wait one minute":
    "Слишком много попыток входа. Повторите через минуту",
  "Login busy; try again shortly": "Сервис входа занят. Повторите чуть позже",
  "Session expired": "Сессия завершена. Войдите снова",
};
const errText = (e: unknown) =>
  e instanceof Error
    ? errorTranslations[e.message] || e.message
    : "Не удалось выполнить запрос";
const rulePresets: {
  id: string;
  label: string;
  sourceFormats?: string[];
  rule: Partial<Rule>;
}[] = [
  {
    id: "custom",
    label: "Своё правило",
    rule: {
      type: "rate",
      path_regex: "^/$",
      window: "10s",
      threshold: 5,
      group_by: "ip",
    },
  },
  {
    id: "web-sensitive",
    label: "Web · секретные файлы",
    sourceFormats: ["nginx_combined", "nginx_custom"],
    rule: {
      type: "signature",
      path_regex:
        "(?i)(?:^|/)(?:\\.env(?:[/._-]|$)|\\.git(?:/|$)|\\.aws(?:/|$)|proc/self|etc/passwd)",
      window: "1s",
      threshold: 1,
      group_by: "ip",
    },
  },
  {
    id: "web-home-burst",
    label: "Web · всплеск запросов главной",
    sourceFormats: ["nginx_combined", "nginx_custom"],
    rule: {
      type: "rate",
      path_regex: "^/$",
      window: "5s",
      threshold: 10,
      group_by: "ip",
    },
  },
  {
    id: "web-admin",
    label: "Web · перебор admin/login",
    sourceFormats: ["nginx_combined", "nginx_custom"],
    rule: {
      type: "rate",
      path_regex:
        "^/(?:admin|administrator|login|wp-admin|phpmyadmin|manager)(?:/|$)",
      window: "60s",
      threshold: 10,
      group_by: "ip",
    },
  },
  {
    id: "web-sqli",
    label: "Web · SQLi в query",
    sourceFormats: ["nginx_combined", "nginx_custom"],
    rule: {
      type: "signature",
      path_regex: ".*",
      query_regex:
        "(?i)(?:union(?:%20|\\+|\\s)+(?:all(?:%20|\\+|\\s)+)?select|(?:%27|%2527|')(?:%20|\\+|\\s)+(?:and|or)(?:%20|\\+|\\s)+[0-9]+(?:=|%3d)[0-9]+|extractvalue(?:%28|\\()|sleep(?:%28|\\()|benchmark(?:%28|\\())",
      window: "1s",
      threshold: 1,
      group_by: "ip",
    },
  },
  {
    id: "nginx-auth",
    label: "Nginx · ошибки Basic Auth",
    sourceFormats: ["nginx_error"],
    rule: {
      type: "rate",
      path_regex: "^/auth/basic/failure$",
      window: "60s",
      threshold: 5,
      group_by: "ip",
    },
  },
  {
    id: "ssh-password",
    label: "SSH · подбор пароля",
    sourceFormats: ["syslog_sshd"],
    rule: {
      type: "rate",
      path_regex: "^/ssh/failed$",
      window: "60s",
      threshold: 5,
      group_by: "ip",
    },
  },
  {
    id: "ssh-user",
    label: "SSH · перебор пользователей",
    sourceFormats: ["syslog_sshd"],
    rule: {
      type: "rate",
      path_regex: "^/ssh/invalid-user$",
      window: "60s",
      threshold: 3,
      group_by: "ip",
    },
  },
  {
    id: "port-scan",
    label: "Сеть · уникальные порты",
    sourceFormats: ["netfilter_log"],
    rule: {
      type: "cardinality",
      unique_by: "destination_port",
      path_regex: "^/port/(?:tcp|udp)/[0-9]{1,5}$",
      window: "30s",
      threshold: 8,
      group_by: "ip",
    },
  },
  {
    id: "web-unique-paths",
    label: "Web · уникальные URL",
    sourceFormats: ["nginx_combined", "nginx_custom"],
    rule: {
      type: "cardinality",
      unique_by: "path",
      path_regex: ".*",
      window: "30s",
      threshold: 20,
      group_by: "ip",
    },
  },
];
function defaultRuleForSource(source: LogSource): Rule {
  const common = {
    enabled: true,
    action: "dry_run" as const,
    log_source: source.id,
    group_by: "ip",
    ignore_ips: [] as string[],
  };
  if (source.format === "nginx_error")
    return {
      ...common,
      id: `${source.id}-basic-auth`,
      type: "rate",
      path_regex: "^/auth/basic/failure$",
      window: "60s",
      threshold: 5,
    };
  if (source.format === "syslog_sshd")
    return {
      ...common,
      id: `${source.id}-ssh-password`,
      type: "rate",
      path_regex: "^/ssh/failed$",
      window: "60s",
      threshold: 5,
    };
  if (source.format === "netfilter_log")
    return {
      ...common,
      id: `${source.id}-port-scan`,
      type: "cardinality",
      unique_by: "destination_port",
      path_regex: "^/port/(?:tcp|udp)/[0-9]{1,5}$",
      window: "30s",
      threshold: 8,
    };
  return {
    ...common,
    id: `${source.id}-homepage`,
    type: "rate",
    path_regex: "^/$",
    window: "5s",
    threshold: 10,
  };
}

function CaptchaRuleHelp() {
  return (
    <div className="notice subtle rule-action-help" role="note">
      <strong>Чтобы CAPTCHA реально выдавалась:</strong> на сервере должен быть
      установлен checker, а выбранный сайт подключён к Nginx через
      <code>auth_request</code>. После сохранения настройки выполните:
      <ol>
        <li value={0}>
          Найдите ID сайта в <code>/etc/antiddos/config.json</code>, в разделе{" "}
          <code>soft_block.sites</code>. В интерфейсе это блок{" "}
          <strong>Soft-block</strong> на странице правил. Например:
          <pre className="mt-2 mb-0"><code>{'"soft_block": {
  "sites": {
    "site": { "hosts": ["example.com"], "log_sources": ["web"] }
  }
}'}</code></pre>
          Здесь ID сайта — <code>site</code>.
        </li>
        <li>
          <code>sudo /usr/local/bin/antiddos nginx-snippet --config /etc/antiddos/config.json --site &lt;site_id&gt; --output /etc/nginx/snippets/antiddos-&lt;site_id&gt; --write</code>
        </li>
        <li>
          Откройте{" "}
          <code>/etc/nginx/snippets/antiddos-&lt;site_id&gt;/README.txt</code> и
          подключите указанные там include в Nginx; затем добавьте worker Nginx
          в группу <code>antiddos-check</code>.
        </li>
        <li>
          <code>sudo nginx -t &amp;&amp; sudo systemctl restart nginx antiddos antiddos-challenge</code>
        </li>
      </ol>
      <span>
        Замените <code>&lt;site_id&gt;</code> на ID сайта из блока Soft-block.
        Проверка:{" "}
        <code>sudo /usr/local/bin/antiddos soft-block doctor --config /etc/antiddos/config.json --site &lt;site_id&gt;</code>.{" "}
        <a
          href="https://github.com/it-nsk/antiddos#soft-block-captcha-setup"
          target="_blank"
          rel="noreferrer"
        >
          Документация
        </a>
        .
      </span>
    </div>
  );
}
function App() {
  const [session, setSession] = useState<Session | null>(null),
    [checking, setChecking] = useState(true),
    [error, setError] = useState("");
  useEffect(() => {
    api<Session>("session")
      .then(setSession)
      .catch((e) => {
        if (!(e instanceof APIError && e.status === 401)) setError(errText(e));
      })
      .finally(() => setChecking(false));
  }, []);
  if (checking)
    return (
      <div className="login">
        <p>Подключение к AntiDDoS…</p>
      </div>
    );
  return session ? (
    <Workspace session={session} onLogout={() => setSession(null)} />
  ) : (
    <Login initialError={error} onLogin={setSession} />
  );
}
function Login({
  onLogin,
  initialError,
}: {
  onLogin: (s: Session) => void;
  initialError: string;
}) {
  const [name, setName] = useState(""),
    [password, setPassword] = useState(""),
    [error, setError] = useState(initialError),
    [busy, setBusy] = useState(false);
  return (
    <main className="login">
      <div className="login-brand">
        A<span>AntiDDoS</span>
      </div>
      <form
        className="login-card"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError("");
          try {
            onLogin(
              await api<Session>("login", {
                method: "POST",
                body: JSON.stringify({ username: name, password }),
              }),
            );
          } catch (e) {
            setError(errText(e));
          } finally {
            setBusy(false);
          }
        }}
      >
        <p className="eyebrow">ПАНЕЛЬ УПРАВЛЕНИЯ</p>
        <h1>Вход в AntiDDoS</h1>
        <p className="muted">Статистика, срабатывания и разрешённые адреса.</p>
        <label>
          Пользователь
          <input
            autoComplete="username"
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <label>
          Пароль
          <input
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        <button className="primary" disabled={busy}>
          {busy ? "Проверяем…" : "Войти"}
        </button>
        <p className="muted small">
          Учётную запись создаёт администратор через консоль.
        </p>
      </form>
    </main>
  );
}
type Page = "dashboard" | "detections" | "whitelist" | "history" | "users";
function Workspace({
  session,
  onLogout,
}: {
  session: Session;
  onLogout: () => void;
}) {
  const [page, setPage] = useState<Page>("dashboard"),
    [data, setData] = useState<Dashboard | null>(null),
    [config, setConfig] = useState<ConfigState | null>(null),
    [users, setUsers] = useState<User[]>([]);
  const [challenge, setChallenge] = useState<{
      status: ChallengeStatus;
      metrics: ChallengeMetric[] | null;
    } | null>(null),
    [challengePage, setChallengePage] = useState(0);
  const [softBlocks, setSoftBlocks] = useState<SoftBlock[] | null>(null);

  const [historyJobs, setHistoryJobs] = useState<HistoryJob[] | null>(null);
  const [range, setRange] = useState({
      from: Math.floor(Date.now() / 1000) - 3600,
      to: Math.floor(Date.now() / 1000),
    }),
    [live, setLive] = useState(true),
    [error, setError] = useState(""),
    [refresh, setRefresh] = useState(0),
    [before, setBefore] = useState(0);
  const admin = session.user.role === "admin";
  const softEnabled =
    config?.daemon.block_mode === "soft_block" ||
    (config?.daemon.block_mode === "hybrid" &&
      config.config.rules.some((rule) => rule.action === "soft_block"));
  const report = useCallback(
    (e: unknown) => {
      if (e instanceof APIError && e.status === 401) onLogout();
      else setError(errText(e));
    },
    [onLogout],
  );
  useEffect(() => {
    let active = true;
    let busy = false;
    const load = async () => {
      if (busy) return;
      busy = true;
      try {
        const end = live ? Math.floor(Date.now() / 1000) : range.to,
          start = live ? end - (range.to - range.from) : range.from;
        const [d, c] = await Promise.all([
          api<Dashboard>(`dashboard?from=${start}&to=${end}&before=${before}`),
          api<ConfigState>("config"),
        ]);
        if (active) {
          setData(d);
          setConfig(c);
          setError("");
        }
      } catch (e) {
        if (active) report(e);
      } finally {
        busy = false;
      }
    };
    void load();
    const id = window.setInterval(load, 10000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, [range, live, before, refresh, report]);
  useEffect(() => {
    if (!softEnabled) {
      setChallenge(null);
      setChallengePage(0);
      return;
    }
    let active = true;
    const load = async () => {
      try {
        const status = await api<ChallengeStatus>("challenge/status");
        let metrics: ChallengeMetric[] | null = null;
        try {
          metrics = await api<ChallengeMetric[]>(
            "challenge/metrics?limit=1000",
          );
        } catch {
          /* status remains available */
        }
        if (active) setChallenge({ status, metrics });
      } catch {
        if (active) setChallenge(null);
      }
    };
    void load();
    const id = window.setInterval(load, 2000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, [softEnabled, refresh]);
  useEffect(() => {
    if (!softEnabled) {
      setSoftBlocks(null);
      return;
    }
    let active = true;
    const load = async () => {
      try {
        const rows = await api<SoftBlock[]>("soft-blocks");
        if (active) setSoftBlocks(rows);
      } catch {
        if (active) setSoftBlocks(null);
      }
    };
    void load();
    const id = window.setInterval(load, 2000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, [softEnabled, refresh]);
  useEffect(() => {
    if (page === "users" && admin)
      api<User[]>("users").then(setUsers).catch(report);
  }, [page, admin, report]);
  useEffect(() => {
    if (page !== "history" || !admin) return;
    let active = true;
    const load = () =>
      api<HistoryJob[]>("history/jobs")
        .then((v) => {
          if (active) setHistoryJobs(v);
        })
        .catch(report);
    void load();
    const id = window.setInterval(load, 2000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, [page, admin, report]);
  const zoom = (from: number, to: number) => {
    setRange({ from, to });
    setLive(false);
    setBefore(0);
  };
  const showHistoryRange = (from: string, to: string) => {
    const start = Math.floor(new Date(from).getTime() / 1000);
    const end = Math.ceil(new Date(to).getTime() / 1000) + 15;
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start)
      return;
    setRange({ from: start, to: end });
    setLive(false);
    setBefore(0);
    setPage("dashboard");
  };
  const preset = (seconds: number) => {
    const to = Math.floor(Date.now() / 1000);
    setRange({ from: to - seconds, to });
    setLive(true);
    setBefore(0);
  };
  // Keep the selected period when moving between the dashboard and detections.
  // Historical detections otherwise disappear because entering the page reset
  // the query to the current 15 minutes.
  const titles: Record<Page, string> = {
    dashboard: "Обзор трафика",
    detections: "Срабатывания и блокировки",
    whitelist: "Правила и фильтры",
    history: "Исторический анализ",
    users: "Пользователи",
  };
  const totals = data?.points.reduce(
    (a, p) => ({
      requests: a.requests + p.requests,
      matched: a.matched + p.matched,
      bytes: a.bytes + p.bytes,
      known: a.known + p.known_rows,
    }),
    { requests: 0, matched: 0, bytes: 0, known: 0 },
  );
  const measuredResponsePoints = data?.points.filter((p) => p.response_time_rows > 0) ?? [];
  const responseRows = measuredResponsePoints.reduce((sum, p) => sum + p.response_time_rows, 0);
  const responseTotalMS = measuredResponsePoints.reduce((sum, p) => sum + p.response_time_total_ms, 0);
  const pointTotals = (points: Point[]) =>
    points.reduce(
      (a, p) => ({
        requests: a.requests + p.requests,
        matched: a.matched + p.matched,
        bytes: a.bytes + p.bytes,
        detections: a.detections + p.detections,
      }),
      { requests: 0, matched: 0, bytes: 0, detections: 0 },
    );
  const ruleColors = [
    "#df8445",
    "#3866df",
    "#16a48b",
    "#8b5ac7",
    "#d84f8b",
    "#6b7280",
    "#b7791f",
  ];
  const ruleSeriesFor = (chartPoints: Point[], sourceId?: string) => {
    if (!data) return [];
    const counts = new Map<string, Map<number, number>>();
    for (const sample of data.rule_points) {
      if (sourceId !== undefined && sample.source_id !== sourceId) continue;
      const values = counts.get(sample.rule) || new Map<number, number>();
      values.set(sample.time, (values.get(sample.time) || 0) + sample.count);
      counts.set(sample.rule, values);
    }
    return [...counts.keys()]
      .sort()
      .map((rule, index) => ({
        label: rule,
        color: ruleColors[index % ruleColors.length],
        value: (point: Point) => counts.get(rule)?.get(point.time) || 0,
      }));
  };
  const ruleSeries = data ? ruleSeriesFor(data.points) : [];
  const sourceCharts =
    data && config
      ? [
          ...config.config.sources.map((source) => {
            const points =
              data.source_points.find((item) => item.source_id === source.id)
                ?.points ??
              data.points.map((point) => ({
                ...point,
                requests: 0,
                matched: 0,
                bytes: 0,
                known_rows: 0,
                detections: 0,
              }));
            return {
              id: source.id,
              path: source.path,
              points,
              totals: pointTotals(points),
              ruleSeries: ruleSeriesFor(points, source.id),
            };
          }),
          ...data.source_points
            .filter(
              (item) =>
                !config.config.sources.some(
                  (source) => source.id === item.source_id,
                ),
            )
            .map((item) => ({
              id: item.source_id || "unknown",
              path: item.source_id
                ? "Источник больше не настроен"
                : "Старые объединённые данные: источник неизвестен",
              points: item.points,
              totals: pointTotals(item.points),
              ruleSeries: ruleSeriesFor(item.points, item.source_id),
            })),
        ]
      : [];
  return (
    <div className="app">
      <aside>
        <a className="brand" href="/">
          A
          <span>
            AntiDDoS<small>МОНИТОРИНГ И ЗАЩИТА</small>
          </span>
        </a>
        <nav>
          {(
            [
              "dashboard",
              "detections",
              "whitelist",
              ...(admin ? ["users"] : []),
            ] as Page[]
          ).map((p, i) => (
            <button
              className={page === p ? "selected" : ""}
              key={p}
              onClick={() => setPage(p)}
            >
              <span className="nav-mark">{["◫", "≋", "✓", "♙"][i]}</span>
              {titles[p]}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <strong>{session.user.username}</strong>
          <span>{admin ? "Администратор" : "Только просмотр"}</span>
          <button
            onClick={async () => {
              try {
                await api("logout", {
                  method: "POST",
                  headers: { "X-CSRF-Token": session.csrf },
                  body: "{}",
                });
                onLogout();
              } catch (e) {
                report(e);
              }
            }}
          >
            Выйти
          </button>
        </div>
      </aside>
      <main className="workspace">
        <header>
          <div>
            <p className="eyebrow">
              ANTI DDOS / {page === "whitelist" ? "НАСТРОЙКИ" : "НАБЛЮДЕНИЕ"}
            </p>
            <h1>{titles[page]}</h1>
          </div>
          <div
            className={"status " + (config?.daemon_available ? "online" : "")}
          >
            <i />
            {config?.daemon_available
              ? config.daemon.block_mode === "nftables"
                ? "Блокировка включена"
                : config.daemon.block_mode === "soft_block"
                  ? "Soft-block включён"
                  : config.daemon.block_mode === "hybrid"
                    ? "Независимые действия правил включены"
                    : "Режим наблюдения"
              : "Статус демона недоступен"}
          </div>
        </header>
        {error && (
          <div className="error" role="alert">
            {error}{" "}
            <button onClick={() => setRefresh((v) => v + 1)}>Повторить</button>
          </div>
        )}
        {config?.restart_required === true && (
          <div className="notice">
            Настройки сохранены, но демон пока работает со старой конфигурацией.
            Применить: <code>sudo systemctl restart antiddos</code>
          </div>
        )}
        {config && config.restart_required === null && (
          <div className="notice subtle">
            Статистика доступна из базы. Не удалось проверить применённый
            whitelist: нет связи с локальным сокетом демона.
          </div>
        )}
        {(page === "dashboard" || page === "detections") && (
          <>
            <section className="toolbar">
              <div className="presets">
                {[
                  [900, "15 мин"],
                  [3600, "1 час"],
                  [21600, "6 часов"],
                  [86400, "24 часа"],
                  [604800, "7 дней"],
                ].map(([n, label]) => (
                  <button
                    key={n}
                    className={
                      live && range.to - range.from === n ? "active" : ""
                    }
                    onClick={() => preset(Number(n))}
                  >
                    {label}
                  </button>
                ))}
              </div>
              <div className="period">
                <label>
                  С
                  <input
                    aria-label="Начало периода"
                    type="datetime-local"
                    value={local(range.from)}
                    onChange={(e) => {
                      if (e.target.value)
                        zoom(
                          Math.floor(new Date(e.target.value).getTime() / 1000),
                          range.to,
                        );
                    }}
                  />
                </label>
                <label>
                  По
                  <input
                    aria-label="Конец периода"
                    type="datetime-local"
                    value={local(range.to)}
                    onChange={(e) => {
                      if (e.target.value)
                        zoom(
                          range.from,
                          Math.floor(new Date(e.target.value).getTime() / 1000),
                        );
                    }}
                  />
                </label>
              </div>
              {page === "dashboard" && (
                <>
                  <button className="toolbar-reset" onClick={() => preset(900)}>
                    Сбросить масштаб
                  </button>
                  <button
                    onClick={() => {
                      const end = live
                        ? Math.floor(Date.now() / 1000)
                        : range.to;
                      const span = (range.to - range.from) * 2;
                      zoom(end - span, end);
                    }}
                  >
                    − Масштаб
                  </button>
                  <button
                    onClick={() => {
                      const end = live
                        ? Math.floor(Date.now() / 1000)
                        : range.to;
                      const span = Math.max((range.to - range.from) / 2, 30);
                      zoom(Math.floor(end - span), end);
                    }}
                  >
                    + Масштаб
                  </button>
                </>
              )}
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={live}
                  onChange={(e) => {
                    setLive(e.target.checked);
                    setBefore(0);
                  }}
                />
                Сейчас
              </label>
              <button onClick={() => setRefresh((v) => v + 1)}>Обновить</button>
            </section>
            <div className="subline">
              <span>
                {data ? `${dt(data.from)} — ${dt(data.to)}` : "Загрузка…"}
              </span>
              <span>
                Обновление каждые 10 с · {data ? dt(data.updated_at) : "—"}
              </span>
            </div>
          </>
        )}
        {page === "dashboard" && data && totals && (
          <>
            {softEnabled && (
              <>
                <ChallengePanel
                  data={challenge}
                  page={challengePage}
                  onPage={setChallengePage}
                />
                <SoftBlockPanel rows={softBlocks} />
              </>
            )}
            <div className="charts">
              <Chart
                title="Время ответа"
                unit="мс"
                points={data.points}
                onZoom={zoom}
                series={[
                  { label: "Мин", color: "#16a48b", value: (p) => p.response_time_min_ms || 0 },
                  { label: "Среднее", color: "#3866df", value: (p) => p.response_time_avg_ms || 0 },
                  { label: "Макс", color: "#df8445", value: (p) => p.response_time_max_ms || 0 },
                ]}
              />
              <Chart
                title="Запросы"
                unit="запросов/с"
                points={data.points}
                onZoom={zoom}
                series={[
                  {
                    label: "Все",
                    color: "#3866df",
                    value: (p) => p.requests / p.interval,
                  },
                  {
                    label: "Подходят правилам",
                    color: "#16a48b",
                    value: (p) => p.matched / p.interval,
                  },
                ]}
              />
              <Chart
                title="Исходящий трафик"
                unit="байт/с"
                points={data.points}
                onZoom={zoom}
                series={[
                  {
                    label: "Байты ответа",
                    color: "#3866df",
                    value: (p) => p.bytes / p.interval,
                  },
                ]}
              />
              <Chart
                title="Средний ответ"
                unit="байт"
                points={data.points}
                onZoom={zoom}
                series={[
                  {
                    label: "Из ответов с известным размером",
                    color: "#8b5ac7",
                    value: (p) => (p.known_rows ? p.bytes / p.known_rows : 0),
                  },
                ]}
              />
              <Chart
                title="Срабатывания правил"
                unit="за интервал"
                points={data.points}
                onZoom={zoom}
                series={
                  ruleSeries.length
                    ? ruleSeries
                    : [
                        {
                          label: "Detections",
                          color: "#df8445",
                          value: (p) => p.detections,
                        },
                      ]
                }
              />
            </div>
            {sourceCharts.length > 1 && (
              <section className="panel source-breakdown">
                <details>
                  <summary>
                    Графики по отдельным источникам ({sourceCharts.length})
                  </summary>
                  {sourceCharts.map((source) => (
                    <details className="source-graphs" key={source.id}>
                      <summary>
                        <strong>{source.id}</strong> ·{" "}
                        <code>{source.path}</code>
                      </summary>
                      <div className="source-metrics">
                        {[
                          [
                            "Всего запросов",
                            fmt.format(source.totals.requests),
                          ],
                          [
                            "Подходят правилам",
                            fmt.format(source.totals.matched),
                          ],
                          [
                            "Передано",
                            fmt.format(source.totals.bytes / 1048576) + " MiB",
                          ],
                          [
                            "Срабатывания",
                            fmt.format(source.totals.detections),
                          ],
                        ].map(([label, value]) => (
                          <div className="source-metric" key={label}>
                            <span>{label}</span>
                            <strong>{value}</strong>
                          </div>
                        ))}
                      </div>
                      <div className="charts">
                        <Chart
                          title="Запросы"
                          unit="запросов/с"
                          points={source.points}
                          onZoom={zoom}
                          series={[
                            {
                              label: "Все",
                              color: "#3866df",
                              value: (p) => p.requests / p.interval,
                            },
                            {
                              label: "Подходят правилам",
                              color: "#16a48b",
                              value: (p) => p.matched / p.interval,
                            },
                          ]}
                        />
                        <Chart
                          title="Исходящий трафик"
                          unit="байт/с"
                          points={source.points}
                          onZoom={zoom}
                          series={[
                            {
                              label: "Байты ответа",
                              color: "#3866df",
                              value: (p) => p.bytes / p.interval,
                            },
                          ]}
                        />
                        <Chart
                          title="Средний ответ"
                          unit="байт"
                          points={source.points}
                          onZoom={zoom}
                          series={[
                            {
                              label: "Из ответов с известным размером",
                              color: "#8b5ac7",
                              value: (p) =>
                                p.known_rows ? p.bytes / p.known_rows : 0,
                            },
                          ]}
                        />
                        <Chart
                          title="Срабатывания правил"
                          unit="за интервал"
                          points={source.points}
                          onZoom={zoom}
                          series={
                            source.ruleSeries?.length
                              ? source.ruleSeries
                              : [
                                  {
                                    label: "Срабатывания",
                                    color: "#df8445",
                                    value: (p) => p.detections,
                                  },
                                ]
                          }
                        />
                      </div>
                    </details>
                  ))}
                </details>
              </section>
            )}
            <Blocks data={data} rules={config?.config.rules ?? []} admin={admin} onReconcile={() => api("blocks/reconcile",{method:"POST",headers:{"X-CSRF-Token":session.csrf}}).then(()=>setRefresh(v=>v+1)).catch(report)} onUnblock={(ip) => api("blocks/unblock",{method:"POST",headers:{"X-CSRF-Token":session.csrf},body:JSON.stringify({ip})}).then(()=>setRefresh(v=>v+1)).catch(report)} />
            <section className="panel">
              <details>
                <summary>Все показатели трафика по интервалам</summary>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        {[
                          "Начало",
                          "Интервал, с",
                          "Запросы",
                          "Подходят",
                          "Запросов/с",
                          "Байты",
                          "Байт/с",
                          "Известных размеров",
                          "Средний ответ",
                        ].map((v) => (
                          <th key={v}>{v}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {data.points.map((p) => (
                        <tr key={p.time}>
                          <td>{dt(p.time)}</td>
                          <td>{p.interval}</td>
                          <td>{p.requests}</td>
                          <td>{p.matched}</td>
                          <td>{fmt.format(p.requests / p.interval)}</td>
                          <td>{p.bytes}</td>
                          <td>{fmt.format(p.bytes / p.interval)}</td>
                          <td>{p.known_rows}</td>
                          <td>
                            {p.known_rows
                              ? fmt.format(p.bytes / p.known_rows)
                              : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </details>
            </section>
          </>
        )}
        {page === "detections" && data && (
          <>
            <Blocks data={data} rules={config?.config.rules ?? []} admin={admin} onReconcile={() => api("blocks/reconcile",{method:"POST",headers:{"X-CSRF-Token":session.csrf}}).then(()=>setRefresh(v=>v+1)).catch(report)} onUnblock={(ip) => api("blocks/unblock",{method:"POST",headers:{"X-CSRF-Token":session.csrf},body:JSON.stringify({ip})}).then(()=>setRefresh(v=>v+1)).catch(report)} />
            <section className="panel">
              <div className="panel-head">
                <h2>
                  Срабатывания{" "}
                  <span className="badge">{data.detection_count}</span>
                </h2>
                <span>Detection не означает применённую блокировку</span>
              </div>
              <DetectionTable rows={data.detections} />
              <div className="pagination">
                <button disabled={!before} onClick={() => setBefore(0)}>
                  К последним
                </button>
                <button
                  disabled={!data.next_before}
                  onClick={() => {
                    setLive(false);
                    setRange({ from: data.from, to: data.to });
                    setBefore(data.next_before);
                  }}
                >
                  Ранее →
                </button>
                <span>До 100 записей на странице</span>
              </div>
            </section>
          </>
        )}
        {page === "whitelist" && config && (
          <Whitelist
            state={config}
            session={session}
            onSaved={(next) => {
              setConfig(next);
              setRefresh((v) => v + 1);
            }}
            report={report}
          />
        )}
        {page === "history" && admin && (
          <HistoryJobsV2
            jobs={historyJobs}
            sources={config?.config.sources ?? []}
            session={session}
            report={report}
            onShowRange={showHistoryRange}
          />
        )}
        {page === "users" && admin && (
          <section className="panel">
            <div className="panel-head">
              <h2>Доступ к интерфейсу</h2>
              <span>{users.length} пользователей</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Пользователь</th>
                    <th>Роль</th>
                    <th>Создан</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td>
                        <strong>{u.username}</strong>
                      </td>
                      <td>
                        {u.role === "admin" ? "Администратор" : "Просмотр"}
                      </td>
                      <td>{dt(u.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="panel-note">
              Создание, смена пароля и удаление — через{" "}
              <code>antiddos user</code> на сервере. Администратор меняет
              регулярные выражения и whitelist; viewer доступен только для
              просмотра.
            </p>
          </section>
        )}
      </main>
    </div>
  );
}
function HistoryJobs({
  jobs,
  sources,
  session,
  report,
}: {
  jobs: HistoryJob[] | null;
  sources: LogSource[];
  session: Session;
  report: (e: unknown) => void;
}) {
  const [source, setSource] = useState(sources[0]?.id || ""),
    [directory, setDirectory] = useState(""),
    [nameRegex, setNameRegex] = useState(""),
    [order, setOrder] = useState("natural"),
    [from, setFrom] = useState(""),
    [to, setTo] = useState(""),
    [allowMalformed, setAllowMalformed] = useState("1000"),
    [publish, setPublish] = useState(false),
    [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<HistoryPreview | null>(null);
  useEffect(() => {
    if (!source && sources[0]) setSource(sources[0].id);
  }, [source, sources]);
  const request = {
    source_id: source,
    directory,
    name_regex: nameRegex,
    order,
    allow_malformed: Number(allowMalformed),
    publish,
  } satisfies HistoryJobRequest;
  const inspect = async () => {
    setBusy(true);
    try {
      setPreview(
        await api<HistoryPreview>("history/preview", {
          method: "POST",
          headers: { "X-CSRF-Token": session.csrf },
          body: JSON.stringify(request),
        }),
      );
    } catch (e) {
      report(e);
    } finally {
      setBusy(false);
    }
  };
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api<HistoryJob>("history/jobs", {
        method: "POST",
        headers: { "X-CSRF-Token": session.csrf },
        body: JSON.stringify(request),
      });
      setPreview(null);
    } catch (e) {
      report(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Новая историческая задача</h2>
        <span>Источник задаёт формат и все включённые правила</span>
      </div>
      <form onSubmit={submit}>
        <label>
          Источник
          <select value={source} onChange={(e) => setSource(e.target.value)}>
            {sources.map((s) => (
              <option value={s.id} key={s.id}>
                {s.id} · {s.format}
              </option>
            ))}
          </select>
        </label>
        <label>
          Каталог архивов
          <input
            required
            value={directory}
            onChange={(e) => setDirectory(e.target.value)}
            placeholder="/srv/antiddos-archives"
          />
        </label>
        <label>
          Regex имени файла (RE2)
          <input
            required
            value={nameRegex}
            onChange={(e) => setNameRegex(e.target.value)}
            placeholder="^access\.log(?:\.[0-9]+(?:\.gz)?)?$"
          />
        </label>
        <label>
          Начало периода
          <input
            required
            type="datetime-local"
            value={from}
            onChange={(e) => setFrom(e.target.value)}
          />
        </label>
        <label>
          Конец периода
          <input
            required
            type="datetime-local"
            value={to}
            onChange={(e) => setTo(e.target.value)}
          />
        </label>
        <label>
          Пропустить битых строк
          <input
            required
            type="number"
            min="0"
            value={allowMalformed}
            onChange={(e) => setAllowMalformed(e.target.value)}
          />
        </label>
        <label>
          Порядок
          <select value={order} onChange={(e) => setOrder(e.target.value)}>
            <option value="natural">Естественный rotation</option>
            <option value="lexical">Лексический</option>
            <option value="first-event">Первое событие</option>
          </select>
        </label>
        <label>
          <input
            type="checkbox"
            checked={publish}
            onChange={(e) => setPublish(e.target.checked)}
          />{" "}
          После успеха опубликовать в dashboard
        </label>
        <button
          type="button"
          onClick={inspect}
          disabled={busy || !source || !directory || !nameRegex}
        >
          Предпросмотр
        </button>
        <button className="primary" disabled={busy || !sources.length}>
          {busy ? "Запуск…" : "Импортировать"}
        </button>
      </form>
      {preview && (
        <>
          <p className="panel-note">
            Найдено: {preview.files.length} файлов; строк: {preview.lines};
            распознано: {preview.parsed}; пропущено: {preview.ignored}; ошибок:{" "}
            {preview.malformed}; пересечений: {preview.overlapping}.
          </p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Файл</th>
                  <th>Строки</th>
                  <th>Распознано</th>
                  <th>Ошибки</th>
                  <th>Порядок</th>
                </tr>
              </thead>
              <tbody>
                {preview.files.map((file) => (
                  <tr key={file.name}>
                    <td>
                      <code>{file.name}</code>
                      {file.compressed ? " · gzip" : ""}
                      {file.error && (
                        <>
                          <br />
                          <small>{file.error}</small>
                        </>
                      )}
                    </td>
                    <td>{file.lines}</td>
                    <td>{file.parsed}</td>
                    <td>{file.malformed}</td>
                    <td>
                      {file.out_of_order_lines
                        ? "несортированных: " + file.out_of_order_lines
                        : "OK"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      <p className="panel-note">
        Публикация доступна, только если web service запущен с{" "}
        <code>--history-publish</code>; она не создаёт блокировок.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Создано</th>
              <th>Источник / каталог</th>
              <th>Состояние</th>
              <th>Прогресс</th>
              <th>Результат</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {jobs === null ? (
              <tr>
                <td colSpan={6}>Загрузка…</td>
              </tr>
            ) : jobs.length ? (
              jobs.map((job) => (
                <tr key={job.id}>
                  <td>{new Date(job.created_at).toLocaleString("ru")}</td>
                  <td>
                    {job.request.source_id}
                    <br />
                    <code>{job.request.directory}</code>
                  </td>
                  <td>
                    {job.state}
                    {job.error && (
                      <>
                        <br />
                        <small>{job.error}</small>
                      </>
                    )}
                  </td>
                  <td>
                    {job.progress.stage || "ожидание"} · {job.progress.parsed}{" "}
                    строк
                  </td>
                  <td>
                    {job.result ? (
                      <>
                        <code>{job.result.import_id.slice(0, 12)}</code>
                        <br />
                        {job.result.detections} detections
                        {job.live_published && (
                          <>
                            <br />
                            dashboard обновлён
                          </>
                        )}
                      </>
                    ) : job.state === "published" ? (
                      <code>{job.output_path}</code>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td>
                    {(job.state === "queued" || job.state === "running") && (
                      <button
                        onClick={() =>
                          api(`history/jobs/${job.id}/cancel`, {
                            method: "POST",
                            headers: { "X-CSRF-Token": session.csrf },
                            body: "{}",
                          }).catch(report)
                        }
                      >
                        Отменить
                      </button>
                    )}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={6}>Задач ещё нет.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
// The historical flow deliberately derives its range from archive events.
// It does not expose a manual period selector: the preview is the authority.
function HistoryJobsV2({
  jobs,
  sources,
  session,
  report,
  onShowRange,
}: {
  jobs: HistoryJob[] | null;
  sources: LogSource[];
  session: Session;
  report: (e: unknown) => void;
  onShowRange: (from: string, to: string) => void;
}) {
  const [source, setSource] = useState(sources[0]?.id || ""),
    [directory, setDirectory] = useState(""),
    [nameRegex, setNameRegex] = useState(""),
    [preview, setPreview] = useState<HistoryPreview | null>(null),
    [busy, setBusy] = useState(false);
  const [savedResults, setSavedResults] = useState<
    {
      name: string;
      imports: {
        ID: string;
        SourceID: string;
        FirstEvent: string;
        LastEvent: string;
        WarmupComplete: boolean;
      }[];
      rules: { RuleID: string; Count: number }[];
    }[]
  >([]);
  const [openedResult, setOpenedResult] = useState<string | null>(null),
    [resultDetections, setResultDetections] = useState<Dashboard | null>(null),
    [publishedResults, setPublishedResults] = useState<Record<string, boolean>>(
      {},
    );
  const openResult = (name: string, before = 0) => {
    api<Dashboard>(
      `history/results/${encodeURIComponent(name)}/detections?before=${before}`,
    )
      .then((data) => {
        setOpenedResult(name);
        setResultDetections(data);
      })
      .catch(report);
  };
  useEffect(() => {
    api<typeof savedResults>("history/results")
      .then(setSavedResults)
      .catch(report);
  }, [jobs?.length]);
  const request = {
    source_id: source,
    directory,
    name_regex: nameRegex,
    order: "natural",
    allow_malformed: 1000,
  } satisfies HistoryJobRequest;
  const inspect = async () => {
    setBusy(true);
    try {
      setPreview(
        await api<HistoryPreview>("history/preview", {
          method: "POST",
          headers: { "X-CSRF-Token": session.csrf },
          body: JSON.stringify(request),
        }),
      );
    } catch (e) {
      report(e);
    } finally {
      setBusy(false);
    }
  };
  const start = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api<HistoryJob>("history/jobs", {
        method: "POST",
        headers: { "X-CSRF-Token": session.csrf },
        body: JSON.stringify(request),
      });
      setPreview(null);
    } catch (e) {
      report(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Исторический анализ</h2>
        <span>Диапазон определяется по событиям архивов</span>
      </div>
      <form onSubmit={start}>
        <label>
          Source preset
          <select value={source} onChange={(e) => setSource(e.target.value)}>
            {sources.map((s) => (
              <option value={s.id} key={s.id}>
                {s.id} · {s.format}
              </option>
            ))}
          </select>
        </label>
        <label>
          Каталог архивов
          <input
            required
            value={directory}
            onChange={(e) => setDirectory(e.target.value)}
            placeholder="/var/lib/antiddos-history/logs"
          />
        </label>
        <label>
          Regex имени файла (RE2)
          <input
            required
            value={nameRegex}
            onChange={(e) => setNameRegex(e.target.value)}
            placeholder="^site_access\\.log(?:\\.[0-9]+(?:\\.gz)?)?$"
          />
        </label>
        <button
          type="button"
          disabled={busy || !source || !directory || !nameRegex}
          onClick={inspect}
        >
          Предпросмотр
        </button>
        <button className="primary" disabled={busy || !preview}>
          {busy ? "Запуск…" : "Начать импорт"}
        </button>
      </form>
      {preview && (
        <p className="panel-note">
          Найдено {preview.files.length} файлов; событий: {preview.parsed};
          observed range:{" "}
          {preview.first_event
            ? new Date(preview.first_event).toLocaleString("ru")
            : "—"}{" "}
          —{" "}
          {preview.last_event
            ? new Date(preview.last_event).toLocaleString("ru")
            : "—"}
          ; распаковка: {fmt.format(preview.expanded_bytes / 1048576)} MiB;
          оценка места: {fmt.format(preview.estimated_bytes / 1073741824)} GiB +
          1 GiB reserve; work: <code>{preview.work_dir}</code> (свободно{" "}
          {fmt.format(preview.work_available_bytes / 1073741824)} GiB); output:{" "}
          <code>{preview.output_dir}</code> (свободно{" "}
          {fmt.format(preview.output_available_bytes / 1073741824)} GiB).
          Отсутствующий warm-up у начала будет отмечен в provenance и не
          блокирует импорт.
        </p>
      )}
      <p className="panel-note">
        UI не выполняет sudo. Если preview сообщает об отказе в доступе,
        выполните staging:{" "}
        <code>
          sudo install -d -o antiddos-web -g antiddos-web -m 0750
          /var/lib/antiddos-history/logs/nginx
        </code>
        , затем{" "}
        <code>
          sudo rsync -a --chown=antiddos-web:antiddos-web
          /path/to/exported-nginx-archives/
          /var/lib/antiddos-history/logs/nginx/
        </code>
        .
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Создано</th>
              <th>Источник</th>
              <th>Статус</th>
              <th>Прогресс</th>
              <th>Результат</th>
            </tr>
          </thead>
          <tbody>
            {jobs?.length ? (
              jobs.map((job) => (
                <tr key={job.id}>
                  <td>{new Date(job.created_at).toLocaleString("ru")}</td>
                  <td>{job.request.source_id}</td>
                  <td>
                    {job.state}
                    {job.error && (
                      <>
                        <br />
                        <small>{job.error}</small>
                      </>
                    )}
                  </td>
                  <td>
                    {job.progress.stage || "ожидание"} · {job.progress.parsed}
                  </td>
                  <td>
                    {job.result ? (
                      <>
                        {job.result.detections} detections ·{" "}
                        <code>{job.result.import_id}</code> ·{" "}
                        <code>{job.output_path}</code> ·{" "}
                        {job.request.comparison_rule ? (
                          "Сравнение правила: " +
                          job.request.comparison_rule +
                          " · исходный импорт: " +
                          (job.request.parent_import_id || "—")
                        ) : job.live_published ? (
                          <>
                            Опубликовано ·{" "}
                            <button
                              onClick={() =>
                                job.result &&
                                onShowRange(
                                  job.result.first_event,
                                  job.result.last_event,
                                )
                              }
                            >
                              Показать в dashboard
                            </button>
                          </>
                        ) : (
                          <button
                            onClick={() =>
                              api(`history/jobs/${job.id}/publish`, {
                                method: "POST",
                                headers: { "X-CSRF-Token": session.csrf },
                                body: "{}",
                              })
                                .then(
                                  () =>
                                    job.result &&
                                    onShowRange(
                                      job.result.first_event,
                                      job.result.last_event,
                                    ),
                                )
                                .catch(report)
                            }
                          >
                            Опубликовать
                          </button>
                        )}
                      </>
                    ) : (
                      job.output_path
                    )}
                    {(job.state === "queued" || job.state === "running") && (
                      <button
                        onClick={() =>
                          api(`history/jobs/${job.id}/cancel`, {
                            method: "POST",
                            headers: { "X-CSRF-Token": session.csrf },
                            body: "{}",
                          }).catch(report)
                        }
                      >
                        Отменить
                      </button>
                    )}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={5}>Задач ещё нет.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <h3>Изолированные SQLite результаты</h3>
      <p className="panel-note">
        Файлы в history output dir доступны только для чтения; live DB не
        изменяется.
      </p>
      {savedResults.map((result) => (
        <p key={result.name}>
          <code>{result.name}</code>
          {result.imports.map((item) => (
            <span key={item.ID}>
              {" "}
              · {item.SourceID} · {item.ID} · {item.FirstEvent} —{" "}
              {item.LastEvent} · warm-up:{" "}
              {item.WarmupComplete ? "полный" : "неполный"}
            </span>
          ))}{" "}
          <button onClick={() => openResult(result.name)}>
            Посмотреть срабатывания
          </button>{" "}
          {publishedResults[result.name] ? (
            <>
              <strong>Опубликовано в dashboard</strong>{" "}
              <button
                onClick={() =>
                  onShowRange(
                    result.imports[0].FirstEvent,
                    result.imports[0].LastEvent,
                  )
                }
              >
                Показать в dashboard
              </button>
            </>
          ) : (
            <button
              onClick={() => {
                if (
                  !window.confirm(
                    `Опубликовать импорт ${result.imports[0]?.ID} в live dashboard?`,
                  )
                )
                  return;
                api(
                  `history/results/${encodeURIComponent(result.name)}/publish`,
                  {
                    method: "POST",
                    headers: { "X-CSRF-Token": session.csrf },
                    body: JSON.stringify({ import_id: result.imports[0]?.ID }),
                  },
                )
                  .then(() => {
                    setPublishedResults((v) => ({ ...v, [result.name]: true }));
                    onShowRange(
                      result.imports[0].FirstEvent,
                      result.imports[0].LastEvent,
                    );
                  })
                  .catch(report);
              }}
            >
              Опубликовать в dashboard
            </button>
          )}
        </p>
      ))}
      {openedResult && resultDetections && (
        <>
          <h3>
            Срабатывания · {openedResult} · всего{" "}
            {resultDetections.detection_count}
          </h3>
          <DetectionTable rows={resultDetections.detections} />
          <button
            disabled={!resultDetections.next_before}
            onClick={() =>
              openResult(openedResult, resultDetections.next_before)
            }
          >
            Следующая страница →
          </button>
        </>
      )}
    </section>
  );
}
function ChallengePanel({
  data,
  page,
  onPage,
}: {
  data: { status: ChallengeStatus; metrics: ChallengeMetric[] | null } | null;
  page: number;
  onPage: (page: number) => void;
}) {
  const names: Record<string, string> = {
    issued: "Выдано",
    solved: "Решено",
    rejected: "Отклонено",
    immunity: "Пропуск по cookie",
    fail_open: "Пропуск при недоступном feed",
  };
  const pageSize = 20;
  const pageCount = data?.metrics
    ? Math.max(1, Math.ceil(data.metrics.length / pageSize))
    : 1;
  const rows = data?.metrics
    ? [...data.metrics].reverse().slice(page * pageSize, (page + 1) * pageSize)
    : [];
  const pageItems: (number | "ellipsis")[] = [];
  const addPage = (value: number) => {
    if (!pageItems.includes(value)) pageItems.push(value);
  };
  if (pageCount <= 7) {
    for (let index = 0; index < pageCount; index++) addPage(index);
  } else {
    addPage(0);
    if (page > 3) pageItems.push("ellipsis");
    for (
      let index = Math.max(1, page - 1);
      index <= Math.min(pageCount - 2, page + 1);
      index++
    )
      addPage(index);
    if (page < pageCount - 4) pageItems.push("ellipsis");
    addPage(pageCount - 1);
  }
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Проверки CAPTCHA</h2>
        <span>
          {data
            ? `Checker: ${data.status.health} · метрики: ${data.status.metrics_health || "недоступны"}`
            : "Checker недоступен"}
        </span>
      </div>
      {data?.metrics ? (
        data.metrics.length ? (
          <>
            <ul>
              {rows.map((row, i) => (
                <li key={`${row.bucket}-${row.site}-${row.reason}-${i}`}>
                  {row.site} · {names[row.reason] || row.reason} · {row.count}{" "}
                  <span className="muted small">({dt(row.bucket)})</span>
                </li>
              ))}
            </ul>
            <div className="pagination" aria-label="Пагинация проверок CAPTCHA">
              <button
                aria-label="Предыдущая страница"
                disabled={page === 0}
                onClick={() => onPage(page - 1)}
              >
                ‹
              </button>
              {pageItems.map((item, index) =>
                item === "ellipsis" ? (
                  <span
                    className="pagination-ellipsis"
                    key={`ellipsis-${index}`}
                  >
                    …
                  </span>
                ) : (
                  <button
                    key={item}
                    aria-current={page === item ? "page" : undefined}
                    className={page === item ? "active" : ""}
                    onClick={() => onPage(item)}
                  >
                    {item + 1}
                  </button>
                ),
              )}
              <button
                aria-label="Следующая страница"
                disabled={page >= pageCount - 1}
                onClick={() => onPage(page + 1)}
              >
                ›
              </button>
            </div>
          </>
        ) : (
          <p>За последний час сохранённых проверок нет.</p>
        )
      ) : (
        <p>Данные метрик недоступны.</p>
      )}
    </section>
  );
}
function SoftBlockPanel({ rows }: { rows: SoftBlock[] | null }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Активные проверки soft-block</h2>
        <span>Решения о проверке, не блокировки firewall</span>
      </div>
      {rows === null ? (
        <p>Данные недоступны.</p>
      ) : rows.length ? (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Сайт</th>
                  <th>Источник</th>
                  <th>Правило</th>
                  <th>Создано</th>
                  <th>Истекает</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={`${row.site_id}-${row.rule_id}-${row.ip}`}>
                    <td>
                      <code>{row.ip}</code>
                    </td>
                    <td>{row.site_id}</td>
                    <td>{row.source_id}</td>
                    <td>{row.rule_id}</td>
                    <td>{new Date(row.created_at).toLocaleString("ru")}</td>
                    <td>{new Date(row.expires_at).toLocaleString("ru")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {rows.length === 1000 && <p>Показаны первые 1000 решений.</p>}
        </>
      ) : (
        <p>Активных проверок нет.</p>
      )}
    </section>
  );
}
function Blocks({ data, rules, admin, onReconcile, onUnblock }: { data: Dashboard; rules: Config["rules"]; admin:boolean; onReconcile:()=>void; onUnblock:(ip:string)=>void }) {
  const sourceByRule = new Map(rules.map((rule) => [rule.id, rule.log_source]));
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>
          Активные блокировки <span className="badge">{data.block_count}</span>
        </h2>
        <span>На текущий момент · до 1000 адресов</span>
		{admin && <button type="button" onClick={onReconcile}>Синхронизировать блокировки с firewall</button>}
      </div>
      {data.blocks.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>IP</th>
                <th>Источник лога</th>
                <th>Правило</th>
				<th>Происхождение</th>
                <th>Заблокирован</th>
                <th>Истекает</th>
                <th>Осталось</th>
                {admin && <th aria-label="Действия"></th>}
              </tr>
            </thead>
            <tbody>
              {data.blocks.map((b) => (
                <tr key={b.ip}>
                  <td>
                    <code>{b.ip}</code>
                  </td>
                  <td>{sourceByRule.get(b.rule) || "источник неизвестен"}</td>
                  <td>{b.rule}</td>
				  <td>{b.origin === "external" ? "Внешний firewall" : "Обнаружение AntiDDoS"}</td>
                  <td>{dt(b.started_at)}</td>
                  <td>{dt(b.expires_at)}</td>
                  <td>{Math.max(0, b.expires_at - data.updated_at)} с</td>
                  {admin && <td><button type="button" className="block-remove" title={`Снять блокировку ${b.ip}`} aria-label={`Снять блокировку ${b.ip}`} onClick={() => onUnblock(b.ip)}>×</button></td>}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty">
          <span>✓</span>Активных блокировок нет
        </div>
      )}
    </section>
  );
}
function detectionRequest(d: Detection) {
  const http = [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
  ].includes(d.method);
  if (http) {
    const target = (d.path || "/") + (d.raw_query ? `?${d.raw_query}` : "");
    return `${d.method} ${target}${d.protocol ? ` ${d.protocol}` : ""}`;
  }
  return (
    d.raw_event ||
    [d.method, d.path].filter(Boolean).join(" ") ||
    "Исходное событие не сохранено"
  );
}
function detectionReason(d: Detection) {
  if (d.reason) return d.reason;
  if (d.rule.toLowerCase().includes("sqli"))
    return "Старая запись SQLi: точный query ранее не сохранялся";
  if (d.method === "SSH") return "Серия неудачных попыток входа по SSH";
  if (d.method === "GET") return "Частота HTTP-запросов превысила порог";
  return "Условие правила выполнено";
}
function DetectionTable({ rows }: { rows: Detection[] }) {
  return rows.length ? (
    <div className="table-wrap">
      <table className="detections-table">
        <thead>
          <tr>
            {[
              "Время события",
              "Источник лога",
              "Правило",
              "Причина срабатывания",
              "Запрос / исходное событие",
              "Status",
              "IP",
              "Число / порог",
              "Окно",
              "User-Agent",
              "Записано",
            ].map((s) => (
              <th key={s}>{s}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((d) => {
            const request = detectionRequest(d);
            const reason = detectionReason(d);
            return (
              <tr key={d.id}>
                <td>{new Date(d.event_time).toLocaleString("ru")}</td>
                <td>{d.source_id || "источник не сохранён"}</td>
                <td>{d.rule}</td>
                <td className="detection-reason" title={reason}>
                  {reason}
                </td>
                <td className="detection-event">
                  <code title={request}>{request}</code>
                  {d.raw_event && d.raw_event !== request && (
                    <details>
                      <summary>Полная строка лога</summary>
                      <code>{d.raw_event}</code>
                    </details>
                  )}
                </td>
                <td>{d.status || "—"}</td>
                <td>
                  <code>{d.ip}</code>
                </td>
                <td>
                  {d.count} / {d.threshold}
                </td>
                <td>{d.window_ms / 1000} с</td>
                <td className="long" title={d.user_agent}>
                  {d.user_agent || "—"}
                </td>
                <td>{new Date(d.recorded_at).toLocaleString("ru")}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  ) : (
    <div className="empty">За выбранный период срабатываний нет</div>
  );
}
function Whitelist({
  state,
  session,
  onSaved,
  report,
}: {
  state: ConfigState;
  session: Session;
  onSaved: (state: ConfigState) => void;
  report: (e: unknown) => void;
}) {
  const [doc, setDoc] = useState<Config>(state.config);
  const [global, setGlobal] = useState<string[]>([...state.config.ignore_ips]);
  const [rules, setRules] = useState<Record<string, string[]>>(
    Object.fromEntries(
      state.config.rules.map((r) => [r.id, [...r.ignore_ips]]),
    ),
  );
  const [regexes, setRegexes] = useState<Record<string, string>>(
    Object.fromEntries(state.config.rules.map((r) => [r.id, r.path_regex])),
  );
  const [queryRegexes, setQueryRegexes] = useState<Record<string, string>>(
    Object.fromEntries(
      state.config.rules.map((r) => [r.id, r.query_regex || ""]),
    ),
  );
  const [statuses, setStatuses] = useState<Record<string, string>>(
    Object.fromEntries(
      state.config.rules.map((r) => [r.id, (r.statuses || []).join(",")]),
    ),
  );
  const [actions, setActions] = useState<Record<string, string>>(
    Object.fromEntries(state.config.rules.map((r) => [r.id, r.action || ""])),
  );
  const [ruleSources, setRuleSources] = useState<Record<string, string>>(
    Object.fromEntries(state.config.rules.map((r) => [r.id, r.log_source])),
  );
  const [windows, setWindows] = useState<Record<string, string>>(
    Object.fromEntries(state.config.rules.map((r) => [r.id, r.window])),
  );
  const [thresholds, setThresholds] = useState<Record<string, number>>(
    Object.fromEntries(state.config.rules.map((r) => [r.id, r.threshold])),
  );
  const [groups, setGroups] = useState<Record<string, string>>(
    Object.fromEntries(state.config.rules.map((r) => [r.id, r.group_by])),
  );
  const [enabled, setEnabled] = useState<Record<string, boolean>>(
    Object.fromEntries(
      state.config.rules.map((r) => [r.id, r.enabled !== false]),
    ),
  );
  const [types, setTypes] = useState<Record<string, string>>(
    Object.fromEntries(state.config.rules.map((r) => [r.id, r.type || "rate"])),
  );
  const [uniqueBy, setUniqueBy] = useState<Record<string, string>>(
    Object.fromEntries(
      state.config.rules.map((r) => [r.id, r.unique_by || "path"]),
    ),
  );
  const [blockMode, setBlockMode] = useState<Config["block_mode"]>(
    state.config.block_mode,
  );
  const [cookieTTL, setCookieTTL] = useState(
    state.config.soft_block?.cookie_ttl || "",
  );
  const [addRules, setAddRules] = useState<Rule[]>([]),
    [deleteRules, setDeleteRules] = useState<string[]>([]);
  const [addSources, setAddSources] = useState<LogSource[]>([]),
    [sourceWizard, setSourceWizard] = useState(false);
  const [sourceDraft, setSourceDraft] = useState<LogSource>({
    id: "",
    path: "",
    format: "nginx_combined",
  });
  const [wizard, setWizard] = useState(false),
    [selectedPreset, setSelectedPreset] = useState("custom"),
    [draft, setDraft] = useState<Rule>({
      id: "",
      enabled: true,
      type: "rate",
      action: "dry_run",
      log_source: state.config.sources[0]?.id || "",
      path_regex: "^/$",
      window: "10s",
      threshold: 5,
      group_by: "ip",
      ignore_ips: [],
    });
  const [dirty, setDirty] = useState(false),
    [busy, setBusy] = useState(false),
    [message, setMessage] = useState(""),
    [saved, setSaved] = useState(false);
  const [openRules, setOpenRules] = useState<Record<string, boolean>>({});
  const readOnly = session.user.role !== "admin";
  useEffect(() => {
    if (!dirty) return;
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);
  function reset(c: Config) {
    setDoc(c);
    setGlobal([...c.ignore_ips]);
    setRules(Object.fromEntries(c.rules.map((r) => [r.id, [...r.ignore_ips]])));
    setRegexes(Object.fromEntries(c.rules.map((r) => [r.id, r.path_regex])));
    setQueryRegexes(
      Object.fromEntries(c.rules.map((r) => [r.id, r.query_regex || ""])),
    );
    setStatuses(
      Object.fromEntries(
        c.rules.map((r) => [r.id, (r.statuses || []).join(",")]),
      ),
    );
    setActions(Object.fromEntries(c.rules.map((r) => [r.id, r.action || ""])));
    setRuleSources(
      Object.fromEntries(c.rules.map((r) => [r.id, r.log_source])),
    );
    setWindows(Object.fromEntries(c.rules.map((r) => [r.id, r.window])));
    setThresholds(Object.fromEntries(c.rules.map((r) => [r.id, r.threshold])));
    setGroups(Object.fromEntries(c.rules.map((r) => [r.id, r.group_by])));
    setTypes(Object.fromEntries(c.rules.map((r) => [r.id, r.type || "rate"])));
    setUniqueBy(
      Object.fromEntries(c.rules.map((r) => [r.id, r.unique_by || "path"])),
    );
    setEnabled(
      Object.fromEntries(c.rules.map((r) => [r.id, r.enabled !== false])),
    );
    setBlockMode(c.block_mode);
    setCookieTTL(c.soft_block?.cookie_ttl || "");
    setAddRules([]);
    setDeleteRules([]);
    setAddSources([]);
    setSourceWizard(false);
    setDirty(false);
    setMessage("");
    setSaved(false);
  }
  useEffect(() => {
    if (!dirty && state.config.revision !== doc.revision) reset(state.config);
  }, [state.config, dirty, doc.revision]);
  const parse = (items: string[]) => items.map((v) => v.trim()).filter(Boolean);
  const setGlobalIP = (index: number, value: string) => {
    setGlobal((items) => items.map((item, i) => (i === index ? value : item)));
    setDirty(true);
  };
  const addGlobalIP = () => {
    setGlobal((items) => [...items, ""]);
    setDirty(true);
  };
  const removeGlobalIP = (index: number) => {
    setGlobal((items) => items.filter((_, i) => i !== index));
    setDirty(true);
  };
  const setRuleIP = (id: string, index: number, value: string) => {
    setRules((items) => ({
      ...items,
      [id]: (items[id] || []).map((item, i) => (i === index ? value : item)),
    }));
    setDirty(true);
  };
  const addRuleIP = (id: string) => {
    setRules((items) => ({ ...items, [id]: [...(items[id] || []), ""] }));
    setDirty(true);
  };
  const removeRuleIP = (id: string, index: number) => {
    setRules((items) => ({
      ...items,
      [id]: (items[id] || []).filter((_, i) => i !== index),
    }));
    setDirty(true);
  };
  const availableSources = [...doc.sources, ...addSources];
  const effectiveAction = (rule: Rule) =>
    blockMode === "hybrid"
      ? actions[rule.id] || rule.action || "dry_run"
      : blockMode;
  const actionLabel = (action: string) =>
    action === "soft_block"
      ? "CAPTCHA"
      : action === "nftables"
        ? "nftables"
        : action === "iptables"
          ? "iptables+ipset"
          : "наблюдение";
  const modeHelp =
    blockMode === "nftables" ? (
      <>
        nftables: служба сохраняет <code>CAP_NET_ADMIN</code> и блокирует IP на
        портах <code>block_tcp_ports</code>.{" "}
        <a
          href="https://github.com/it-nsk/antiddos#nftables-blocking-setup"
          target="_blank"
          rel="noreferrer"
        >
          Как включить блокировки
        </a>
        .
      </>
    ) : blockMode === "iptables" ? (
      <>
        iptables+ipset: служба добавляет IP в свои временные sets и блокирует их
        на портах <code>block_tcp_ports</code>.{" "}
        <a
          href="https://github.com/it-nsk/antiddos#iptables-ipset-blocking-setup"
          target="_blank"
          rel="noreferrer"
        >
          Как включить блокировки
        </a>
        .
      </>
    ) : blockMode === "soft_block" ? (
      <>
        CAPTCHA: <code>CAP_NET_ADMIN</code> не используется; нужны checker и
        подключение <code>auth_request</code> в Nginx.{" "}
        <a
          href="https://github.com/it-nsk/antiddos#soft-block-captcha-setup"
          target="_blank"
          rel="noreferrer"
        >
          Как подключить CAPTCHA
        </a>
        .
      </>
    ) : blockMode === "hybrid" ? (
      <>
        Действие задаётся для каждого правила. Для firewall нужны порты и
        whitelist; для CAPTCHA нужны checker и Nginx.
      </>
    ) : (
      <>
        Наблюдение: служба только читает логи и записывает detections;{" "}
        <code>CAP_NET_ADMIN</code>, checker и изменение Nginx не требуются.
      </>
    );
  const formatHelp: Record<LogSource["format"], string> = {
    nginx_combined:
      "Обычный access_log Nginx: IP, дата, запрос в кавычках и HTTP-статус.",
    nginx_custom:
      "Нестандартный access_log Nginx. Найдите имя формата в access_log и соответствующую директиву log_format.",
    nginx_error: "Журнал error_log Nginx, обычно /var/log/nginx/error.log.",
    syslog_sshd:
      "Журнал OpenSSH с сообщениями sshd, обычно /var/log/auth.log или /var/log/secure.",
    netfilter_log:
      "Журнал UFW/kernel со строками SRC=, PROTO= и DPT=, например /var/log/ufw.log или /var/log/kern.log.",
  };
  async function save() {
    const modeChanged = blockMode !== doc.block_mode;
    const actionEnablesFirewall =
      blockMode === "hybrid" &&
      (doc.rules.some(
        (r) =>
          (actions[r.id] === "nftables" || actions[r.id] === "iptables") &&
          r.action !== actions[r.id],
      ) ||
        addRules.some(
          (r) => r.action === "nftables" || r.action === "iptables",
        ));
    const confirmRealBlocks =
      (modeChanged &&
        (blockMode === "nftables" ||
          blockMode === "iptables" ||
          blockMode === "hybrid")) ||
      actionEnablesFirewall;
    if (
      confirmRealBlocks &&
      !window.confirm(
        "Включить реальные блокировки? После сохранения и перезапуска AntiDDoS будет блокировать IP в firewall. Продолжить?",
      )
    )
      return;
    setBusy(true);
    setMessage("");
    setSaved(false);
    try {
      const result = await api<ConfigState>("config/rules", {
        method: "PUT",
        headers: { "X-CSRF-Token": session.csrf },
        body: JSON.stringify({
          revision: doc.revision,
          ignore_ips: parse(global),
          rules: Object.fromEntries(
            doc.rules.map((r) => [
              r.id,
              {
                enabled: enabled[r.id] !== false,
                log_source: ruleSources[r.id] ?? r.log_source,
                ignore_ips: parse(rules[r.id] || []),
                path_regex: regexes[r.id] ?? r.path_regex,
                query_regex: queryRegexes[r.id] ?? r.query_regex ?? "",
                statuses: (statuses[r.id] || "")
                  .split(",")
                  .map((v) => Number(v.trim()))
                  .filter(Boolean),
                unique_by:
                  (types[r.id] ?? r.type ?? "rate") === "cardinality"
                    ? (uniqueBy[r.id] ?? r.unique_by ?? "path")
                    : "",
                window: windows[r.id] ?? r.window,
                threshold: Number(thresholds[r.id] ?? r.threshold),
                group_by: groups[r.id] ?? r.group_by,
                type: types[r.id] ?? r.type ?? "rate",
                ...(blockMode === "hybrid"
                  ? { action: actions[r.id] || r.action }
                  : {}),
              },
            ]),
          ),
          add_sources: addSources,
          add_rules: addRules,
          delete_rules: deleteRules,
          ...(modeChanged ? { block_mode: blockMode } : {}),
          ...(doc.soft_block && cookieTTL !== doc.soft_block.cookie_ttl
            ? { cookie_ttl: cookieTTL }
            : {}),
          confirm_real_blocks: confirmRealBlocks,
        }),
      });
      reset(result.config);
      onSaved(result);
      setSaved(true);
      setMessage("Сохранено. Перезапустите antiddos для применения.");
    } catch (e) {
      report(e);
      setMessage(errText(e));
      setOpenRules((items) => ({
        ...items,
        ...Object.fromEntries(
          doc.rules
            .filter((rule) => !deleteRules.includes(rule.id))
            .map((rule) => [rule.id, true]),
        ),
      }));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <p className="muted">
        Настройте источник, условия срабатывания и whitelist каждого правила.
        Изменения сначала остаются в форме и начинают действовать после
        сохранения и перезапуска службы.
      </p>
      {dirty && !readOnly && (
        <div className="unsaved-banner" aria-live="polite">
          <span className="unsaved-dot" />
          Есть несохранённые изменения{" "}
          <span>
            Сохраните их внизу страницы, затем выполните{" "}
            <code>sudo systemctl restart antiddos</code>.
          </span>
        </div>
      )}
      {dirty && doc.revision !== state.config.revision && (
        <div className="notice">
          Конфигурация изменилась на сервере. Перезагрузите форму перед
          сохранением.
        </div>
      )}
      <section className="panel editor">
        <div>
          <h2>Режим блокировки</h2>
          <p>
            Сейчас демон работает в режиме:{" "}
            <strong>
              {state.daemon.block_mode === "nftables"
                ? "nftables"
                : state.daemon.block_mode === "iptables"
                  ? "iptables+ipset"
                  : state.daemon.block_mode === "soft_block"
                    ? "Soft-block с CAPTCHA"
                    : state.daemon.block_mode === "hybrid"
                      ? "Независимые действия правил"
                      : "Наблюдение (dry-run)"}
            </strong>
            .
          </p>
          <p className="muted small">
            Переключение сохраняется в конфиге. Новый режим начнёт действовать
            после перезапуска службы.
          </p>
        </div>
        <label>
          Режим
          <select
            aria-label="Режим блокировки"
            disabled={readOnly}
            value={blockMode}
            onChange={(e) => {
              const mode = e.target.value as Config["block_mode"];
              setBlockMode(mode);
              if (mode === "hybrid")
                setActions(
                  Object.fromEntries(
                    doc.rules.map((rule) => [
                      rule.id,
                      actions[rule.id] || rule.action || "dry_run",
                    ]),
                  ),
                );
              setDirty(true);
            }}
          >
            <option value="dry_run">
              Наблюдение — только фиксировать detections
            </option>
            <option value="nftables">Реальные блокировки через nftables</option>
            <option value="iptables">
              Реальные блокировки через iptables + ipset
            </option>
            {doc.soft_block && (
              <option value="soft_block">Soft-block с CAPTCHA</option>
            )}
            <option value="hybrid">Независимые действия каждого правила</option>
          </select>
          <p className="muted small mode-help">{modeHelp}</p>
        </label>
      </section>
      {doc.soft_block && (
        <section className="panel editor">
          <div>
            <h2>Soft-block</h2>
            <p>Настроенные сайты и источники:</p>
            {Object.entries(doc.soft_block.sites || {}).map(([id, site]) => (
              <p key={id}>
                <strong>{id}</strong> · {site.hosts.join(", ")} ·{" "}
                {site.log_sources.join(", ")}
              </p>
            ))}
          </div>
          <label>
            Время действия cookie
            <input
              aria-label="Время действия cookie"
              value={cookieTTL}
              readOnly={readOnly}
              onChange={(e) => {
                setCookieTTL(e.target.value);
                setDirty(true);
              }}
            />
            <p className="muted small">
              От 1m до 24h, например 30m. Изменение применяется после
              перезапуска daemon.
            </p>
          </label>
        </section>
      )}
      <section className="panel editor">
        <div>
          <h2>Глобальный whitelist</h2>
          <p>Действует для всех правил.</p>
          <p className="muted small">
            IPv4, IPv6 или CIDR.
            <br />
            Например: 192.0.2.10 или 2001:db8::/32.
          </p>
        </div>
        <div className="ip-list" aria-label="Глобальные разрешённые адреса">
          {global.map((ip, index) => (
            <div className="ip-row" key={index}>
              <input
                aria-label={`Глобальный IP ${index + 1}`}
                readOnly={readOnly}
                value={ip}
                placeholder="IPv4, IPv6 или CIDR"
                onChange={(e) => setGlobalIP(index, e.target.value)}
              />
              {!readOnly && (
                <button
                  type="button"
                  aria-label={`Удалить глобальный IP ${index + 1}`}
                  onClick={() => removeGlobalIP(index)}
                >
                  Удалить
                </button>
              )}
            </div>
          ))}
          {global.length === 0 && <p className="ip-list-empty">Список пуст</p>}
          {!readOnly && (
            <button type="button" onClick={addGlobalIP}>
              Добавить IP в глобальный whitelist
            </button>
          )}
        </div>
      </section>
      <section className="panel">
        <div className="panel-head section-head">
          <div>
            <h2>
              Источники логов{" "}
              <span className="badge">{availableSources.length}</span>
            </h2>
            <p className="muted small">
              Путь вводит администратор. При сохранении daemon проверит файл и
              право чтения.
            </p>
          </div>
          {!readOnly && (
            <button type="button" onClick={() => setSourceWizard((v) => !v)}>
              Добавить источник
            </button>
          )}
        </div>
        {sourceWizard && (
          <div className="source-wizard">
            <label>
              Имя источника
              <input
                aria-label="Имя нового источника"
                value={sourceDraft.id}
                placeholder="например ssh_auth"
                onChange={(e) =>
                  setSourceDraft({ ...sourceDraft, id: e.target.value })
                }
              />
            </label>
            <label>
              Путь к логу
              <input
                aria-label="Путь нового источника"
                value={sourceDraft.path}
                placeholder="/var/log/auth.log"
                onChange={(e) =>
                  setSourceDraft({ ...sourceDraft, path: e.target.value })
                }
              />
            </label>
            <label>
              Формат
              <select
                aria-label="Формат нового источника"
                value={sourceDraft.format}
                onChange={(e) =>
                  setSourceDraft({
                    ...sourceDraft,
                    format: e.target.value as LogSource["format"],
                    log_format: "",
                  })
                }
              >
                <option value="nginx_combined">Nginx combined access</option>
                <option value="nginx_custom">Nginx custom access</option>
                <option value="nginx_error">Nginx error</option>
                <option value="syslog_sshd">OpenSSH auth.log</option>
                <option value="netfilter_log">UFW/kernel netfilter</option>
              </select>
              <p className="muted small field-help">
                {formatHelp[sourceDraft.format]}{" "}
                {sourceDraft.format === "nginx_custom" && (
                  <a
                    href="https://github.com/it-nsk/antiddos#nginx-custom-log-format"
                    target="_blank"
                    rel="noreferrer"
                  >
                    Как найти формат
                  </a>
                )}
              </p>
            </label>
            {sourceDraft.format === "nginx_custom" && (
              <label className="source-log-format">
                Формат Nginx
                <input
                  aria-label="log_format нового источника"
                  value={sourceDraft.log_format || ""}
                  placeholder={
                    "log_format main '$remote_addr [$time_local] \"$request\" $status';"
                  }
                  onChange={(e) =>
                    setSourceDraft({
                      ...sourceDraft,
                      log_format: e.target.value,
                    })
                  }
                />
                <p className="muted small field-help">
                  Вставьте полную директиву <code>log_format …;</code> из вывода{" "}
                  <code>sudo nginx -T</code>, а не пример строки из журнала.
                  Нужны IP, время, запрос и статус.
                </p>
              </label>
            )}
            <div className="wizard-actions">
              <button
                className="primary"
                type="button"
                onClick={() => {
                  if (
                    !sourceDraft.id ||
                    !sourceDraft.path ||
                    (sourceDraft.format === "nginx_custom" &&
                      !sourceDraft.log_format)
                  )
                    return;
                  const source = { ...sourceDraft };
                  setAddSources((v) => [...v, source]);
                  setAddRules((v) => [...v, defaultRuleForSource(source)]);
                  setDirty(true);
                  setSourceWizard(false);
                  setSourceDraft({
                    id: "",
                    path: "",
                    format: "nginx_combined",
                  });
                }}
              >
                Добавить с базовым правилом
              </button>
              <button type="button" onClick={() => setSourceWizard(false)}>
                Отмена
              </button>
            </div>
          </div>
        )}
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Имя</th>
                <th>Путь</th>
                <th>Формат</th>
                <th>Состояние</th>
              </tr>
            </thead>
            <tbody>
              {availableSources.map((s) => (
                <tr key={s.id}>
                  <td>{s.id}</td>
                  <td className="source-path">
                    <code title={s.path}>{s.path}</code>
                  </td>
                  <td>{s.format}</td>
                  <td>
                    {addSources.some((x) => x.id === s.id)
                      ? "Ожидает сохранения"
                      : "Настроен"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section className="rules-section" aria-labelledby="rules-heading">
        <div className="rules-heading">
          <div>
            <h2 id="rules-heading">
              Правила{" "}
              <span className="badge">
                {doc.rules.filter((r) => !deleteRules.includes(r.id)).length}
              </span>
            </h2>
            <p className="muted small">
              Откройте правило, чтобы изменить его условия и исключения.
            </p>
          </div>
          {!readOnly && (
            <button type="button" onClick={() => setWizard((v) => !v)}>
              Добавить правило
            </button>
          )}
        </div>
        {!readOnly && (
          <>
            {wizard && (
              <section className="panel rule-wizard">
                <h2>Новое правило</h2>
                <label>
                  Пресет
                  <select
                    value={selectedPreset}
                    onChange={(e) => {
                      const p = rulePresets.find(
                        (x) => x.id === e.target.value,
                      )!;
                      setSelectedPreset(p.id);
                      setDraft((d) => ({
                        ...d,
                        ...p.rule,
                        id: p.id === "custom" ? "" : p.id,
                        log_source:
                          availableSources.find((s) =>
                            p.sourceFormats?.includes(s.format),
                          )?.id || d.log_source,
                      }));
                    }}
                  >
                    {rulePresets.map((p) => (
                      <option value={p.id} key={p.id}>
                        {p.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  ID
                  <input
                    value={draft.id}
                    onChange={(e) => setDraft({ ...draft, id: e.target.value })}
                  />
                </label>
                <label>
                  Источник
                  <select
                    value={draft.log_source}
                    onChange={(e) =>
                      setDraft({ ...draft, log_source: e.target.value })
                    }
                  >
                    {availableSources.map((s) => (
                      <option value={s.id} key={s.id}>
                        {s.id}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Тип
                  <select
                    value={draft.type}
                    onChange={(e) => {
                      const type = e.target.value as Rule["type"];
                      setDraft({
                        ...draft,
                        type,
                        ...(type === "signature"
                          ? { window: "1s", threshold: 1 }
                          : {}),
                      });
                    }}
                  >
                    <option value="rate">Частота событий</option>
                    <option value="signature">Сигнатура</option>
                    <option value="cardinality">Уникальные значения</option>
                  </select>
                </label>
                <label>
                  Regex path
                  <input
                    value={draft.path_regex}
                    onChange={(e) =>
                      setDraft({ ...draft, path_regex: e.target.value })
                    }
                  />
                  {selectedPreset === "web-sqli" && (
                    <p className="muted small field-help">
                      <code>.*</code> проверяет все URL. Для меньшего числа
                      ложных срабатываний укажите конкретный путь, например{" "}
                      <code>^/where2buy$</code>.
                    </p>
                  )}
                </label>
                <label>
                  Regex query
                  <input
                    value={draft.query_regex || ""}
                    onChange={(e) =>
                      setDraft({ ...draft, query_regex: e.target.value })
                    }
                  />
                  {selectedPreset === "web-sqli" && (
                    <p className="muted small field-help">
                      Проверяется исходная query-строка из access.log: например,{" "}
                      <code>%20</code> — пробел, <code>%27</code> — кавычка,{" "}
                      <code>%28</code> — открывающая скобка. Пресет ищет
                      высоковероятные SQLi-конструкции: UNION SELECT, кавычку
                      перед AND/OR 1=1, EXTRACTVALUE, SLEEP и BENCHMARK. Одно
                      совпадение создаёт detection; это сигнал и реакция на
                      сканер, а не замена параметризованным SQL-запросам
                      приложения.
                    </p>
                  )}
                </label>
                <label>
                  HTTP-статусы
                  <input
                    value={(draft.statuses || []).join(",")}
                    placeholder="401,403"
                    onChange={(e) =>
                      setDraft({
                        ...draft,
                        statuses: e.target.value
                          .split(",")
                          .map((v) => Number(v.trim()))
                          .filter(Boolean),
                      })
                    }
                  />
                </label>
                {draft.type !== "signature" && (
                  <>
                    <label>
                      Окно
                      <input
                        value={draft.window}
                        onChange={(e) =>
                          setDraft({ ...draft, window: e.target.value })
                        }
                      />
                    </label>
                    <label>
                      Порог
                      <input
                        type="number"
                        min="1"
                        value={draft.threshold}
                        onChange={(e) =>
                          setDraft({
                            ...draft,
                            threshold: Number(e.target.value),
                          })
                        }
                      />
                    </label>
                  </>
                )}
                {draft.type === "cardinality" && (
                  <label>
                    Что считать уникальным
                    <select
                      value={draft.unique_by || "path"}
                      onChange={(e) =>
                        setDraft({
                          ...draft,
                          unique_by: e.target.value as Rule["unique_by"],
                        })
                      }
                    >
                      <option value="path">URL/path</option>
                      <option value="destination_port">Порт назначения</option>
                    </select>
                  </label>
                )}
                <label>
                  Действие
                  <select
                    disabled={blockMode !== "hybrid"}
                    value={
                      blockMode === "hybrid"
                        ? draft.action || "dry_run"
                        : blockMode
                    }
                    onChange={(e) =>
                      setDraft({
                        ...draft,
                        action: e.target.value as Rule["action"],
                      })
                    }
                  >
                    <option value="dry_run">Наблюдение</option>
                    <option value="soft_block">CAPTCHA</option>
                    <option value="nftables">nftables</option>
                    <option value="iptables">iptables + ipset</option>
                  </select>
                  <p className="muted small field-help">
                    {blockMode === "hybrid"
                      ? "Определяется отдельно для нового правила."
                      : "Определяется глобальным режимом."}
                  </p>
                  {((blockMode === "hybrid" && draft.action === "soft_block") ||
                    blockMode === "soft_block") && (
                    <CaptchaRuleHelp />
                  )}
                </label>
                <div className="wizard-actions">
                  <button
                    className="primary"
                    type="button"
                    onClick={() => {
                      if (!draft.id || !draft.log_source) return;
                      setAddRules((v) => [...v, draft]);
                      setDirty(true);
                      setWizard(false);
                      setSelectedPreset("custom");
                      setDraft({ ...draft, id: "" });
                    }}
                  >
                    Добавить в конфигурацию
                  </button>
                  <button type="button" onClick={() => setWizard(false)}>
                    Отмена
                  </button>
                </div>
              </section>
            )}
            {addRules.length > 0 && (
              <p className="notice">
                Новых правил ожидают сохранения:{" "}
                {addRules.map((r) => r.id).join(", ")}
              </p>
            )}
          </>
        )}
        {doc.rules
          .filter((r) => !deleteRules.includes(r.id))
          .map((r) => {
            const type = types[r.id] ?? r.type ?? "rate";
            const isOpen = !!openRules[r.id];
            const summary =
              type === "signature"
                ? "Одно совпадение"
                : `${thresholds[r.id] ?? r.threshold} ${type === "cardinality" ? `уникальных ${uniqueBy[r.id] ?? r.unique_by ?? "URL"}` : "событий"} / ${windows[r.id] ?? r.window}`;
            return (
              <section
                className={
                  "rule-card " + (enabled[r.id] === false ? "is-disabled" : "")
                }
                key={r.id}
              >
                <div className="rule-card-head">
                  <button
                    className="rule-disclosure"
                    type="button"
                    aria-expanded={isOpen}
                    aria-controls={`rule-editor-${r.id}`}
                    onClick={() =>
                      setOpenRules((items) => ({
                        ...items,
                        [r.id]: !items[r.id],
                      }))
                    }
                  >
                    <span className="rule-chevron" aria-hidden="true">
                      {isOpen ? "⌄" : "›"}
                    </span>
                    <span className="rule-title">
                      <strong>{r.id}</strong>
                      <span className="rule-meta">
                        <span>
                          {enabled[r.id] === false ? "Выключено" : "Включено"}
                        </span>
                        <span>{ruleSources[r.id] ?? r.log_source}</span>
                        <span>{actionLabel(effectiveAction(r))}</span>
                        <span>{summary}</span>
                      </span>
                    </span>
                  </button>
                  {!readOnly && (
                    <div className="rule-actions">
                      <button
                        type="button"
                        disabled={dirty}
                        title={
                          dirty
                            ? "Сначала сохраните правило"
                            : "Создать отдельный результат пересчёта по последнему завершённому архиву источника"
                        }
                        onClick={() =>
                          api(
                            `history/rules/${encodeURIComponent(r.id)}/rewrite`,
                            {
                              method: "POST",
                              headers: { "X-CSRF-Token": session.csrf },
                              body: "{}",
                            },
                          )
                            .then(() =>
                              setMessage(
                                "Пересчёт запущен. Результат появится в историческом анализе.",
                              ),
                            )
                            .catch(report)
                        }
                      >
                        Переписать историю
                      </button>
                      <label className="rule-enabled">
                        <input
                          type="checkbox"
                          checked={enabled[r.id] !== false}
                          onChange={(e) => {
                            setEnabled({
                              ...enabled,
                              [r.id]: e.target.checked,
                            });
                            setDirty(true);
                          }}
                        />{" "}
                        Включено
                      </label>
                      <button
                        className="rule-delete"
                        type="button"
                        title={`Удалить правило ${r.id}`}
                        aria-label={`Удалить правило ${r.id}`}
                        onClick={() => {
                          if (window.confirm(`Удалить правило ${r.id}?`)) {
                            setDeleteRules((v) => [...v, r.id]);
                            setDirty(true);
                          }
                        }}
                      >
                        ×
                      </button>
                    </div>
                  )}
                </div>
                {isOpen && (
                  <div id={`rule-editor-${r.id}`} className="rule-editor">
                    <section className="rule-field-group">
                      <h3>Что отслеживать</h3>
                      <div className="rule-fields">
                        <label>
                          Источник лога
                          <select
                            aria-label={"Источник " + r.id}
                            disabled={readOnly}
                            value={ruleSources[r.id] ?? r.log_source}
                            onChange={(e) => {
                              setRuleSources({
                                ...ruleSources,
                                [r.id]: e.target.value,
                              });
                              setDirty(true);
                            }}
                          >
                            {availableSources.map((source) => (
                              <option value={source.id} key={source.id}>
                                {source.id} · {source.path}
                              </option>
                            ))}
                          </select>
                        </label>
                        <label>
                          Тип правила
                          <select
                            aria-label={"Тип правила " + r.id}
                            disabled={readOnly}
                            value={type}
                            onChange={(e) => {
                              const next = e.target.value;
                              setTypes({ ...types, [r.id]: next });
                              if (next === "signature") {
                                setWindows({ ...windows, [r.id]: "1s" });
                                setThresholds({ ...thresholds, [r.id]: 1 });
                              }
                              setDirty(true);
                            }}
                          >
                            <option value="rate">Частота запросов</option>
                            <option value="signature">
                              Сигнатура — одно совпадение
                            </option>
                            <option value="cardinality">
                              Уникальные значения
                            </option>
                          </select>
                        </label>
                        <label className="rule-field-wide">
                          Регулярное выражение пути
                          <input
                            aria-label={"Регулярное выражение " + r.id}
                            readOnly={readOnly}
                            value={regexes[r.id] ?? r.path_regex}
                            onChange={(e) => {
                              setRegexes({
                                ...regexes,
                                [r.id]: e.target.value,
                              });
                              setDirty(true);
                            }}
                          />
                        </label>
                        <label>
                          Regex query-параметров (необязательно)
                          <input
                            value={queryRegexes[r.id] ?? r.query_regex ?? ""}
                            readOnly={readOnly}
                            placeholder="например (?i)union.*select"
                            onChange={(e) => {
                              setQueryRegexes({
                                ...queryRegexes,
                                [r.id]: e.target.value,
                              });
                              setDirty(true);
                            }}
                          />
                        </label>
                        <label>
                          HTTP-статусы (необязательно)
                          <input
                            value={
                              statuses[r.id] ?? (r.statuses || []).join(",")
                            }
                            readOnly={readOnly}
                            placeholder="например 401,403,404"
                            onChange={(e) => {
                              setStatuses({
                                ...statuses,
                                [r.id]: e.target.value,
                              });
                              setDirty(true);
                            }}
                          />
                        </label>
                      </div>
                    </section>
                    <section className="rule-field-group">
                      <h3>Когда срабатывает</h3>
                      <div className="rule-fields">
                        {type !== "signature" && (
                          <>
                            <label>
                              Окно
                              <input
                                aria-label={"Окно " + r.id}
                                readOnly={readOnly}
                                value={windows[r.id] ?? r.window}
                                onChange={(e) => {
                                  setWindows({
                                    ...windows,
                                    [r.id]: e.target.value,
                                  });
                                  setDirty(true);
                                }}
                                placeholder="10s"
                              />
                            </label>
                            <label>
                              Порог
                              <input
                                type="number"
                                min="1"
                                aria-label={"Порог " + r.id}
                                readOnly={readOnly}
                                value={thresholds[r.id] ?? r.threshold}
                                onChange={(e) => {
                                  setThresholds({
                                    ...thresholds,
                                    [r.id]: Number(e.target.value),
                                  });
                                  setDirty(true);
                                }}
                              />
                            </label>
                            <label>
                              Группировка
                              <select
                                aria-label={"Группировка " + r.id}
                                disabled={readOnly}
                                value={groups[r.id] ?? r.group_by}
                                onChange={(e) => {
                                  setGroups({
                                    ...groups,
                                    [r.id]: e.target.value,
                                  });
                                  setDirty(true);
                                }}
                              >
                                <option value="ip">IP-адрес</option>
                                <option value="path">Путь</option>
                              </select>
                            </label>
                          </>
                        )}
                        {type === "cardinality" && (
                          <label>
                            Уникальность
                            <select
                              disabled={readOnly}
                              value={uniqueBy[r.id] ?? r.unique_by ?? "path"}
                              onChange={(e) => {
                                setUniqueBy({
                                  ...uniqueBy,
                                  [r.id]: e.target.value,
                                });
                                setDirty(true);
                              }}
                            >
                              <option value="path">URL/path</option>
                              <option value="destination_port">
                                Порт назначения
                              </option>
                            </select>
                          </label>
                        )}
                        <label>
                          Действие правила
                          <select
                            aria-label={"Действие " + r.id}
                            disabled={readOnly || blockMode !== "hybrid"}
                            value={effectiveAction(r)}
                            onChange={(e) => {
                              setActions({
                                ...actions,
                                [r.id]: e.target.value,
                              });
                              setDirty(true);
                            }}
                          >
                            <option value="dry_run">
                              Наблюдение — только detection
                            </option>
                            <option value="soft_block">CAPTCHA</option>
                            <option value="nftables">nftables</option>
                          </select>
                          <p className="muted small field-help">
                            {blockMode === "hybrid"
                              ? "Определяется отдельно для этого правила."
                              : "Определяется глобальным режимом."}
                          </p>
                          {effectiveAction(r) === "soft_block" && <CaptchaRuleHelp />}
                        </label>
                      </div>
                    </section>
                    <section className="rule-field-group">
                      <h3>Исключения</h3>
                      <div
                        className="ip-list"
                        aria-label={`Разрешённые адреса правила ${r.id}`}
                      >
                        {(rules[r.id] || []).map((ip, index) => (
                          <div className="ip-row" key={index}>
                            <input
                              aria-label={`IP ${r.id} ${index + 1}`}
                              readOnly={readOnly}
                              value={ip}
                              placeholder="IPv4, IPv6 или CIDR"
                              onChange={(e) =>
                                setRuleIP(r.id, index, e.target.value)
                              }
                            />
                            {!readOnly && (
                              <button
                                type="button"
                                aria-label={`Удалить IP ${r.id} ${index + 1}`}
                                onClick={() => removeRuleIP(r.id, index)}
                              >
                                Удалить
                              </button>
                            )}
                          </div>
                        ))}
                        {(rules[r.id] || []).length === 0 && (
                          <p className="ip-list-empty">
                            Нет адресов этого правила
                          </p>
                        )}
                        {!readOnly && (
                          <button type="button" onClick={() => addRuleIP(r.id)}>
                            Добавить IP в whitelist {r.id}
                          </button>
                        )}
                      </div>
                    </section>
                  </div>
                )}
              </section>
            );
          })}
      </section>
      {!readOnly && (
        <div className={"savebar " + (dirty ? "is-dirty" : "")}>
          <div className="savebar-copy">
            <strong>
              {dirty
                ? "Есть несохранённые изменения"
                : "Все изменения сохранены"}
            </strong>
            <span>
              После сохранения перезапустите службу командой{" "}
              <code>sudo systemctl restart antiddos</code>.
            </span>
          </div>
          <button className="primary" disabled={!dirty || busy} onClick={save}>
            {busy ? "Сохраняем…" : "Сохранить изменения"}
          </button>
          <button onClick={() => reset(state.config)} disabled={!dirty || busy}>
            Отменить
          </button>
        </div>
      )}
      {message &&
        (saved ? (
          <div className="notice" role="status">
            <strong>Сохранено.</strong> Перезапустите antiddos для применения:
            <br />
            <code>sudo systemctl restart antiddos</code>
          </div>
        ) : (
          <div className="error" role="alert">
            {message}
          </div>
        ))}
    </>
  );
}
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
