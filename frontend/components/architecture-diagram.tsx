"use client";

import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import styles from "./architecture-diagram.module.css";

type IconKind = "user" | "globe" | "alb" | "ec2" | "db" | "memorydb" | "cert" | "params" | "iam" | "budget" | "mail" | "console" | "api";
type Motion = "rise" | "grow" | "pop" | "fade" | "expand";

const COLOR = {
  compute: "#ED7100",
  network: "#8C4FFF",
  database: "#C925D1",
  security: "#DD344C",
  management: "#E7157B",
  neutral: "#232F3E",
};

const ROUTE = {
  inbound: "#232F3E",
  console: "#2F7DE1",
  api: "#ED7100",
  data: "#C925D1",
  outbound: "#8A97A8",
};

function Glyph({ kind }: { kind: IconKind }) {
  switch (kind) {
    case "user":
      return <><circle cx="24" cy="17" r="6" /><path d="M12 38c0-10 24-10 24 0" /></>;
    case "globe":
      return <><circle cx="24" cy="24" r="13" /><ellipse cx="24" cy="24" rx="6" ry="13" /><path d="M11 24h26" /></>;
    case "alb":
      return <><circle cx="24" cy="13" r="4" /><path d="M24 17v7M12 24h24M12 24v7M24 24v7M36 24v7" /><circle cx="12" cy="35" r="3.5" /><circle cx="24" cy="35" r="3.5" /><circle cx="36" cy="35" r="3.5" /></>;
    case "ec2":
      return <><rect x="14" y="14" width="20" height="20" rx="3" /><rect x="20" y="20" width="8" height="8" /><path d="M19 9v5M24 9v5M29 9v5M19 34v5M24 34v5M29 34v5M9 19h5M9 24h5M9 29h5M34 19h5M34 24h5M34 29h5" /></>;
    case "db":
      return <><ellipse cx="24" cy="14" rx="10" ry="4" /><path d="M14 14v20c0 2.2 4.5 4 10 4s10-1.8 10-4V14" /><path d="M14 24c0 2.2 4.5 4 10 4s10-1.8 10-4" /></>;
    case "memorydb":
      return <><ellipse cx="24" cy="14" rx="10" ry="4" /><path d="M14 14v20c0 2.2 4.5 4 10 4s10-1.8 10-4V14" /><path d="M26 20l-6 9h5l-2 7 7-10h-5z" fill="#fff" stroke="none" /></>;
    case "cert":
      return <><rect x="11" y="12" width="26" height="18" rx="2" /><path d="M17 19h14M17 24h8M29 30v9l3-3 3 3v-9" /></>;
    case "params":
      return <><path d="M13 17h22M13 24h22M13 31h22" /><circle cx="20" cy="17" r="3" fill="#fff" /><circle cx="29" cy="24" r="3" fill="#fff" /><circle cx="22" cy="31" r="3" fill="#fff" /></>;
    case "iam":
      return <><circle cx="19" cy="17" r="5" /><path d="M10 36c0-8 18-8 18 0" /><circle cx="35" cy="27" r="3" /><path d="M35 30v8M35 34h3" /></>;
    case "budget":
      return <text x="24" y="33" textAnchor="middle" fontSize="26" fontWeight="700" fill="#fff" stroke="none">$</text>;
    case "mail":
      return <><rect x="10" y="14" width="28" height="20" rx="2" /><path d="M10 16l14 10 14-10" /></>;
    case "console":
      return <><rect x="10" y="13" width="28" height="22" rx="2" /><path d="M10 20h28" /></>;
    case "api":
      return <text x="24" y="31" textAnchor="middle" fontSize="19" fontWeight="700" fill="#fff" stroke="none" fontFamily="ui-monospace, Menlo, monospace">{"{ }"}</text>;
  }
}

function Icon({ kind, color, x, y, size = 48 }: { kind: IconKind; color: string; x: number | string; y: number | string; size?: number }) {
  return (
    <g transform={`translate(${x} ${y}) scale(${size / 48})`}>
      <rect fill={color} height="48" rx="7" width="48" />
      <g fill="none" stroke="#fff" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.4">
        <Glyph kind={kind} />
      </g>
    </g>
  );
}

/** Wraps a block so it can be revealed on a timeline. Without the playing class it is a plain group. */
function A({ kind = "rise", at, dur, children }: { kind?: Motion; at: number; dur?: number; children: ReactNode }) {
  const style = { "--d": `${at}s`, ...(dur ? { "--dur": `${dur}s` } : {}) } as CSSProperties;
  return <g className={`${styles.a} ${styles[kind]}`} style={style}>{children}</g>;
}

function Head({ x, y, dir, color, at }: { x: number; y: number; dir: "r" | "l"; color: string; at: number }) {
  const d = dir === "r" ? `M${x - 9} ${y - 4.5}L${x} ${y}L${x - 9} ${y + 4.5}z` : `M${x + 9} ${y - 4.5}L${x} ${y}L${x + 9} ${y + 4.5}z`;
  return <A dur={0.2} kind="fade" at={at}><path d={d} fill={color} /></A>;
}

function Line({ d, color, at, dur = 0.6, dashed = false }: { d: string; color: string; at: number; dur?: number; dashed?: boolean }) {
  if (dashed) {
    return <A dur={dur} kind="fade" at={at}><path d={d} fill="none" stroke={color} strokeDasharray="6 4" strokeLinejoin="round" strokeWidth="2" /></A>;
  }
  const style = { "--d": `${at}s`, "--dur": `${dur}s` } as CSSProperties;
  return <path className={styles.draw} d={d} fill="none" pathLength={1} stroke={color} strokeLinejoin="round" strokeWidth="2" style={style} />;
}

function Packet({ d, color, begin, dur }: { d: string; color: string; begin: number; dur: number }) {
  return (
    <circle className={styles.packet} fill={color} opacity="0" r="4.4" stroke="#fff" strokeWidth="1.5">
      <animateMotion begin={`${begin}s`} calcMode="spline" dur={`${dur}s`} fill="freeze" keySplines=".4 0 .2 1" keyTimes="0;1" path={d} />
      <animate attributeName="opacity" begin={`${begin}s`} dur={`${dur}s`} fill="freeze" keyTimes="0;0.12;0.85;1" values="0;1;1;0" />
    </circle>
  );
}

const description =
  "Users reach auth.darshan-pr.tech through the internet gateway to an Application Load Balancer inside a VPC. The load balancer sends " +
  "/api/* and /.well-known/* to the Spring Boot API and every other path to the Next.js console, both running on one EC2 instance in a public " +
  "subnet in Availability Zone a. The API connects over TLS to RDS for PostgreSQL and MemoryDB for Valkey in a private data subnet with no " +
  "route to the internet, and sends email over SMTP with STARTTLS. Availability Zone b holds only the load balancer's second subnet and the " +
  "database subnet group, with no workloads. ACM, Systems Manager Parameter Store, IAM and AWS Budgets support the stack outside the request path.";

/** Shown instead of the diagram on narrow screens, where a scaled-down diagram would be unreadable. */
const STEPS = [
  { color: ROUTE.inbound, title: "Users and customer apps", body: "Connect over HTTPS through the internet gateway to auth.darshan-pr.tech." },
  { color: COLOR.network, title: "Application Load Balancer", body: "Ends TLS with an ACM certificate and redirects HTTP to HTTPS." },
  { color: ROUTE.console, title: "Route / to the console", body: "Next.js, for developers and administrators." },
  { color: ROUTE.api, title: "Route /api/* and /.well-known/* to the API", body: "Spring Boot, for authentication, sessions and roles. The console and API run on one EC2 instance in a public subnet in Availability Zone a." },
  { color: ROUTE.data, title: "RDS for PostgreSQL and MemoryDB for Valkey", body: "Reached over TLS from the API. They sit in a private data subnet with no route to the internet." },
  { color: ROUTE.outbound, title: "Email provider", body: "The API sends verification links and one-time codes by SMTP with STARTTLS." },
  { color: COLOR.management, title: "Supporting services", body: "ACM for certificates, Parameter Store for secrets, IAM for roles and AWS Budgets for cost alerts. Availability Zone b holds only the load balancer's second subnet and the database subnet group, with no workloads." },
];

const SUPPORT = [
  { kind: "cert" as const, color: COLOR.security, x: 180, title: "ACM", sub: "TLS certificate" },
  { kind: "params" as const, color: COLOR.management, x: 430, title: "Systems Manager", sub: "Parameter Store: secrets" },
  { kind: "iam" as const, color: COLOR.security, x: 710, title: "IAM", sub: "Instance and deploy roles" },
  { kind: "budget" as const, color: COLOR.management, x: 940, title: "AWS Budgets", sub: "Monthly cost alert" },
];

export function ArchitectureDiagram() {
  const [run, setRun] = useState(0);
  const svgRef = useRef<SVGSVGElement>(null);
  const playing = run > 0;

  // The svg is re-created on every run (key), so CSS animations and the SMIL timeline both restart from zero.
  useEffect(() => {
    if (run > 0) svgRef.current?.setCurrentTime(0);
  }, [run]);

  return (
    <figure className={styles.figure}>
      <div className={styles.full}>
      <div className={styles.toolbar}>
        <button className={styles.play} onClick={() => setRun((n) => n + 1)} type="button">
          <svg aria-hidden="true" height="14" viewBox="0 0 14 14" width="14">
            {playing ? (
              <path d="M2.2 7a4.8 4.8 0 1 0 1.7-3.7M2 1.8v3.4h3.4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" />
            ) : (
              <path d="M3.5 1.8v10.4L12 7z" fill="currentColor" />
            )}
          </svg>
          {playing ? "Replay animation" : "Play animation"}
        </button>
      </div>

      <div className={styles.scroller}>
        <svg
          aria-describedby="arch-desc"
          aria-labelledby="arch-title"
          className={`${styles.svg} ${playing ? styles.playing : ""}`}
          key={run}
          ref={svgRef}
          role="img"
          viewBox="0 0 1160 640"
        >
          <title id="arch-title">Auth Platform infrastructure on AWS</title>
          <desc id="arch-desc">{description}</desc>

          {/* 1. The client appears first */}
          <A at={0} kind="pop">
            <Icon color={COLOR.neutral} kind="user" size={52} x="26" y="222" />
          </A>
          <A at={0.15}>
            <text className={styles.title} textAnchor="middle" x="52" y="296">Users and</text>
            <text className={styles.title} textAnchor="middle" x="52" y="312">customer apps</text>
          </A>

          {/* 2. Region and VPC frame the path */}
          <A at={0.5} dur={0.9} kind="grow">
            <rect fill="#fff" height="612" rx="6" stroke="#4D5B70" strokeDasharray="6 4" strokeWidth="1.4" width="1036" x="110" y="14" />
            <text className={styles.zone} fill="#232F3E" x="126" y="35">AWS Cloud · eu-north-1 (Stockholm)</text>
          </A>
          <A at={0.75} dur={0.9} kind="grow">
            <rect fill="#FBF9FF" height="468" rx="6" stroke={COLOR.network} strokeWidth="1.6" width="966" x="160" y="46" />
            <text className={styles.zone} fill={COLOR.network} x="176" y="67">VPC</text>
          </A>

          {/* 3. Availability Zone a and the public subnet */}
          <A at={1.2} dur={0.8} kind="grow">
            <rect fill="none" height="326" rx="5" stroke="#147EBA" strokeDasharray="5 4" strokeWidth="1.4" width="902" x="204" y="78" />
            <text className={styles.zone} fill="#147EBA" x="220" y="98">Availability Zone a · all workloads</text>
          </A>
          <A at={1.4} dur={0.8} kind="grow">
            <rect fill="#F4F9EC" height="278" rx="5" stroke="#7AA116" strokeWidth="1.4" width="620" x="220" y="110" />
            <text className={styles.zone} fill="#5C7A0F" x="236" y="130">Public subnet</text>
          </A>

          {/* 4. Internet gateway and load balancer */}
          <A at={1} kind="pop">
            <Icon color={COLOR.network} kind="globe" size={40} x="140" y="228" />
          </A>
          <A at={1.15}>
            <text className={`${styles.small} ${styles.halo}`} textAnchor="middle" x="160" y="282">Internet</text>
            <text className={`${styles.small} ${styles.halo}`} textAnchor="middle" x="160" y="295">gateway</text>
          </A>
          <A at={1.65} kind="pop">
            <Icon color={COLOR.network} kind="alb" size={52} x="274" y="222" />
          </A>
          <A at={1.9}>
            <text className={styles.title} textAnchor="middle" x="300" y="296">Application Load Balancer</text>
            <text className={styles.small} textAnchor="middle" x="300" y="312">HTTPS, ACM certificate</text>
            <text className={styles.small} textAnchor="middle" x="300" y="327">HTTP redirects to HTTPS</text>
          </A>

          {/* 5. The instance and its two services */}
          <A at={2.2} dur={0.8} kind="grow">
            <rect fill="#FFFAF4" height="216" rx="5" stroke={COLOR.compute} strokeWidth="1.6" width="340" x="476" y="140" />
            <Icon color={COLOR.compute} kind="ec2" size={22} x="488" y="148" />
            <text className={styles.zone} fill="#B35400" x="516" y="164">EC2 instance · systemd services</text>
          </A>
          <A at={2.45} dur={0.7} kind="expand">
            <rect fill="#fff" height="68" rx="6" stroke="#CBD5E1" width="300" x="496" y="176" />
          </A>
          <A at={2.65} kind="pop">
            <Icon color={COLOR.neutral} kind="console" size={40} x="508" y="190" />
          </A>
          <A at={2.75}>
            <text className={styles.title} x="560" y="206">Console</text>
            <text className={styles.small} x="560" y="224">Next.js · developer and admin UI</text>
          </A>
          <A at={2.65} dur={0.7} kind="expand">
            <rect fill="#fff" height="68" rx="6" stroke="#CBD5E1" width="300" x="496" y="268" />
          </A>
          <A at={2.85} kind="pop">
            <Icon color={COLOR.neutral} kind="api" size={40} x="508" y="282" />
          </A>
          <A at={2.95}>
            <text className={styles.title} x="560" y="298">API</text>
            <text className={styles.small} x="560" y="316">Spring Boot · auth, sessions, roles</text>
          </A>

          {/* 6. Private data subnet and the two stores */}
          <A at={3.8} dur={0.8} kind="grow">
            <rect fill="#F2F8FC" height="278" rx="5" stroke="#147EBA" strokeWidth="1.4" width="226" x="860" y="110" />
            <text className={styles.zone} fill="#147EBA" x="876" y="130">Private data subnet</text>
            <text className={styles.small} x="876" y="145">no route to the internet</text>
          </A>
          <A at={4.05} kind="pop">
            <Icon color={COLOR.database} kind="db" size={52} x="947" y="170" />
          </A>
          <A at={4.25}>
            <text className={styles.title} textAnchor="middle" x="973" y="240">RDS for PostgreSQL</text>
            <text className={styles.small} textAnchor="middle" x="973" y="256">TLS, encrypted, backups</text>
          </A>
          <A at={4.25} kind="pop">
            <Icon color={COLOR.database} kind="memorydb" size={52} x="947" y="288" />
          </A>
          <A at={4.45}>
            <text className={styles.title} textAnchor="middle" x="973" y="358">MemoryDB for Valkey</text>
            <text className={styles.small} textAnchor="middle" x="973" y="374">TLS, ACL user</text>
          </A>

          {/* 7. Availability Zone b, email, supporting services */}
          <A at={5} dur={0.8} kind="grow">
            <rect fill="none" height="76" rx="5" stroke="#8A97A8" strokeDasharray="5 4" strokeWidth="1.4" width="902" x="204" y="420" />
            <text className={styles.zone} fill="#5D6B81" x="220" y="440">Availability Zone b · load balancer and database subnet group only, no workloads</text>
            <rect fill="#FAFBFC" height="34" rx="4" stroke="#C5CDD8" strokeDasharray="4 3" width="620" x="220" y="450" />
            <text className={styles.small} x="236" y="471">Public subnet (load balancer)</text>
            <rect fill="#FAFBFC" height="34" rx="4" stroke="#C5CDD8" strokeDasharray="4 3" width="226" x="860" y="450" />
            <text className={styles.small} x="876" y="471">Data subnet (RDS)</text>
          </A>
          <A at={5.5} kind="pop">
            <Icon color={COLOR.neutral} kind="mail" size={40} x="32" y="352" />
          </A>
          <A at={5.65}>
            <text className={styles.title} textAnchor="middle" x="52" y="408">Email provider</text>
            <text className={styles.small} textAnchor="middle" x="52" y="423">SMTP</text>
          </A>
          <A at={5.8} dur={0.8} kind="grow">
            <rect fill="#FAFBFC" height="84" rx="6" stroke="#C5CDD8" width="966" x="160" y="530" />
            <text className={styles.zone} fill="#5D6B81" x="176" y="551">Supporting services, outside the request path</text>
          </A>
          {SUPPORT.map((item, i) => (
            <g key={item.title}>
              <A at={6 + i * 0.15} kind="pop">
                <Icon color={item.color} kind={item.kind} size={36} x={item.x} y="562" />
              </A>
              <A at={6.1 + i * 0.15}>
                <text className={styles.title} x={item.x + 46} y="578">{item.title}</text>
                <text className={styles.small} x={item.x + 46} y="593">{item.sub}</text>
              </A>
            </g>
          ))}

          {/* 8. Routes draw in as the blocks they connect appear */}
          <Line at={0.45} color={ROUTE.inbound} d="M80 248H138" dur={0.5} />
          <Head at={0.95} color={ROUTE.inbound} dir="r" x={138} y={248} />
          <A at={0.7} dur={0.4} kind="fade">
            <text className={`${styles.route} ${styles.haloWhite}`} fill={ROUTE.inbound} x="92" y="240">HTTPS</text>
          </A>
          <Line at={1.3} color={ROUTE.inbound} d="M180 248H272" dur={0.5} />
          <Head at={1.8} color={ROUTE.inbound} dir="r" x={272} y={248} />

          <Line at={3} color={ROUTE.console} d="M326 248H400V210H494" dur={0.6} />
          <Head at={3.6} color={ROUTE.console} dir="r" x={494} y={210} />
          <A at={3.4} dur={0.4} kind="fade">
            <text className={styles.route} fill={ROUTE.console} x="406" y="203">/ (default)</text>
          </A>
          <Line at={3.1} color={ROUTE.api} d="M400 248V302H494" dur={0.7} />
          <Head at={3.8} color={ROUTE.api} dir="r" x={494} y={302} />
          <A at={3.6} dur={0.4} kind="fade">
            <text className={styles.route} fill={ROUTE.api} textAnchor="end" x="470" y="319">/api/*</text>
            <text className={styles.route} fill={ROUTE.api} textAnchor="end" x="470" y="333">/.well-known/*</text>
          </A>

          <Line at={4.5} color={ROUTE.data} d="M796 290H828V196H945" dur={0.6} />
          <Head at={5.1} color={ROUTE.data} dir="r" x={945} y={196} />
          <Line at={4.6} color={ROUTE.data} d="M796 314H945" dur={0.5} />
          <Head at={5.1} color={ROUTE.data} dir="r" x={945} y={314} />
          <A at={4.9} dur={0.4} kind="fade">
            <text className={styles.route} fill={ROUTE.data} x="834" y="189">TLS</text>
            <text className={styles.route} fill={ROUTE.data} x="834" y="308">TLS</text>
          </A>

          <Line at={5.4} color={ROUTE.outbound} d="M650 356V372H74" dashed dur={0.6} />
          <Head at={6} color={ROUTE.outbound} dir="l" x={74} y={372} />
          <A at={5.8} dur={0.4} kind="fade">
            <text className={styles.route} fill="#5D6B81" x="236" y="366">Outbound email, STARTTLS, via the internet gateway</text>
          </A>

          {/* 9. Request packets travel the finished routes (only while the animation is playing) */}
          {playing && (
            <g>
              <Packet begin={7} color={ROUTE.inbound} d="M80 248H272" dur={1.3} />
              <Packet begin={8.3} color={ROUTE.console} d="M326 248H400V210H494" dur={0.8} />
              <Packet begin={8.3} color={ROUTE.api} d="M326 248H400V302H494" dur={0.9} />
              <Packet begin={9.2} color={ROUTE.data} d="M796 290H828V196H945" dur={0.8} />
              <Packet begin={9.2} color={ROUTE.data} d="M796 314H945" dur={0.7} />
              <Packet begin={9.4} color={ROUTE.outbound} d="M650 356V372H74" dur={1.2} />
            </g>
          )}
        </svg>
      </div>

      <ul aria-hidden="true" className={styles.legend}>
        <li><span className={styles.line} style={{ background: ROUTE.inbound }} />Inbound HTTPS</li>
        <li><span className={styles.line} style={{ background: ROUTE.console }} />Console route</li>
        <li><span className={styles.line} style={{ background: ROUTE.api }} />API route</li>
        <li><span className={styles.line} style={{ background: ROUTE.data }} />Database and cache, TLS</li>
        <li><span className={`${styles.line} ${styles.dashedLine}`} />Outbound email</li>
      </ul>
      </div>

      <ol className={styles.compact}>
        {STEPS.map((step) => (
          <li key={step.title} style={{ "--c": step.color } as CSSProperties}>
            <strong>{step.title}</strong>
            <span>{step.body}</span>
          </li>
        ))}
      </ol>

      <figcaption>
        Auth Platform runs in a single Availability Zone on AWS, behind an HTTPS load balancer. The console and API share one instance.
        The database and cache are in a private subnet and are not reachable from the internet.
      </figcaption>
    </figure>
  );
}
