export type User = {id:number;username:string;role:'admin'|'viewer';created_at:number};
export type Session = {user:User;csrf:string;expires_at:number};
export type Point = {time:number;interval:number;requests:number;matched:number;bytes:number;known_rows:number;detections:number;response_time_min_ms:number;response_time_avg_ms:number;response_time_max_ms:number;response_time_rows:number;response_time_total_ms:number};
export type SourcePoints = {source_id:string;points:Point[]};
export type Detection = {id:number;source_id:string;event_time:string;recorded_at:number;rule:string;group_by:string;group:string;ip:string;user_agent:string;method:string;path:string;raw_query:string;protocol:string;raw_event:string;reason:string;status:number;count:number;window_ms:number;threshold:number};
export type Block = {ip:string;rule:string;started_at:number;expires_at:number};
export type Dashboard = {from:number;to:number;updated_at:number;points:Point[];source_points:SourcePoints[];detections:Detection[];blocks:Block[];detection_count:number;block_count:number;next_before:number};
export type Rule = {id:string;enabled?:boolean;type?:'rate'|'signature'|'cardinality';action?:'dry_run'|'nftables'|'iptables'|'soft_block';log_source:string;path_regex:string;query_regex?:string;statuses?:number[];methods?:string[];unique_by?:'path'|'destination_port';window:string;threshold:number;group_by:string;ignore_ips:string[]};
export type LogSource = {id:string;path:string;format:'nginx_combined'|'nginx_custom'|'nginx_error'|'syslog_sshd'|'netfilter_log';log_format?:string};
export type Config = {revision:string;whitelist_revision:string;ignore_ips:string[];rules:Rule[];sources:LogSource[];block_mode:'dry_run'|'nftables'|'iptables'|'soft_block'|'hybrid';soft_block?:{cookie_ttl:string;sites:Record<string,{hosts:string[];log_sources:string[]}>}};
export type ChallengeStatus = {health:string;mode?:string;metrics_health?:string;metrics_dropped:number;sites:number};
export type ChallengeMetric = {bucket:number;site:string;reason:string;count:number};
export type SoftBlock = {site_id:string;rule_id:string;source_id:string;ip:string;created_at:string;expires_at:string};
export type ConfigState = {config:Config;daemon_available:boolean;daemon:{started_at:string;block_mode:string;config_revision:string};restart_required:boolean|null};
export type HistoryJobRequest = {source_id:string;directory:string;name_regex:string;order?:string;timezone?:string;syslog_year?:number;from?:string;to?:string;allow_malformed?:number;publish?:boolean;comparison_rule?:string;parent_import_id?:string};
export type HistoryJob = {id:string;state:'queued'|'running'|'published'|'failed'|'cancelled';created_at:string;started_at?:string;finished_at?:string;request:HistoryJobRequest;progress:{stage:string;files:number;lines:number;parsed:number;processed:number;detections:number};result?:{output_path:string;import_id:string;files:number;lines:number;parsed:number;ignored:number;malformed:number;detections:number;published:number;warmup:number;first_event:string;last_event:string};error?:string;output_path:string;live_published:boolean};
export type HistoryPreview = {files:{name:string;size:number;compressed:boolean;lines:number;parsed:number;ignored:number;malformed:number;out_of_order_lines:number;first_event?:string;last_event?:string;error?:string}[];lines:number;parsed:number;ignored:number;malformed:number;overlapping:number;expanded_bytes:number;estimated_bytes:number;work_available_bytes:number;output_available_bytes:number;work_dir:string;output_dir:string;first_event?:string;last_event?:string};
export class APIError extends Error { constructor(public status:number,message:string){super(message)} }
export async function api<T>(path:string,options:RequestInit={}):Promise<T>{
 const res=await fetch('/api/'+path,{...options,credentials:'same-origin',headers:{'Content-Type':'application/json',...options.headers}});
 const value=await res.json();if(!res.ok)throw new APIError(res.status,value.error||'Ошибка запроса');return value;
}
