export type User = {id:number;username:string;role:'admin'|'viewer';created_at:number};
export type Session = {user:User;csrf:string;expires_at:number};
export type Point = {time:number;interval:number;requests:number;matched:number;bytes:number;known_rows:number;detections:number};
export type SourcePoints = {source_id:string;points:Point[]};
export type Detection = {id:number;source_id:string;event_time:string;recorded_at:number;rule:string;group_by:string;group:string;ip:string;user_agent:string;count:number;window_ms:number;threshold:number};
export type Block = {ip:string;rule:string;started_at:number;expires_at:number};
export type Dashboard = {from:number;to:number;updated_at:number;points:Point[];source_points:SourcePoints[];detections:Detection[];blocks:Block[];detection_count:number;block_count:number;next_before:number};
export type Rule = {id:string;log_source:string;path_regex:string;window:string;threshold:number;group_by:string;ignore_ips:string[]};
export type Config = {revision:string;whitelist_revision:string;ignore_ips:string[];rules:Rule[];sources:{id:string;path:string;format:string}[];block_mode:'dry_run'|'nftables'};
export type ConfigState = {config:Config;daemon_available:boolean;daemon:{started_at:string;block_mode:string;config_revision:string};restart_required:boolean|null};
export class APIError extends Error { constructor(public status:number,message:string){super(message)} }
export async function api<T>(path:string,options:RequestInit={}):Promise<T>{
 const res=await fetch('/api/'+path,{...options,credentials:'same-origin',headers:{'Content-Type':'application/json',...options.headers}});
 const value=await res.json();if(!res.ok)throw new APIError(res.status,value.error||'Ошибка запроса');return value;
}
