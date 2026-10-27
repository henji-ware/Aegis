export type Page='overview'|'audit'|'antivirus'|'network'|'firewall'|'privacy'|'history'|'settings';
export interface Settings{reducedMotion:boolean;liveNetwork:boolean;language?:string}
export interface SystemInfo{platform:string;release:string;architecture:string;hostname:string;os:string;memory:number;cpus:number;interfaces:{name:string;address:string;family:string}[]}
export interface Connection{analysis?:{level:string;signals:string[];path:string|null;signature:string|null;inspected:boolean;at:string;token:string|null};id:string;protocol:string;localAddress:string;localPort:number;remoteAddress:string;remotePort:number;state:string;pid:number;process:string}
export interface Check{id:string;title:string;status:'pass'|'warning'|'review'|'unknown';evidence:string;recommendation:string;action?:Page}
export interface Audit{id:string;at:string;system:SystemInfo;checks:Check[];counts:{pass:number;warning:number;review:number;unknown:number}}
export interface LocalEvent{id:string;at:string;type:string;title:string;detail:string|Record<string,unknown>|number|null;status:string}
export interface AvJob{id:string;type:string;state:string;startedAt:string;endedAt?:string;targets?:string[];lines:string[];error?:string;persistenceError?:string;summary?:{scanned:number|null;infected:number;errors:number;limited:boolean;partial?:boolean;threatsTruncated?:boolean;threats:{path:string;name:string}[]}}
export interface AvStatus{engine:string;installed:boolean;updaterAvailable:boolean;version:string|null;runnable?:boolean;signatures:{ready:boolean;updatedAt:string|null;count:number;files:{name:string;databaseDate:string;version:string}[]};job:AvJob|null;scans:AvJob[];realtime:boolean}
export interface FirewallStatus{platform:string;native:{backend?:string;supported:boolean;error?:string;evidence?:string;enabled?:boolean;stealth?:boolean;profiles?:{Name:string;Enabled:boolean|number;DefaultInboundAction:number|string}[]};rules:{id:string;port:number;pending:boolean;at:string}[];canRestore:boolean}
export interface VpnStatus{installed:boolean;secureStorage:boolean;profiles:{id:string;name:string;meta:{endpoint:string;addresses:string[];fullTunnel:boolean;ipv6:boolean;dns:string[]}}[];active:{id:string;name:string;tunnel:string;interfaceActive:boolean|null;present:boolean|null;interfaceName?:string|null;error?:string;pending:boolean}|null;verification:string}
export interface TorStatus{installed:boolean;state:string;progress:number;port:number|null;lines:string[];error?:string}
export interface Bootstrap{system:SystemInfo;settings:Settings;history:LocalEvent[];latestAudit:Audit|null;version:string;recoveryMessage?:string|null}
export interface AegisAPI{call<T=unknown>(method:string,payload?:unknown):Promise<T>;onEvent(callback:(event:{type:string;data:any})=>void):()=>void}
declare global{interface Window{aegis?:AegisAPI}}

