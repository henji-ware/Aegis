import {ScanProgress,Quarantine,Automation,NetworkActivity,Updates,Onboarding,VpnDiagnostics} from './Features';
import { summary, recommendation, eventTitle, eventSummary, confirmationSummary, Original, Problem } from './presentation';
import { useEffect, useRef, useState, lazy, Suspense, type ComponentProps, type ReactNode } from 'react';
import { Shield, LayoutDashboard, ScanLine, Bug, Network, ShieldCheck, GlobeLock, History, Settings2, ChevronRight, ArrowUpRight, ArrowRight, ArrowDownToLine, RefreshCw, Search, Check, X, Play, Square, FolderSearch, HardDrive, Activity, LockKeyhole, Eye, Info, TriangleAlert, CheckCircle2, HelpCircle, Loader2, Download, Trash2, Terminal, Monitor, ExternalLink, SlidersHorizontal, Link2, Clock3, GitBranch, Plus, type LucideIcon } from 'lucide-react';
const Orb = lazy(() => import('./Orb').then(module => ({ default: module.Orb })));
function Scene(props: ComponentProps<typeof Orb>) { return <Suspense fallback={<div className="orb-loading" role="status">{t('Carregando visualização 3D…')}</div>}><Orb {...props}/></Suspense>; }
import { useParallax } from './useParallax';
import { call, date, jobLabel } from './api';
import { t, useI18n, languages, setLanguage } from './i18n';
import { version } from '../package.json';
import type { Page, Settings, SystemInfo, Connection, Audit, Check as AuditCheck, LocalEvent, AvStatus, AvJob, FirewallStatus, VpnStatus, TorStatus, Bootstrap } from './types';
function Logo({ small = false }: {
    small?: boolean;
}) { return <div className={'brand ' + (small ? 'small' : '')} role="img" aria-label="Aegis"><svg viewBox="0 0 64 64" fill="none" aria-hidden="true"><path d="M32 4 56 18v28L32 60 8 46V18Z M32 4v56 M8 18l48 28 M56 18 8 46" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"/></svg></div>; }
function Badge({ tone = 'neutral', children }: {
    tone?: string;
    children: ReactNode;
}) { return <span className={'badge ' + tone}><i />{children}</span>; }
function Button({ children, onClick, disabled = false, kind = 'secondary', icon: Icon, className = '' }: {
    children?: ReactNode;
    onClick?: () => void;
    disabled?: boolean;
    kind?: string;
    icon?: LucideIcon;
    className?: string;
}) { return <button type="button" className={'button ' + kind + ' ' + className} disabled={disabled} onClick={onClick}>{Icon && <Icon size={15}/>}<span>{children}</span></button>; }
function Empty({ icon: Icon = ScanLine, title, children }: {
    icon?: LucideIcon;
    title: string;
    children: ReactNode;
}) { return <div className="empty"><div className="empty-icon"><Icon size={26} strokeWidth={1.4}/></div><h3>{title}</h3><p>{children}</p></div>; }
function CheckIcon({ status }: {
    status: string;
}) { const Icon = status === 'pass' ? CheckCircle2 : status === 'warning' ? TriangleAlert : status === 'review' ? Eye : HelpCircle; return <span className={'check-icon ' + status}><Icon size={18}/></span>; }
function Toggle({ checked, onChange, label }: {
    checked: boolean;
    onChange: () => void;
    label: string;
}) { return <button className={'toggle ' + (checked ? 'on' : '')} role="switch" aria-checked={checked} aria-label={label} onClick={onChange}><span /></button>; }
export function App() {
    const { language } = useI18n();
    const navigation: {
        id: Page;
        label: string;
        icon: LucideIcon;
    }[] = [
        { id: 'overview', label: t("Visão geral"), icon: LayoutDashboard }, { id: 'audit', label: t("Diagnóstico"), icon: ScanLine }, { id: 'antivirus', label: t("Antivírus"), icon: Bug }, { id: 'network', label: t("Conexões"), icon: Network }, { id: 'firewall', label: t("Firewall"), icon: ShieldCheck }, { id: 'privacy', label: t("Privacidade"), icon: GlobeLock }, { id: 'history', label: t("Atividade"), icon: History }
    ];
    const titles: Record<Page, {
        eyebrow: string;
        title: string;
        description: string;
    }> = {
        overview: { eyebrow: t("PAINEL"), title: t("Visão geral"), description: t("Status do sistema e acesso aos módulos de segurança.") },
        audit: { eyebrow: t("POSTURA DO DISPOSITIVO"), title: t("Diagnóstico"), description: t("Verificações locais, evidências claras e próximos passos.") },
        antivirus: { eyebrow: t("CLAMAV · CÓDIGO ABERTO"), title: t("Antivírus"), description: t("Varreduras independentes, sem precisar do Windows Defender.") },
        network: { eyebrow: t("VISIBILIDADE DE REDE"), title: t("Conexões"), description: t("Uma fotografia das conexões TCP e dos serviços em escuta.") },
        firewall: { eyebrow: t("CONTROLE DE ACESSO"), title: t("Firewall"), description: t("Revise a proteção de entrada e aplique regras reversíveis.") },
        privacy: { eyebrow: t("CONECTIVIDADE"), title: t("Privacidade"), description: t("WireGuard e Tor no mesmo lugar, com o alcance de cada um à vista.") },
        history: { eyebrow: t("HISTÓRICO LOCAL"), title: t("Atividade"), description: t("Acompanhe verificações e alterações feitas pelo Aegis.") },
        settings: { eyebrow: t("APLICATIVO"), title: t("Preferências"), description: t("Ajuste a experiência e conheça os componentes do aplicativo.") }
    };
    const statusLabel = { pass: t("Atendido"), warning: t("Atenção"), review: t("Revisar"), unknown: t("Não verificado") };
    const [quarantineRevision,setQuarantineRevision]=useState(0);
    const [page, setPage] = useState<Page>('overview'), [system, setSystem] = useState<SystemInfo | null>(null), [settings, setSettings] = useState<Settings>({ reducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches, liveNetwork: false, language: 'system' });
    const [latest, setLatest] = useState<Audit | null>(null), [events, setEvents] = useState<LocalEvent[]>([]), [audits, setAudits] = useState<Audit[]>([]), [av, setAv] = useState<AvStatus | null>(null), [fw, setFw] = useState<FirewallStatus | null>(null), [vpn, setVpn] = useState<VpnStatus | null>(null), [tor, setTor] = useState<TorStatus | null>(null);
    const [connections, setConnections] = useState<Connection[]>([]), [networkError, setNetworkError] = useState(''), [avError, setAvError] = useState(''), [busy, setBusy] = useState(''), [auditRunning, setAuditRunning] = useState(false), [toast, setToast] = useState<{
        text: string;
        error?: boolean;
    } | null>(null), [bootError, setBootError] = useState(''), [loaded, setLoaded] = useState(false);
    const [selectedCheck, setSelectedCheck] = useState<AuditCheck | null>(null), [selectedConnection, setSelectedConnection] = useState<Connection | null>(null), [query, setQuery] = useState(''), [netFilter, setNetFilter] = useState('all'), [port, setPort] = useState(''), [logs, setLogs] = useState(false), [view, setView] = useState('map'), [privacyTab, setPrivacyTab] = useState('vpn'), [palette, setPalette] = useState(false), [paletteQuery, setPaletteQuery] = useState('');
    const shellRef = useRef<HTMLDivElement>(null);
    useParallax(shellRef, settings.reducedMotion);
    const actionRef = useRef(false), toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
    const notify = (text: string, error = false) => {
        setToast({ text, error });
        if (toastTimer.current)
            clearTimeout(toastTimer.current);
        toastTimer.current = setTimeout(() => setToast(null), 6500);
    };
    const refreshHistory = async () => {
        const data = await call<{
            events: LocalEvent[];
            audits: Audit[];
        }>('history');
        setEvents(data.events);
        setAudits(data.audits);
    };
    const refreshAv = async () => {
        try {
            setAv(await call<AvStatus>('av:status'));
            setAvError('');
        }
        catch (error) {
            setAvError((error as Error).message);
        }
    };
    const refreshNetwork = async () => {
        try {
            setConnections(await call<Connection[]>('connections'));
            setNetworkError('');
        }
        catch (error) {
            setNetworkError((error as Error).message);
        }
    };
    const refreshPrivacy = async () => {
        const results = await Promise.allSettled([call<VpnStatus>('vpn:status').then(setVpn), call<TorStatus>('tor:status').then(setTor)]);
        const failure = results.find(r => r.status === 'rejected');
        if (failure?.status === 'rejected')
            throw failure.reason;
    };
    const refreshFw = async () => setFw(await call<FirewallStatus>('firewall:status'));
    const perform = async (key: string, fn: () => Promise<unknown>, message?: string) => {
        if (actionRef.current)
            return;
        actionRef.current = true;
        setBusy(key);
        try {
            await fn();
            if (message)
                notify(message);
            await refreshHistory().catch(() => { });
        }
        catch (error) {
            const text = (error as Error).message;
            if (text !== 'Operação cancelada.')
                notify(text, true);
        }
        finally {
            actionRef.current = false;
            setBusy('');
        }
    };
    useEffect(() => {
        let alive = true;
        async function init() {
            try {
                const data = await call<Bootstrap>('bootstrap');
                if (!alive)
                    return;
                if (data.recoveryMessage)
                    notify(t(data.recoveryMessage));
                setSystem(data.system);
                setSettings({ ...data.settings, language: data.settings.language || 'system' });
                setLanguage(data.settings.language || 'system');
                setLatest(data.latestAudit);
                setEvents(data.history);
                await Promise.allSettled([refreshAv(), refreshNetwork(), refreshFw(), refreshPrivacy(), refreshHistory()]);
            }
            catch (error) {
                if (alive)
                    setBootError((error as Error).message);
            }
            finally {
                if (alive)
                    setLoaded(true);
            }
        }
        init();
        const dispose = window.aegis?.onEvent(event => {
            if(event.type==='connections'){setConnections(event.data);setNetworkError('');}
        if (event.type === 'antivirus') {
                setAv(previous => previous ? { ...previous, job: event.data } : previous);
                if (!['preparing','running', 'cancelling'].includes(event.data?.state)) {
                    refreshAv();
                    refreshHistory().catch(() => { });
                }
            }
            if (event.type === 'tor')
                setTor(previous => ({ ...event.data, installed: previous?.installed ?? true }));
            if (event.type === 'audit') {
                setAuditRunning(event.data.state === 'running');
                if (event.data.result) {
                    setLatest(event.data.result);
                    refreshHistory().catch(() => { });
                }
            }
        });
        return () => {
            alive = false;
            dispose?.();
            if (toastTimer.current)
                clearTimeout(toastTimer.current);
        };
    }, []);
    useEffect(() => { document.documentElement.dataset.motion = settings.reducedMotion ? 'reduced' : 'full'; }, [settings.reducedMotion]);
    useEffect(() => {
        const key = (event: KeyboardEvent) => {
            if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
                event.preventDefault();
                setPalette(p => !p);
            }
            if (event.key === 'Escape') {
                setPalette(false);
                setSelectedCheck(null);
                setSelectedConnection(null);
            }
        };
        window.addEventListener('keydown', key);
        return () => window.removeEventListener('keydown', key);
    }, []);
    const changeLanguage = (choice: string) => perform('language', async () => { const result = await call<Settings>('settings', { language: choice }); setSettings(result); setLanguage(result.language || 'system'); });
    const languageSelect = () => <label className="language-picker"><GlobeLock size={15}/><span>{t('Idioma')}</span><select aria-label={t('Idioma')} value={language} onChange={e => changeLanguage(e.target.value)} disabled={Boolean(busy)}><option value="system">{t('Idioma do sistema')}</option>{languages.map(item => <option key={item.code} value={item.code}>{item.native}</option>)}</select></label>;
    const go = (id: Page) => { setPage(id); setQuery(''); setPalette(false); };
    const external = (id: string) => perform('external', () => call('external', { id }));
    const startAudit = () => perform('audit', async () => {
        setAuditRunning(true);
        try {
            setLatest(await call<Audit>('audit'));
        }
        finally {
            setAuditRunning(false);
        }
    }, t("Diagnóstico concluído. Revise os resultados."));
    const exportReport = () => perform('export', async () => {
        if (await call<string | null>('export'))
            notify(t("Relatório salvo no local escolhido."));
    });
    const runScan = (type: string) => perform('scan', async () => {
        const result = await call<AvJob | null>('av:scan', { type, selection: 'folder' });
        if (result) {
            setAv(previous => previous ? { ...previous, job: result } : previous);
            setLogs(false);
        }
    });
    const updateSignatures = () => perform('update', async () => { const result = await call<AvJob>('av:update'); setAv(previous => previous ? { ...previous, job: result } : previous); setLogs(true); });
    const firewallAction = (method: string, payload?: unknown) => perform('firewall', async () => { setFw(await call<FirewallStatus>(method, payload)); }, t("Estado do firewall atualizado."));
    const running = av?.job && ['preparing', 'running', 'cancelling'].includes(av.job.state), ready = av?.installed && av.runnable !== false && av.signatures.ready;
    const activeConnections = connections.filter(c => c.state === 'Established'), listeners = connections.filter(c => c.state === 'Listen'), processCount = new Set(connections.map(c => c.process).filter(Boolean)).size;
    const firewallEnabled = fw?.native.profiles ? fw.native.profiles.length > 0 && fw.native.profiles.every(p => p.Enabled === true || p.Enabled === 1) : fw?.native.enabled;
    const pageTitle = titles[page], updateSetting = (key: keyof Settings) => perform('settings', async () => { setSettings(await call<Settings>('settings', { [key]: !settings[key] })); });
    const filterConnections = connections.filter(c => (netFilter === 'all' || netFilter === 'active' && c.state === 'Established' || netFilter === 'listen' && c.state === 'Listen') && ((c.process || t("Não verificado")) + ' ' + c.remoteAddress + ' ' + c.localAddress + ' ' + c.localPort + ' ' + c.pid).toLowerCase().includes(query.toLowerCase()));
    function CheckList({ compact = false }: {
        compact?: boolean;
    }) { return <div className={'check-list ' + (compact ? 'compact' : '')}>{(compact ? latest?.checks.slice().sort((a, b) => ['warning', 'review', 'unknown', 'pass'].indexOf(a.status) - ['warning', 'review', 'unknown', 'pass'].indexOf(b.status)).slice(0, 4) : latest?.checks)?.map(check => <button className="check-row" key={check.id} onClick={() => setSelectedCheck(check)}><CheckIcon status={check.status}/><span><strong>{t(check.title)}</strong><small>{recommendation(check)}</small></span><span className={'status-text ' + check.status}>{statusLabel[check.status]}</span><ChevronRight size={15}/></button>)}</div>; }
    const analyseNetwork = () => perform('network-analysis', async () => { setConnections(await call<Connection[]>('connections:analyse')); setNetworkError(''); });
    const riskLabel = (c: Connection) => t(c.analysis?.level === 'review' ? 'Revisar sinais' : c.analysis?.level === 'no-signals' ? 'Sem sinais locais' : 'Não analisado');
    function NetworkTable() { return <div className="table-scroll"><table className="network-table"><thead><tr><th>{t("Aplicativo")}</th><th>{t("Destino / escuta")}</th><th>{t("Protocolo")}</th><th>{t("Estado")}</th><th>PID</th><th>{t("Análise local")}</th></tr></thead><tbody>{filterConnections.map(c => <tr key={c.id}><td><span className="process-icon"><Monitor size={13}/></span><span className="process-name">{c.process || t("Não verificado")}</span></td><td className="mono">{c.state === 'Listen' ? c.localAddress + ':' + c.localPort : c.remoteAddress + ':' + c.remotePort}</td><td className="mono muted">{c.protocol}</td><td><span className={'network-state ' + (c.state === 'Listen' ? 'listening' : '')}><i />{c.state === 'Listen' ? t("Em escuta") : t("Estabelecida")}</span></td><td className="mono muted">{c.pid || '—'}</td><td><button className={'text-button ' + (c.analysis?.level === 'review' ? 'amber' : 'muted')} onClick={() => setSelectedConnection(c)}>{riskLabel(c)}<ChevronRight size={12}/></button></td></tr>)}</tbody></table>{!filterConnections.length && <div className="table-empty">{networkError ? <Problem value={networkError}/> : (!loaded ? t("Consultando o sistema…") : query ? t("Nenhuma conexão corresponde à busca.") : t("Nenhuma conexão retornada nesta consulta."))}</div>}</div>; }
    function EventRows({ compact = false }: {
        compact?: boolean;
    }) { const items = compact ? events.slice(0, 3) : events; return <div className="event-list">{items.map(event => <div className="event-row" key={event.id}><div className={'event-symbol ' + event.status}>{event.type === 'antivirus' ? <Bug size={16}/> : event.type === 'firewall' ? <ShieldCheck size={16}/> : event.type === 'vpn' || event.type === 'tor' ? <GlobeLock size={16}/> : <ScanLine size={16}/>}</div><div><strong>{eventTitle(event)}</strong>{!compact && <><p>{eventSummary(event)}</p><Original value={{ title: event.title, detail: event.detail }}/></>}<small>{date(event.at)}</small></div><span className={'event-dot ' + event.status}/></div>)}{!items.length && <p className="quiet-empty">{t("Suas verificações e alterações aparecerão aqui.")}</p>}</div>; }
    const overview = <>{loaded&&!settings.onboardingDone&&<Onboarding av={av} audit={!!latest} prepare={updateSignatures} diagnose={startAudit} finish={()=>perform('setup',async()=>setSettings(await call<Settings>('settings',{onboardingDone:true})))}/>} 
    <div className="overview-metrics" aria-label={t("Resumo")}>
    <button className="overview-metric" onClick={() => go('audit')}><span>{t("Atendidos")}</span><strong>{latest?.counts.pass ?? '—'}</strong><small>{t("Último diagnóstico")}</small></button>
    <button className="overview-metric review" onClick={() => go('audit')}><span>{t("Para revisar")}</span><strong>{latest ? latest.counts.warning + latest.counts.review : '—'}</strong><small>{t("Verificações")}</small></button>
    <button className="overview-metric" onClick={() => go('audit')}><span>{t("Não verificados")}</span><strong>{latest?.counts.unknown ?? '—'}</strong><small>{t("Diagnóstico")}</small></button>
    <button className="overview-metric" onClick={() => go('network')}><span>{t("Conexões")}</span><strong>{networkError ? '—' : connections.length}</strong><small>{networkError ? t("Estado não verificado") : t("Observados nesta consulta")}</small></button>
    </div>
    <div className="overview-grid">
    <section className="panel hero-panel" data-parallax="hero">
    <div className="panel-top"><span className="overline"><span className="live-dot"/>{t("Conexões")}</span><div className="segmented"><button className={view === 'map' ? 'selected' : ''} onClick={() => setView('map')}>{t("Mapa 3D")}</button><button className={view === 'summary' ? 'selected' : ''} onClick={() => setView('summary')}>{t("Resumo")}</button></div></div>
    <div className="hero-stage">{view === 'map' ? <Scene connections={networkError ? [] : connections} reducedMotion={settings.reducedMotion} onSelect={process => { go('network'); setQuery(process); }}/> : <div className="summary-visual"><div><strong>{networkError ? '—' : processCount}</strong><span>{t("Aplicativo")}</span></div><div><strong>{networkError ? '—' : connections.filter(c => c.state === 'Established').length}</strong><span>{t("Estabelecida")}</span></div><div><strong>{networkError ? '—' : connections.filter(c => c.state === 'Listen').length}</strong><span>{t("Em escuta")}</span></div></div>}</div>
    <div className="hero-footer"><span><i className="tiny-square"/>{networkError ? t("Estado não verificado") : t('{count} sockets observados', { count: connections.length })}</span><span>{t('Linhas representam conexões observadas')}<Info size={12}/></span></div>
    </section>
    <section className="panel diagnosis-panel">
    <div className="panel-top"><span className="overline">{t("DIAGNÓSTICO")}</span><ScanLine size={16} className="muted"/></div>
    <div className="hero-caption"><h2>{auditRunning ? t("Verificando sistema…") : latest ? t("Verificação concluída") : t("Não verificado")}</h2><p>{latest ? confirmationSummary(latest.counts.unknown) : t("Execute a verificação para consultar as configurações.")}</p><div className="diagnosis-actions"><button className="text-button" onClick={() => latest ? go('audit') : startAudit()} disabled={Boolean(busy) || auditRunning}>{latest ? t("Ver diagnóstico") : t("Iniciar diagnóstico")}<ArrowUpRight size={14}/></button></div></div>
    <div className="overview-device"><div className="device-icon"><Monitor size={19} strokeWidth={1.5}/></div><div><strong>{system?.hostname || t("Meu dispositivo")}</strong><span>{system ? system.os + ' · ' + system.architecture : t("Conectando ao aplicativo")}</span><small>{t("Último diagnóstico")} · {latest ? date(latest.at) : t("Pendente")}</small></div></div>
    <div className="device-note"><LockKeyhole size={12}/><span>{t("Seus relatórios ficam neste dispositivo.")}</span></div>
    </section>
    </div>
    <div className="module-grid">
    <button className="module-card" onClick={() => go('antivirus')}><div className="module-icon"><Bug size={17}/></div><ArrowUpRight className="module-arrow" size={16}/><span className="module-name">{t("Antivírus")}</span><strong>{running ? t("Varredura em atividade") : ready ? t("Pronto para verificar") : t("Assinaturas pendentes")}</strong><div><span>ClamAV</span><Badge tone={ready ? 'green' : 'neutral'}>{ready ? t("Base disponível") : t("Configurar")}</Badge></div></button>
    <button className="module-card" onClick={() => go('firewall')}><div className="module-icon"><ShieldCheck size={17}/></div><ArrowUpRight className="module-arrow" size={16}/><span className="module-name">{t("Firewall")}</span><strong>{firewallEnabled === true ? t("Perfis ativados") : firewallEnabled === false ? t("Revise a configuração") : t("Estado não verificado")}</strong><div><span>{t("Proteção de entrada")}</span><Badge tone={firewallEnabled === true ? 'green' : 'neutral'}>{firewallEnabled === true ? t("Ativado") : t("Revisar")}</Badge></div></button>
    <button className="module-card" onClick={() => go('privacy')}><div className="module-icon"><GlobeLock size={17}/></div><ArrowUpRight className="module-arrow" size={16}/><span className="module-name">{t("Privacidade")}</span><strong>{tor?.state === 'ready' ? t("Proxy Tor disponível") : vpn?.active?.interfaceActive ? t("Interface VPN ativa") : vpn?.active ? t("Ativação não confirmada") : t("Nenhuma conexão do Aegis")}</strong><div><span>WireGuard + Tor</span><Badge tone={vpn?.active && !vpn.active.interfaceActive ? 'amber' : 'neutral'}>{tor?.state === 'ready' || vpn?.active?.interfaceActive ? t("Em uso") : vpn?.active ? t("Revisar") : t("Opcional")}</Badge></div></button>
    </div>
    <div className="bottom-grid"><section className="panel"><div className="panel-top"><h3>{t("Verificações")}</h3><button className="text-button muted" onClick={() => go('audit')}>{t("Ver diagnóstico")}<ArrowUpRight size={14}/></button></div>{latest ? <CheckList compact/> : <Empty title={t("Sem diagnóstico")} icon={ScanLine}>{t("Inicie um diagnóstico. Cada resultado vem acompanhado de evidências e uma recomendação.")}</Empty>}</section><section className="panel"><div className="panel-top"><h3>{t("Atividade recente")}</h3><button className="icon-button" aria-label={t("Ver toda a atividade")} onClick={() => go('history')}><ArrowUpRight size={16}/></button></div><EventRows compact/></section></div>
    </>;
    const auditPage = <><p className="evidence-language-note">{t('Registros e evidências do sistema são preservados no idioma original.')}</p><section className="panel audit-banner"><div className="feature-icon"><ScanLine size={30} strokeWidth={1.3}/></div><div><h2>{t("Verificação de configurações")}</h2><p>{t("Sem alterar suas configurações. Confira o que foi observado e o que ainda não pôde ser verificado.")}</p></div><Button kind="primary" disabled={Boolean(busy) || auditRunning} icon={auditRunning ? Loader2 : ScanLine} onClick={startAudit}>{auditRunning ? t("Verificando…") : latest ? t("Executar novamente") : t("Verificar sistema")}</Button></section>{latest ? <><div className="stat-grid">{[{ label: t("Atendidos"), value: latest.counts.pass, tone: 'green' }, { label: t("Atenção"), value: latest.counts.warning, tone: 'amber' }, { label: t("Para revisar"), value: latest.counts.review, tone: 'blue' }, { label: t("Não verificados"), value: latest.counts.unknown, tone: 'neutral' }].map(stat => <div className="stat-card" key={stat.label}><span>{stat.label}</span><strong className={stat.tone}>{stat.value.toString().padStart(2, '0')}</strong></div>)}</div><section className="panel"><div className="panel-top"><h3>{t("Resultados da verificação")}</h3><span className="muted text-small">{date(latest.at)}</span></div><CheckList /></section><div className="inline-note"><Info size={15}/><p>{t("Itens não verificados não contam como seguros. Um serviço em escuta ou uma conta administrativa exige contexto para ser avaliado.")}</p></div></> : <section className="panel"><Empty title={t("Nenhuma verificação realizada")} icon={ScanLine}>{t("O diagnóstico verifica configurações locais de firewall, antivírus e serviços. As opções disponíveis variam conforme o sistema e as permissões.")}</Empty></section>}</>;
    const antivirusPage = <><div className="av-grid"><section className="panel av-engine"><div className="panel-top"><span className="overline">{t("MECANISMO INDEPENDENTE")}</span><Badge tone={ready ? 'green' : av?.installed ? 'amber' : 'neutral'}>{!av ? t("Consultando") : ready ? t("Base disponível") : av.installed ? t("Preparar assinaturas") : t("Não disponível")}</Badge></div><div className="av-visual"><div className="scan-orbit"><Shield size={63} strokeWidth={1.15}/>{running && <div className="scanning-beam"/>}</div></div><h2>ClamAV<span className="sup">{t("OPEN SOURCE")}</span></h2><p>{t("O mecanismo de varredura é parte do Aegis. Funciona sem depender de outro antivírus.")}</p><div className="engine-version"><Terminal size={13}/>{av?.version || t("Consultando mecanismo…")}</div><div className="engine-details"><div><span>{t("Base local")}</span><strong>{av?.signatures.ready ? t("Disponível") : t("Preparação necessária")}</strong></div><div><span>{t("Última gravação")}</span><strong>{date(av?.signatures.updatedAt)}</strong></div><div><span>{t("Proteção em tempo real")}</span><strong>{t("Não incluída nesta versão")}</strong></div></div><Button icon={running ? Loader2 : Download} disabled={Boolean(busy) || Boolean(running) || !av?.updaterAvailable} onClick={updateSignatures}>{av?.job?.type === 'update' && running ? t("Atualizando assinaturas") : ready ? t("Atualizar assinaturas") : t("Preparar assinaturas")}</Button><small className="subtle">{t("O primeiro download pode ser grande. A atualização usa os servidores oficiais do ClamAV.")}</small></section>
    <section className="panel scan-options"><div className="panel-top"><h3>{t("Escolha sua varredura")}</h3><ScanLine size={18} className="muted"/></div>{[{ type: 'quick', icon: Activity, title: t("Rápida"), description: t("Verifica as pastas Downloads e Desktop do usuário.") }, { type: 'full', icon: HardDrive, title: t("Completa"), description: t("Percorre o volume do sistema. Pode levar bastante tempo.") }, { type: 'custom', icon: FolderSearch, title: t("Personalizada"), description: t("Escolha um arquivo ou uma pasta para analisar.") }].map(({ type, icon: Icon, title, description }) => <button key={type} className="scan-option" onClick={() => runScan(type)} disabled={!ready || Boolean(running) || Boolean(busy)}><span className="option-icon"><Icon size={23} strokeWidth={1.4}/></span><span><strong>{title}</strong><small>{description}</small></span><ArrowRight size={17}/></button>)}{!ready && <div className="inline-note amber"><Info size={15}/><p>{t("Prepare a base de assinaturas para liberar as varreduras.")}</p></div>}<div className="scan-footnote"><LockKeyhole size={15}/><p>{t("Os arquivos são analisados localmente. Nenhum arquivo é enviado para serviços de análise. O Aegis não apaga detecções automaticamente.")}</p></div></section></div>
    <div className="button-group"><Button icon={FolderSearch} disabled={Boolean(busy) || Boolean(running) || !ready} onClick={() => runScan('custom')}>{t('Pasta')}</Button><Button icon={Search} disabled={Boolean(busy) || Boolean(running) || !ready} onClick={() => perform('scan-file', async () => {
            const job = await call<AvJob | null>('av:scan', { type: 'custom', selection: 'file' });
            if (job)
                setAv(previous => previous ? { ...previous, job } : previous);
        })}>{t('Arquivo')}</Button></div>{avError && <div className="error-banner"><Problem value={avError}/></div>}
    {av?.job && <ScanProgress job={av.job} running={!!running} disabled={!!busy} cancel={()=>perform('cancel',()=>call('av:cancel'))} quarantine={index=>perform('quarantine',async()=>{await call('quarantine:add',{scan:av.job!.id,index});setQuarantineRevision(v=>v+1);})}/>}
    <section className="panel"><div className="panel-top"><h3>{t("Varreduras anteriores")}</h3><Button kind="ghost" icon={RefreshCw} disabled={Boolean(busy)} onClick={() => perform('av-refresh', refreshAv)}>{t("Atualizar")}</Button></div>{av?.scans.filter(s => s.type !== 'update').length ? <div className="scan-history">{av.scans.filter(s => s.type !== 'update').map(scan => <div key={scan.id}><span className="event-symbol"><FolderSearch size={17}/></span><div><strong>{scan.type === 'quick' ? t("Rápida") : scan.type === 'full' ? t("Completa") : t("Personalizada")}</strong><small>{date(scan.startedAt)}</small></div><span>{scan.summary?.scanned ?? '—'} {t("arquivos")}</span><Badge tone={scan.state === 'completed' ? 'green' : scan.state === 'threats' ? 'danger' : 'amber'}>{jobLabel(scan.state)}</Badge></div>)}</div> : <p className="quiet-empty">{t("Nenhuma varredura realizada pelo Aegis ainda.")}</p>}</section>
    <div className="inline-note"><Info size={15}/><p>{t("Varreduras usam limites de tamanho e as permissões da sessão. O conteúdo interno de RAR não é analisado. Arquivos inacessíveis, criptografados ou acima dos limites podem não ser analisados integralmente. Consulte os registros antes de concluir a análise.")}</p></div><Quarantine revision={quarantineRevision} run={fn=>perform('quarantine',fn)}/></>;
    const networkPage = <><section className="panel connection-analysis-panel"><div><h3>{t("Análise local das conexões")}</h3><p>{t("Revise processos e serviços em escuta. IPs e portas não comprovam atividade maliciosa.")}</p></div><Button icon={ScanLine} disabled={Boolean(busy)} onClick={analyseNetwork}>{t("Analisar conexões")}</Button></section><section className="panel network-hero"><div><span className="overline">{t("FOTOGRAFIA LOCAL")}</span><h2>{activeConnections.length}<span>{t("conexões estabelecidas")}</span></h2><p>{listeners.length} {t("sockets em escuta ·")} {processCount} {t("aplicativos identificados")}</p><Badge tone={networkError ? 'amber' : 'neutral'}>{networkError ? t("Consulta indisponível") : settings.liveNetwork ? t("Atualização a cada 12 s") : t("Atualização manual")}</Badge></div><div className="mini-orb"><Scene connections={connections} reducedMotion={settings.reducedMotion} onSelect={setQuery}/></div></section><section className="panel"><div className="network-toolbar"><div className="search-field"><Search size={16}/><input aria-label={t("Buscar conexões")} placeholder={t("Buscar aplicativo, IP, porta ou PID…")} value={query} onChange={e => setQuery(e.target.value)}/>{query && <button className="icon-button" aria-label={t("Limpar busca")} onClick={() => setQuery('')}><X size={13}/></button>}</div><div className="segmented">{[{ id: 'all', label: t("Todas") }, { id: 'active', label: t("Ativas") }, { id: 'listen', label: t("Em escuta") }].map(f => <button key={f.id} className={netFilter === f.id ? 'selected' : ''} onClick={() => setNetFilter(f.id)}>{f.label}</button>)}</div><Button icon={RefreshCw} disabled={Boolean(busy)} onClick={() => perform('network', refreshNetwork)}>{t("Atualizar")}</Button></div><NetworkTable /></section><div className="inline-note"><Info size={15}/><p>{t("A visualização mostra sockets TCP, não uma captura de pacotes. Uma conexão estabelecida não indica tráfego malicioso. Portas em escuta também podem estar protegidas pelo firewall.")}</p></div><NetworkActivity/></>;
    const firewallPage = <><div className="firewall-grid"><section className="panel firewall-state"><div className="panel-top"><span className="overline">{t("FIREWALL DO SISTEMA")}</span><Badge tone={firewallEnabled === true ? 'green' : 'neutral'}>{firewallEnabled === true ? t("Ativado") : firewallEnabled === false ? t("Revisar") : t("Consultar")}</Badge></div><div className="firewall-visual"><ShieldCheck size={80} strokeWidth={1}/><div /><div /></div><h2>{fw?.native.backend || t("Proteção de entrada")}</h2><p>{t("Uma camada de controle usando os recursos de rede do sistema operacional.")}</p><div className="profile-list">{fw?.native.profiles?.map(profile => <div key={profile.Name}><span>{({ Domain: t("Domínio"), Private: t("Rede privada"), Public: t("Rede pública") }[profile.Name] || profile.Name)}</span><Badge tone={profile.Enabled === true || profile.Enabled === 1 ? 'green' : 'amber'}>{profile.Enabled === true || profile.Enabled === 1 ? t("Ativado") : t("Desativado")}</Badge></div>)}{fw?.native.evidence && <Original value={fw.native.evidence}/>}{fw?.native.error && <p className="muted"><Problem value={fw.native.error}/></p>}</div><Button kind="primary" icon={ShieldCheck} disabled={Boolean(busy) || fw?.canRestore || !fw?.native.supported} onClick={() => firewallAction('firewall:harden')}>{t("Revisar e reforçar")}</Button>{fw?.canRestore && <Button icon={History} disabled={Boolean(busy)} onClick={() => firewallAction('firewall:restore')}>{t("Restaurar configuração anterior")}</Button>}</section><div className="stack"><section className="panel"><div className="panel-top"><h3>{t("Bloquear porta TCP")}</h3><LockKeyhole className="muted" size={17}/></div><p className="section-description">{t("Bloqueie uma porta TCP de entrada. A regra pode ser removida a qualquer momento pelo Aegis.")}</p><form className="port-form" onSubmit={e => {
            e.preventDefault();
            if (port)
                firewallAction('firewall:block', { port });
        }}><label htmlFor="port">{t("Porta TCP")}</label><div><input id="port" inputMode="numeric" type="number" min="1" max="65535" placeholder={t("Ex.: 3389")} value={port} onChange={e => setPort(e.target.value)}/><Button icon={Plus} disabled={Boolean(busy) || !port || system?.platform === 'darwin'} onClick={() => firewallAction('firewall:block', { port })}>{t("Criar bloqueio")}</Button></div></form><div className="rules-list">{fw?.rules.map(rule => <div key={rule.id}><span className="rule-icon"><LockKeyhole size={15}/></span><div><strong>TCP · {rule.port}</strong><small>{rule.pending ? t("Aplicação não confirmada · é possível remover") : t("Regra de entrada do Aegis")}</small></div><button className="icon-button" aria-label={t('Remover bloqueio da porta {port}', { port: rule.port })} disabled={Boolean(busy)} onClick={() => firewallAction('firewall:remove', { id: rule.id })}><Trash2 size={16}/></button></div>)}{!fw?.rules.length && <p className="quiet-empty">{t("Suas regras aparecerão aqui.")}</p>}</div></section></div></div><div className="inline-note"><Info size={15}/><p>{t("O reforço preserva as regras existentes. Alterações pedem autorização do sistema e podem afetar serviços ou acesso remoto. A restauração usa os valores salvos antes do reforço.")}</p></div></>;
    const privacyPage = <><div className="privacy-tabs"><button className={privacyTab === 'vpn' ? 'active' : ''} onClick={() => setPrivacyTab('vpn')}><Link2 size={16}/>{t("WireGuard VPN")}</button><button className={privacyTab === 'tor' ? 'active' : ''} onClick={() => setPrivacyTab('tor')}><GlobeLock size={16}/>{t("Rede Tor")}</button><span>{t("Conexão opcional")}</span></div>{privacyTab === 'vpn' ? <div className="privacy-grid"><section className="panel privacy-feature"><div className="panel-top"><span className="overline">{t("TÚNEL CRIPTOGRAFADO")}</span><Badge tone={vpn?.active?.interfaceActive ? 'green' : 'neutral'}>{vpn?.active?.interfaceActive ? t("Interface ativa") : vpn?.active ? t("Ativação não confirmada") : t("Desconectado")}</Badge></div><div className="tunnel-visual"><div className="endpoint"><Monitor size={25}/></div><div className="tunnel-path"><span /><span /><span /><LockKeyhole size={18}/></div><div className="endpoint"><GlobeLock size={25}/></div></div><h2>WireGuard</h2><p>{t("Importe um perfil WireGuard de um servidor próprio ou de sua escolha. Sem assinatura do Aegis e sem um provedor obrigatório.")}</p><div className="detail-pairs"><div><span>{t("Cliente WireGuard")}</span><strong>{!vpn ? t("Não verificado") : vpn.installed ? t("Disponível") : t("Instalação necessária")}</strong></div><div><span>{t("Cofre do sistema")}</span><strong>{vpn?.secureStorage ? t("Disponível") : t("Indisponível")}</strong></div><div><span>{t("Servidor VPN incluído")}</span><strong>{t("Não")}</strong></div></div>{vpn?.active && !vpn.profiles.some(p => p.id === vpn.active?.id) && <div className="inline-note amber"><Info size={15}/><span>{t('Ativação não confirmada')} · {vpn.active.name}</span><Button disabled={Boolean(busy)} onClick={() => perform('vpn-recovery', async () => { await call('vpn:disconnect'); await refreshPrivacy(); })}>{t('Desconectar')}</Button></div>}{!vpn?.installed && <Button icon={ExternalLink} onClick={() => external('wireguard')}>{t("Obter WireGuard gratuito")}</Button>}<div className="inline-note"><Info size={15}/><p>{t("O cliente é gratuito. Você precisa de um perfil e um servidor. O Aegis não oferece servidor VPN nem promete infraestrutura gratuita de terceiros.")}</p></div></section><section className="panel vpn-profiles"><div className="panel-top"><h3>{t("Seus perfis")}</h3><Button icon={Plus} disabled={Boolean(busy) || !vpn?.secureStorage} onClick={() => perform('vpn-import', async () => {
                const result = await call('vpn:import');
                if (result) {
                    await refreshPrivacy();
                    notify(t("Perfil importado para o cofre local."));
                }
            })}>{t("Importar .conf")}</Button></div>{vpn?.profiles.length ? vpn.profiles.map(profile => <div className="vpn-profile" key={profile.id}><div className="vpn-profile-title"><span className="option-icon"><GlobeLock size={21}/></span><div><h3>{profile.name}</h3><span className="mono">{profile.meta.endpoint || t("Endpoint definido pelo perfil")}</span></div><button className="icon-button" aria-label={t('Remover perfil {name}', { name: profile.name })} disabled={Boolean(busy) || vpn.active?.id === profile.id} onClick={() => perform('vpn-remove', async () => { await call('vpn:remove', { id: profile.id }); await refreshPrivacy(); })}><Trash2 size={15}/></button></div><div className="vpn-tags"><span>{profile.meta.fullTunnel ? t("Rota padrão IPv4") : t("Rotas específicas")}</span><span>{profile.meta.ipv6 ? t("Inclui rota IPv6") : t("IPv6 não coberto por rota padrão")}</span><span>{t(profile.meta.dns.length ? 'DNS no perfil' : 'DNS do sistema')}</span></div><Button kind={vpn.active?.id === profile.id ? 'secondary' : 'primary'} icon={vpn.active?.id === profile.id ? Square : Play} disabled={Boolean(busy) || !vpn.installed || Boolean(vpn.active && vpn.active.id !== profile.id)} onClick={() => perform('vpn-connect', async () => { await call(vpn.active?.id === profile.id ? 'vpn:disconnect' : 'vpn:connect', { id: profile.id }); await refreshPrivacy(); })}>{vpn.active?.id === profile.id ? (vpn.active.present === false ? t("Limpar estado pendente") : t("Desconectar")) : t("Conectar perfil")}</Button></div>) : <Empty title={t("Nenhum perfil importado")} icon={GlobeLock}>{t("Importe uma configuração .conf. Chaves privadas são guardadas com o cofre seguro do sistema.")}</Empty>}{vpn?.active?.error && <div className="inline-note amber"><TriangleAlert size={15}/><p><Problem value={vpn.active.error}/></p></div>}<div className="privacy-caveat"><Eye size={16}/><p>{t(vpn?.verification || "A conexão só poderá ser avaliada após configurar um perfil.")} {t("O Aegis não anuncia proteção contra vazamentos nem kill switch nesta versão.")}</p></div><Button kind="ghost" icon={RefreshCw} disabled={Boolean(busy)} onClick={() => perform('vpn-refresh', refreshPrivacy)}>{t("Atualizar estado")}</Button></section></div> : <div className="privacy-grid"><section className="panel privacy-feature tor-feature"><div className="panel-top"><span className="overline">{t("ROTEAMENTO ONION")}</span><Badge tone={tor?.state === 'ready' ? 'green' : tor?.state === 'starting' ? 'amber' : 'neutral'}>{tor?.state === 'ready' ? t("Proxy pronto") : tor?.state === 'starting' ? t("Conectando") : t("Desconectado")}</Badge></div><div className="onion-visual"><div /><div /><div /><GlobeLock size={38} strokeWidth={1.3}/></div><h2>{t("Rede Tor")}</h2><p>{t("Inicie o Tor integrado para oferecer um proxy SOCKS local. Não exige conta nem assinatura.")}</p>{tor?.state === 'starting' && <><div className="progress-track"><span style={{ width: tor.progress + '%' }}/></div><p className="text-small">{t("Inicialização informada pelo Tor:")} {tor.progress}%</p></>}<Button kind="primary" icon={tor?.state === 'ready' || tor?.state === 'starting' ? Square : Play} disabled={Boolean(busy) || !tor?.installed} onClick={() => perform('tor', async () => { setTor(await call<TorStatus>(tor?.state === 'ready' || tor?.state === 'starting' ? 'tor:stop' : 'tor:start')); })}>{tor?.state === 'ready' || tor?.state === 'starting' ? t("Desconectar Tor") : t("Conectar à rede Tor")}</Button>{tor?.port && tor.state === 'ready' && <div className="proxy-address"><span>{t("PROXY SOCKS5 LOCAL")}</span><code>127.0.0.1:{tor.port}</code></div>}{tor?.error && <div className="inline-note amber"><TriangleAlert size={15}/><p><Problem value={tor.error}/></p></div>}</section><div className="stack"><section className="panel tor-explanation"><span className="option-icon"><Info size={24}/></span><h3>{t("Configuração dos aplicativos")}</h3><p>{t("Ativar o proxy não encaminha automaticamente todos os aplicativos pelo Tor. Cada aplicativo precisa ser configurado para usar o SOCKS5 e resolver os nomes pela rede Tor.")}</p><p>{t("Para navegar, use o Tor Browser oficial, que inclui proteções próprias de navegação. O proxy integrado não reproduz essas proteções.")}</p><Button icon={ExternalLink} onClick={() => external('tor')}>{t("Obter Tor Browser")}</Button></section><section className="panel"><div className="panel-top"><h3>{t("Estado do mecanismo")}</h3><Terminal size={17} className="muted"/></div><pre className="terminal-log tor-log">{tor?.lines?.join('\n') || t("Os registros de inicialização do Tor aparecerão aqui.")}</pre></section></div></div>}<VpnDiagnostics run={fn=>perform('vpn-diagnostics',fn)}/></>;
    const historyPage = <><div className="stat-grid three"><div className="stat-card"><span>{t("Diagnósticos salvos")}</span><strong>{audits.length.toString().padStart(2, '0')}</strong></div><div className="stat-card"><span>{t("Ações registradas")}</span><strong>{events.length.toString().padStart(2, '0')}</strong></div><div className="stat-card"><span>{t("Armazenamento")}</span><strong className="stat-word">{t("Local")}</strong></div></div>{audits.length > 1 && <section className="panel comparison"><div><GitBranch size={22}/><h3>{t("O que mudou no último diagnóstico")}</h3></div>{audits[0].checks.filter(c => audits[1].checks.find(p => p.id === c.id)?.status !== c.status).map(c => <p key={c.id}><CheckIcon status={c.status}/>{t(c.title)}<span>{statusLabel[c.status]}</span></p>)}{!audits[0].checks.some(c => audits[1].checks.find(p => p.id === c.id)?.status !== c.status) && <p>{t("Os estados das verificações permaneceram iguais.")}</p>}</section>}<section className="panel"><div className="panel-top"><h3>{t("Linha do tempo")}</h3><div className="button-group"><Badge>{t("ATÉ 500 EVENTOS")}</Badge><Button kind="ghost" icon={RefreshCw} disabled={Boolean(busy)} onClick={() => perform('history', refreshHistory)}>{t("Atualizar")}</Button></div></div><EventRows /></section></>;
    const settingsPage = <><section className="panel language-panel"><div className="panel-top"><h3>{t('Idioma e região')}</h3><GlobeLock size={18}/></div><div className="setting-row"><div><strong>{t('Idioma da interface')}</strong><p>{t('A alteração é imediata e fica salva neste dispositivo.')}</p></div>{languageSelect()}</div><p className="section-description">{t('Registros e evidências do sistema são preservados no idioma original.')}</p></section><section className="panel settings-panel"><div className="panel-top"><h3>{t("Experiência")}</h3><SlidersHorizontal size={18} className="muted"/></div><div className="setting-row"><div><strong>{t("Reduzir movimento")}</strong><p>{t("Interrompe a rotação contínua e reduz transições e animações.")}</p></div><Toggle checked={settings.reducedMotion} onChange={() => updateSetting('reducedMotion')} label={t("Reduzir movimento")}/></div><div className="setting-row"><div><strong>{t("Atualizar conexões automaticamente")}</strong><p>{t("Consulta os sockets TCP a cada 12 segundos enquanto o aplicativo está visível.")}</p></div><Toggle checked={settings.liveNetwork} onChange={() => updateSetting('liveNetwork')} label={t("Atualizar conexões automaticamente")}/></div></section><section className="panel"><div className="panel-top"><h3>{t("Sobre esta versão")}</h3><Badge>{version}</Badge></div><p className="section-description">{t("Antivírus sob demanda e diagnóstico de configurações. A cobertura depende das permissões e dos recursos de cada sistema. Não há garantia de detecção de todas as ameaças.")}</p></section><Automation settings={settings} save={async data=>setSettings(await call<Settings>('settings',data))} run={fn=>perform('automation',fn)}/><Updates run={fn=>perform('app-update',fn)}/></>;
    return <div className="app-shell" ref={shellRef}><aside className="sidebar"><Logo /><div className="sidebar-label">{t("MÓDULOS")}</div><nav aria-label={t("Navegação principal")}>{navigation.map(item => <button key={item.id} className={'nav-item ' + (page === item.id ? 'active' : '')} aria-current={page === item.id ? 'page' : undefined} onClick={() => go(item.id)}><item.icon size={18} strokeWidth={1.6}/><span>{item.label}</span>{item.id === 'antivirus' && running ? <span className="nav-task"/> : page === item.id ? <span className="nav-active-dot"/> : null}</button>)}</nav><div className="sidebar-bottom"><button className={'nav-item ' + (page === 'settings' ? 'active' : '')} onClick={() => go('settings')}><Settings2 size={18} strokeWidth={1.6}/><span>{t("Preferências")}</span></button></div></aside>
    <div className="workspace"><header className="topbar"><div className="breadcrumb"><Monitor size={14}/><span>{t("Meu dispositivo")}</span><ChevronRight size={12}/><strong>{navigation.find(n => n.id === page)?.label || t("Preferências")}</strong></div><div className="top-actions"><span className="local-indicator"><i />{window.aegis ? t("Aplicativo local") : t("Prévia da interface")}</span><button className="command-trigger" onClick={() => { setPaletteQuery(''); setPalette(true); }} aria-label={t("Abrir navegação rápida")}><Search size={15}/><span>{t("Ir para…")}</span><kbd>Ctrl K</kbd></button><button className="icon-button" aria-label={t("Abrir histórico de atividade")} onClick={() => go('history')}><Activity size={18}/></button></div></header>
    <main><div className="page-heading"><div><span className="eyebrow">{pageTitle.eyebrow}</span><h1>{pageTitle.title}</h1><p>{pageTitle.description}</p></div><div className="heading-actions"><Button icon={ArrowDownToLine} onClick={exportReport} disabled={Boolean(busy)}>{t("Exportar relatório")}</Button>{page === 'overview' && <Button kind="primary" icon={auditRunning ? Loader2 : ScanLine} disabled={Boolean(busy) || auditRunning} onClick={startAudit}>{auditRunning ? t("Verificando…") : t("Verificar sistema")}</Button>}</div></div>
    {bootError && <div className="error-banner" role="alert"><Info size={17}/><Problem value={bootError}/></div>}
    <div className="page-content" key={page}>{page === 'overview' ? overview : page === 'audit' ? auditPage : page === 'antivirus' ? antivirusPage : page === 'network' ? networkPage : page === 'firewall' ? firewallPage : page === 'privacy' ? privacyPage : page === 'history' ? historyPage : settingsPage}</div>
    </main></div>
    {(running || auditRunning) && <button className="background-task" onClick={() => go(auditRunning ? 'audit' : 'antivirus')}><span className="task-spinner"/><span>{auditRunning ? t("Verificando configurações") : av?.job?.type === 'update' ? t("Atualizando assinaturas") : t("Varredura em andamento")}<small>{t("Você pode continuar navegando")}</small></span><ArrowUpRight size={16}/></button>}
    {toast && <div className={'toast ' + (toast.error ? 'error' : '')} role={toast.error ? 'alert' : 'status'}>{toast.error ? <TriangleAlert size={19}/> : <CheckCircle2 size={19}/>}<span>{toast.error ? <Problem value={toast.text}/> : toast.text}</span><button className="icon-button" aria-label={t("Fechar aviso")} onClick={() => setToast(null)}><X size={16}/></button></div>}
    {selectedConnection && <div className="modal-backdrop" onClick={() => setSelectedConnection(null)}><section className="detail-modal" role="dialog" aria-modal="true" aria-labelledby="connection-title" onClick={e => e.stopPropagation()}><div className="panel-top"><Network size={22}/><button autoFocus className="icon-button" aria-label={t("Fechar detalhes")} onClick={() => setSelectedConnection(null)}><X size={19}/></button></div><h2 id="connection-title">{selectedConnection.process || t("Não verificado")}</h2><Badge>{riskLabel(selectedConnection)}</Badge><p>{t("Esta análise usa sinais locais e não confirma que uma conexão é segura ou maliciosa. Não consulta reputação externa de IPs.")}</p>{!selectedConnection.analysis ? <Button onClick={() => { setSelectedConnection(null); analyseNetwork(); }}>{t("Analisar conexões")}</Button> : <><p>{selectedConnection.analysis.inspected ? t("Caminho do executável consultado.") : t("Não foi possível consultar o executável deste processo.")}</p>{selectedConnection.analysis.signals.map(signal => <p key={signal} className="inline-note amber">{t(({ listener: 'Serviço em escuta fora do loopback. Revise a necessidade e as regras do firewall.', temporary: 'Executável em pasta temporária ou de downloads. Confirme sua origem.', signature: 'A assinatura apresenta um problema de confiança. Revise o arquivo.' } as Record<string, string>)[signal] || 'Não verificado')}</p>)}{selectedConnection.analysis.path && <pre>{selectedConnection.analysis.path}</pre>}<p>{t("Para procurar malware, verifique o arquivo com ClamAV. As assinaturas precisam estar atualizadas; nenhum arquivo será enviado ou removido.")}</p><Button icon={Bug} disabled={Boolean(busy) || !ready || !selectedConnection.analysis.token} onClick={() => perform('connection-scan', async () => { const job = await call<AvJob>('connections:scan', { token: selectedConnection.analysis!.token }); setAv(previous => previous ? { ...previous, job } : previous); setSelectedConnection(null); go('antivirus'); })}>{t("Verificar executável")}</Button>{!ready && <p>{t("Prepare a base de assinaturas antes de iniciar a varredura.")}</p>}</>}</section></div>}
    {selectedCheck && <div className="modal-backdrop" onClick={() => setSelectedCheck(null)}><section className="detail-modal" role="dialog" aria-modal="true" aria-labelledby="check-title" onClick={e => e.stopPropagation()}><div className="panel-top"><CheckIcon status={selectedCheck.status}/><button autoFocus className="icon-button" aria-label={t("Fechar detalhes")} onClick={() => setSelectedCheck(null)}><X size={19}/></button></div><span className="overline">{t("EVIDÊNCIA DO DIAGNÓSTICO")}</span><h2 id="check-title">{t(selectedCheck.title)}</h2><Badge tone={selectedCheck.status === 'pass' ? 'green' : selectedCheck.status === 'warning' ? 'amber' : 'neutral'}>{statusLabel[selectedCheck.status]}</Badge><h4>{t("O que foi observado")}</h4><p>{summary(selectedCheck)}</p><Original value={selectedCheck.evidence}/><h4>{t("Próximo passo")}</h4><p>{recommendation(selectedCheck)}</p>{selectedCheck.action && <Button kind="primary" icon={ArrowRight} onClick={() => { go(selectedCheck.action!); setSelectedCheck(null); }}>{t("Abrir área relacionada")}</Button>}</section></div>}
    {palette && <div className="modal-backdrop command-backdrop" onClick={() => setPalette(false)}><section className="command-palette" role="dialog" aria-modal="true" aria-label={t("Navegação rápida")} onClick={e => e.stopPropagation()}><div className="palette-input"><Search size={20}/><input autoFocus aria-label={t("Buscar área do aplicativo")} placeholder={t("Buscar módulo")} value={paletteQuery} onChange={e => setPaletteQuery(e.target.value)} onKeyDown={e => {
                if (e.key === 'Enter') {
                    const match = [...navigation, { id: 'settings' as Page, label: t("Preferências"), icon: Settings2 }].find(n => n.label.toLowerCase().includes(paletteQuery.toLowerCase()));
                    if (match)
                        go(match.id);
                }
            }}/><button className="icon-button" aria-label={t("Fechar busca")} onClick={() => setPalette(false)}><X size={17}/></button></div>{[...navigation, { id: 'settings' as Page, label: t("Preferências"), icon: Settings2 }].filter(n => n.label.toLowerCase().includes(paletteQuery.toLowerCase())).map(n => <button key={n.id} onClick={() => go(n.id)}><n.icon size={17}/><span>{n.label}</span><ArrowUpRight size={15}/></button>)}<div className="palette-foot">{t("Enter para abrir · Esc para fechar")}</div></section></div>}
    </div>;
}
