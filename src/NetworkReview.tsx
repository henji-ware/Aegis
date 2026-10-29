import {Loader2} from 'lucide-react';
import type {Connection} from './types';
import {date} from './api';
import {t} from './i18n';
import {Problem} from './presentation';
export type ConnectionReport={at:string;rows:Connection[]};
export type ReviewFilter='all'|'review'|'no-signals'|'unknown';
export function reviewLevel(row:Connection):Exclude<ReviewFilter,'all'>{return row.analysis?.level==='review'?'review':row.analysis?.level==='no-signals'&&row.analysis.inspected?'no-signals':'unknown';}
export function signalText(signal:string){return t(({listener:'Serviço em escuta fora do loopback. Revise a necessidade e as regras do firewall.',temporary:'Executável em pasta temporária ou de downloads. Confirme sua origem.',signature:'A assinatura apresenta um problema de confiança. Revise o arquivo.'} as Record<string,string>)[signal]||'Não verificado');}
export function NetworkReview({report,running,error,view,filter,onView,onFilter}:{report:ConnectionReport|null;running:boolean;error:string;view:'live'|'analysis';filter:ReviewFilter;onView:(view:'live'|'analysis')=>void;onFilter:(filter:ReviewFilter)=>void}){
 if(!report&&!running&&!error)return null;
 const counts={all:report?.rows.length||0,review:0,'no-signals':0,unknown:0};for(const row of report?.rows||[])counts[reviewLevel(row)]++;
 const checked=report?.rows.filter(row=>row.analysis?.inspected).length||0;
 return <section className="panel network-review" aria-label={t('Resultado da análise')}>
 {running&&<p className="analysis-pending" role="status"><Loader2 className="task-spinner" size={18}/>{t('Consultando processos e caminhos dos executáveis…')}</p>}
 {error&&<div className="analysis-error" role="alert"><Problem value={error}/></div>}
 {report&&<><div className="panel-top"><div><h3>{t('Resultado da análise')}</h3><span className="subtle">{date(report.at)}</span></div><div className="segmented"><button aria-pressed={view==='analysis'} className={view==='analysis'?'selected':''} onClick={()=>onView('analysis')}>{t('Ver resultado da análise')}</button><button aria-pressed={view==='live'} className={view==='live'?'selected':''} onClick={()=>onView('live')}>{t('Conexões ao vivo')}</button></div></div>
 <div className="analysis-counts">{(['all','review','no-signals','unknown'] as ReviewFilter[]).map(key=><button key={key} className={view==='analysis'&&filter===key?'selected':''} aria-pressed={view==='analysis'&&filter===key} onClick={()=>{onView('analysis');onFilter(key);}}><span>{t(({all:'Conexões analisadas',review:'Revisar sinais','no-signals':'Sem sinais locais',unknown:'Não verificado'})[key])}</span><strong>{counts[key]}</strong></button>)}</div>
 <p className="analysis-coverage">{t('Caminho identificado em {checked} de {total} conexões.',{checked,total:counts.all})}</p>
 <p>{t('A consulta verifica portas em escuta e caminhos de executáveis. Não consulta reputação de IPs nem faz uma varredura automática de malware.')}</p>
 {view==='analysis'&&<p>{t('O resultado é uma fotografia da consulta. O monitoramento não altera esta análise.')}</p>}
 {report.rows.length>=350&&<p className="analysis-limit">{t('A consulta atingiu o limite de conexões; a cobertura pode estar incompleta.')}</p>}
 {!counts.all&&<p className="quiet-empty">{t('Nenhuma conexão retornada nesta consulta.')}</p>}
 </>}
 </section>;
}
