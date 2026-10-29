import {installNative} from './native';
import {t} from './i18n';
import React from 'react';
import{createRoot}from'react-dom/client';
import{App}from'./App';
import './style.css';
import './overview.css';
import './features.css';
class Boundary extends React.Component<{children:React.ReactNode},{error:boolean}>{
  state={error:false};
  static getDerivedStateFromError(){return{error:true};}
  render(){return this.state.error?<div className="fatal"><h1>Aegis</h1><p>{t("A interface encontrou um problema. Reinicie o aplicativo; seu histórico local foi preservado.")}</p><button onClick={()=>location.reload()}>{t("Reabrir interface")}</button></div>:this.props.children;}
}
installNative().then(()=>createRoot(document.getElementById('root')!).render(<Boundary><App/></Boundary>));

