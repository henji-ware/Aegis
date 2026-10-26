import React from 'react';
import{createRoot}from'react-dom/client';
import{App}from'./App';
import './style.css';
class Boundary extends React.Component<{children:React.ReactNode},{error:boolean}>{
  state={error:false};
  static getDerivedStateFromError(){return{error:true};}
  render(){return this.state.error?<div className="fatal"><h1>Aegis</h1><p>A interface encontrou um problema. Reinicie o aplicativo; seu histórico local foi preservado.</p><button onClick={()=>location.reload()}>Reabrir interface</button></div>:this.props.children;}
}
createRoot(document.getElementById('root')!).render(<Boundary><App/></Boundary>);

