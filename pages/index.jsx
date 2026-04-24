import { useState, useRef, useEffect, useCallback, useMemo } from "react";
import { loadStripe } from "@stripe/stripe-js";
import { Elements, CardElement, useStripe, useElements } from "@stripe/react-stripe-js";

const _stripePromise = typeof window !== "undefined" 
  ? loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY) 
  : null;

const PRICE = "$5.00 USD";
const _B = [30.1,17.6,12.5,9.7,7.9,6.7,5.8,5.1,4.6];

function _fd(n){const s=Math.abs(n).toString().replace(".","");for(const c of s)if(c!=="0")return parseInt(c);return null;}
function _analyze(numbers){
  const counts=Array(9).fill(0);let valid=0;
  const byDigit=Array.from({length:9},()=>[]);
  for(const n of numbers){const d=_fd(n);if(d&&d>=1&&d<=9){counts[d-1]++;valid++;byDigit[d-1].push(n);}}
  const dist=counts.map(c=>valid>0?(c/valid)*100:0);
  // Per-digit chi2 contribution
  const chiParts=dist.map((obs,i)=>{
    const exp=(_B[i]/100)*valid;
    const obsN=(obs/100)*valid;
    const contrib=Math.pow(obsN-exp,2)/exp;
    const diff=obs-_B[i];
    return{digit:i+1,observed:parseFloat(obs.toFixed(2)),expected:_B[i],obsN:Math.round(obsN),expN:Math.round(exp),diff:parseFloat(diff.toFixed(2)),contrib:parseFloat(contrib.toFixed(3)),severity:Math.abs(diff)>8?"critical":Math.abs(diff)>4?"high":Math.abs(diff)>2?"medium":"low",overrep:diff>0};
  });
  const score=chiParts.reduce((s,p)=>s+p.contrib,0);
  // Attack zones: suspicious value clusters
  const freq={};
  for(const n of numbers){const k=Math.floor(n/100)*100;freq[k]=(freq[k]||0)+1;}
  const clusters=Object.entries(freq).filter(([,c])=>c>=Math.max(2,valid*0.04)).sort((a,b)=>b[1]-a[1]).slice(0,6).map(([r,c])=>({range:parseInt(r),count:c,pct:parseFloat(((c/valid)*100).toFixed(1))}));
  // Anomalous digits sorted by contribution
  const anomalous=chiParts.filter(p=>p.severity!=="low"&&p.diff>0).sort((a,b)=>b.contrib-a.contrib);
  // p-value approximation (chi2 with 8 df)
  const pApprox=score>26.1?"<0.001":score>20.1?"<0.01":score>15.5?"<0.05":">0.05";
  // Pattern detection
  let pattern="none";
  if(anomalous.some(p=>p.digit>=4&&p.digit<=6))pattern="threshold_avoidance";
  else if(anomalous.some(p=>p.digit>=7))pattern="inflation";
  else if(chiParts.filter(p=>Math.abs(p.diff)<1).length>=7)pattern="uniform";
  else if(score>15)pattern="general";
  return{dist,valid,score,chiParts,clusters,anomalous,pApprox,pattern,byDigit};
}
function _verdict(score){
  if(score<15.5)return{color:"#22c55e",bg:"#052e16",icon:"✓"};
  if(score<25)return{color:"#f59e0b",bg:"#1c1400",icon:"⚠"};
  return{color:"#ef4444",bg:"#2d0a0a",icon:"✕"};
}

const SAMPLES={
  clean:[1250,1890,1340,2100,1567,1823,1092,1445,1678,1234,2890,1567,1123,1890,1234,2345,1456,1678,1890,1234,2100,1567,1823,1345,1234,2890,1456,1123,1567,1890,1234,2100,1456,1823,1345,1678,1234,2890,1567,1123,1890,2345,1456,1678,1234,1567,1890,1345,1123,2100],
  fraud:[4950,5000,4980,9990,9950,4975,5025,9975,4960,5010,4985,9985,4995,5005,9995,4970,5030,9970,4965,5015,4988,9988,4992,5008,9992,4978,5022,9978,4982,5018,9982,4972,5028,9972,4968,5032,9968,4962,5038,9962,4958,5042,9958,4955,5045,9955,4952,5048,9952,4948],
};

const G=`
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400;500;600&family=DM+Mono:wght@400;500&display=swap');
*{box-sizing:border-box}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
@keyframes modalIn{from{opacity:0;transform:translateY(30px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.05)}}
@keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-5px)}75%{transform:translateX(5px)}}
.fade{animation:fadeUp .35s ease}
.spin{animation:spin 1s linear infinite}
.modal{animation:modalIn .3s ease}
.shake{animation:shake .4s ease}
/* ── Desktop layout ── */
@media(min-width:900px){
  .dsk-hero{padding:80px 48px 60px!important;display:flex!important;align-items:center!important;gap:60px!important;text-align:left!important;}
  .dsk-hero-text{flex:1;text-align:left!important;}
  .dsk-hero-logo{flex-shrink:0;}
  .dsk-hero h1{font-size:clamp(36px,4vw,56px)!important;}
  .dsk-hero .cta-row{justify-content:flex-start!important;}
  .dsk-main{max-width:1100px!important;padding:0 48px!important;display:grid!important;grid-template-columns:1fr 1fr!important;gap:32px!important;align-items:start!important;}
  .dsk-full{grid-column:1/-1!important;}
  .dsk-single{max-width:560px!important;margin:0 auto!important;padding:0 32px!important;}
  .dsk-result{max-width:1100px!important;padding:0 48px!important;display:grid!important;grid-template-columns:1fr 1fr!important;gap:28px!important;align-items:start!important;}
  .dsk-result-full{grid-column:1/-1!important;}
  .dsk-nav{padding:10px 48px!important;}
}
`;

const dark={background:"#080c14",minHeight:"100vh",fontFamily:"'DM Sans',sans-serif",color:"#e2e8f0"};
const W={maxWidth:560,margin:"0 auto",padding:"0 16px",width:"100%"};

// ── LOGO COMPONENTS ──────────────────────────────────────────
function LogoHero(){
  return(
    <svg width="80" height="80" viewBox="-90 -90 180 180">
      <circle r="80" fill="none" stroke="#1d4ed8" strokeWidth="0.8" opacity=".18"/>
      <circle r="56" fill="none" stroke="#1d4ed8" strokeWidth="0.8" opacity=".25"/>
      <circle r="32" fill="none" stroke="#1d4ed8" strokeWidth="1" opacity=".35"/>
      <line x1="-85" y1="0" x2="85" y2="0" stroke="#1d4ed8" strokeWidth=".4" opacity=".2"/>
      <line x1="0" y1="-85" x2="0" y2="85" stroke="#1d4ed8" strokeWidth=".4" opacity=".2"/>
      <path d="M0,0 L74,-30 A80,80,0,0,1,76,14 Z" fill="#2563eb" opacity=".14"/>
      <path d="M0,0 L74,-30" stroke="#3b82f6" strokeWidth="1.5" opacity=".8" fill="none"/>
      <text x="52" y="-34" style={{fontFamily:"monospace",fontSize:"12px",fill:"#60a5fa",fontWeight:600}}>χ²</text>
      <circle cx="44" cy="-40" r="6" fill="#ef4444"/>
      <circle cx="44" cy="-40" r="11" fill="none" stroke="#ef4444" strokeWidth="0.8" opacity=".4"/>
      <text x="58" y="-50" style={{fontFamily:"monospace",fontSize:"9px",fill:"#ef4444",opacity:.9}}>p&lt;0.05</text>
      <circle r="3.5" fill="#3b82f6"/>
      <text x="-78" y="54" style={{fontFamily:"monospace",fontSize:"10px",fill:"#3b82f6",opacity:.65}}>Σ(O−E)²/E</text>
      <text x="26" y="70" style={{fontFamily:"monospace",fontSize:"9px",fill:"#475569",opacity:.8}}>95% conf.</text>
    </svg>
  );
}

function LogoSmall(){
  return(
    <svg width="26" height="26" viewBox="-32 -32 64 64">
      <circle r="28" fill="none" stroke="#1d4ed8" strokeWidth=".7" opacity=".22"/>
      <circle r="18" fill="none" stroke="#1d4ed8" strokeWidth=".7" opacity=".3"/>
      <circle r="9" fill="none" stroke="#1d4ed8" strokeWidth=".8" opacity=".4"/>
      <line x1="-31" y1="0" x2="31" y2="0" stroke="#1d4ed8" strokeWidth=".3" opacity=".2"/>
      <line x1="0" y1="-31" x2="0" y2="31" stroke="#1d4ed8" strokeWidth=".3" opacity=".2"/>
      <path d="M0,0 L26,-11 A28,28,0,0,1,27,5 Z" fill="#2563eb" opacity=".16"/>
      <path d="M0,0 L26,-11" stroke="#3b82f6" strokeWidth="1.1" opacity=".75" fill="none"/>
      <circle cx="15" cy="-14" r="3.5" fill="#ef4444"/>
      <circle r="2.5" fill="#3b82f6"/>
    </svg>
  );
}

// ── NAV ──────────────────────────────────────────────────────
const NavBar=({lang,setLang})=>(
  <div className="dsk-nav" style={{position:"fixed",top:0,left:0,right:0,zIndex:300,background:"#080c14ee",backdropFilter:"blur(10px)",borderBottom:"1px solid #1e293b",padding:"8px 16px",display:"flex",alignItems:"center",justifyContent:"space-between"}}>
    <div style={{display:"flex",alignItems:"center",gap:8}}>
      <LogoSmall/>
      <span style={{fontFamily:"'Syne',sans-serif",fontWeight:800,fontSize:15,color:"#f1f5f9",letterSpacing:"-.5px"}}>
        Fraud<span style={{color:"#3b82f6"}}>Radar</span>
        <span style={{fontFamily:"monospace",fontSize:10,color:"#475569",fontWeight:400,marginLeft:2}}>.io</span>
      </span>
    </div>
    <button onClick={()=>setLang(l=>l==="es"?"en":"es")} style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:8,color:"#64748b",fontSize:11,fontFamily:"monospace",padding:"5px 10px",cursor:"pointer",letterSpacing:2,display:"flex",alignItems:"center",gap:6}}>
      <span>{lang==="es"?"🇲🇽":"🇺🇸"}</span>{lang==="es"?"EN":"ES"}
    </button>
  </div>
);

// ── TERMS MODAL ───────────────────────────────────────────────
function TermsModal({onClose,lang}){
  const S=[
    {n:"01",c:"#f59e0b",t:lang==="es"?"Naturaleza del servicio":"Nature of service",
     b:lang==="es"?"FraudRadar aplica metodología estadística forense de nivel institucional. El resultado es indicativo. No constituye dictamen pericial ni prueba legal.":"FraudRadar applies institutional-grade forensic statistical methodology. Results are indicative, not conclusive or legally binding.",
     w:lang==="es"?"NO es servicio de auditoría, contaduría ni asesoría jurídica.":"NOT an auditing, accounting, or legal advisory service."},
    {n:"02",c:"#f59e0b",t:lang==="es"?"Deslinde de responsabilidad":"Disclaimer",
     bullets:lang==="es"?["'SIN ANOMALÍAS' no confirma ausencia de fraude","'ALERTA' no es prueba legal bajo ninguna legislación","El usuario es el único responsable de las decisiones tomadas","FraudRadar no asume responsabilidad por daños de ningún tipo"]:["'NO ANOMALIES' does not confirm absence of fraud","'ALERT' is not legal proof under any jurisdiction","User is solely responsible for decisions made based on results","FraudRadar assumes no liability for damages of any kind"]},
    {n:"03",c:"#f59e0b",t:lang==="es"?"Limitaciones del modelo":"Model limitations",
     bullets:lang==="es"?["Menos de 30 registros — no significativo estadísticamente","Datos con rango artificialmente restringido","Números asignados secuencialmente (folios, SKUs)","Porcentajes, tasas de interés, proporciones","Precios psicológicos ($99, $999)"]:["Fewer than 30 records — statistically insignificant","Artificially restricted range data","Sequentially assigned numbers (folios, SKUs)","Percentages, interest rates, proportions","Psychological prices ($99, $999)"]},
    {n:"04",c:"#ef4444",t:lang==="es"?"Usos prohibidos":"Prohibited uses",
     bullets:lang==="es"?["Acusar o denunciar penalmente usando el resultado como única evidencia","Presentar como dictamen pericial ante SAT, FGR o cualquier autoridad","Extorsionar o coaccionar a personas con los resultados","Uso en despidos sin auditoría formal complementaria"]:["Accusing individuals using result as sole evidence","Presenting as expert opinion before regulatory authorities","Extorting or coercing individuals with results","Use in dismissals without complementary formal audit"]},
    {n:"05",c:"#22c55e",t:lang==="es"?"Política de reembolso":"Refund policy",
     refunds:lang==="es"?[["✓","Error técnico de la plataforma que impidió el análisis"],["✓","Cobro sin entrega de resultado por falla del servidor"],["✗","Desacuerdo con el resultado estadístico"],["✗","Archivo que no cumplía requisitos mínimos"],["✗","Más de 72 horas desde el análisis"]]:
     [["✓","Platform technical error that prevented analysis"],["✓","Payment charged without result due to server failure"],["✗","Disagreement with the statistical result"],["✗","File did not meet minimum requirements"],["✗","More than 72 hours since analysis"]]},
    {n:"06",c:"#3b82f6",t:lang==="es"?"Privacidad":"Privacy",
     b:lang==="es"?"El análisis corre íntegramente en tu navegador. Los datos nunca se transmiten ni almacenan. Solo datos de pago son procesados por Stripe Inc. bajo PCI-DSS.":"Analysis runs entirely in your browser. Data is never transmitted or stored. Only payment data is processed by Stripe Inc. under PCI-DSS."},
    {n:"07",c:"#3b82f6",t:lang==="es"?"Jurisdicción":"Jurisdiction",
     b:lang==="es"?"Rigen las leyes de México. Las partes se someten a tribunales de la Ciudad de México.":"Governed by Mexican law. Parties submit to courts of Mexico City."},
  ];
  return(
    <div style={{position:"fixed",inset:0,background:"#000c",zIndex:999,display:"flex",alignItems:"flex-end",justifyContent:"center"}}>
      <div className="modal" style={{background:"#0d1117",border:"1px solid #1e293b",borderRadius:"20px 20px 0 0",width:"100%",maxWidth:500,maxHeight:"85vh",overflow:"auto",paddingBottom:32}}>
        <div style={{position:"sticky",top:0,background:"#0d1117",borderBottom:"1px solid #1e293b",padding:"14px 18px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <p style={{color:"#f1f5f9",fontFamily:"'Syne',sans-serif",fontWeight:800,fontSize:15,margin:0}}>{lang==="es"?"Términos, Condiciones y Deslinde":"Terms, Conditions & Disclaimer"}</p>
          <button onClick={onClose} style={{background:"#1e293b",border:"none",borderRadius:"50%",width:28,height:28,cursor:"pointer",color:"#94a3b8",fontSize:14,display:"flex",alignItems:"center",justifyContent:"center"}}>✕</button>
        </div>
        <div style={{padding:"16px 18px",display:"flex",flexDirection:"column",gap:12}}>
          {S.map(s=>(
            <div key={s.n} style={{background:"#080c14",border:"1px solid #1e293b",borderRadius:10,padding:"12px"}}>
              <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
                <span style={{background:s.c+"22",border:`1px solid ${s.c}33`,borderRadius:4,padding:"2px 6px",color:s.c,fontSize:10,fontFamily:"monospace",fontWeight:600}}>{s.n}</span>
                <p style={{color:"#f1f5f9",fontWeight:600,fontSize:13,margin:0}}>{s.t}</p>
              </div>
              {s.b&&<p style={{color:"#64748b",fontSize:12,lineHeight:1.6,margin:0}}>{s.b}</p>}
              {s.w&&<div style={{background:"#2d0a0a",border:"1px solid #ef444422",borderRadius:7,padding:"7px 10px",marginTop:7}}><p style={{color:"#f87171",fontSize:11,margin:0}}>⚠ {s.w}</p></div>}
              {s.bullets&&<div style={{display:"flex",flexDirection:"column",gap:4}}>{s.bullets.map((b,i)=><div key={i} style={{display:"flex",gap:8}}><span style={{color:"#334155",fontSize:10,flexShrink:0,marginTop:2}}>→</span><p style={{color:"#64748b",fontSize:11,lineHeight:1.5,margin:0}}>{b}</p></div>)}</div>}
              {s.refunds&&<div style={{display:"flex",flexDirection:"column",gap:4}}>{s.refunds.map(([ic,d],i)=><div key={i} style={{display:"flex",gap:8,background:"#0d1117",borderRadius:5,padding:"5px 8px"}}><span style={{color:ic==="✓"?"#22c55e":"#ef4444",fontSize:10,flexShrink:0}}>{ic}</span><p style={{color:"#64748b",fontSize:11,margin:0}}>{d}</p></div>)}</div>}
            </div>
          ))}
          <button onClick={onClose} style={{width:"100%",background:"#f1f5f9",color:"#080c14",border:"none",borderRadius:10,padding:"13px",fontSize:14,fontWeight:700,cursor:"pointer",fontFamily:"inherit",marginTop:4}}>
            {lang==="es"?"Entendido — Cerrar":"Got it — Close"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── PDF ───────────────────────────────────────────────────────
function makePDF(dist,score,valid,verdict,filename,lang,chiParts=[],anomalous=[],clusters=[],pApprox=">0.05",pattern="none"){
  const date=new Date().toLocaleDateString(lang==="es"?"es-MX":"en-US",{year:"numeric",month:"long",day:"numeric"});
  const vLabel=score<15.5?(lang==="es"?"SIN ANOMALÍAS":"NO ANOMALIES"):score<25?(lang==="es"?"REVISAR":"REVIEW"):(lang==="es"?"ALERTA":"ALERT");
  const interp=score<15.5
    ?(lang==="es"?"El conjunto de datos presenta patrones estadísticos consistentes con registros financieros orgánicos. No se detectaron señales de anomalía significativa.":"The dataset presents statistical patterns consistent with organic financial records. No significant anomaly signals were detected.")
    :score<25
    ?(lang==="es"?"Se detectaron desviaciones estadísticas moderadas. Se recomienda revisión manual de los registros con mayor concentración en rangos específicos.":"Moderate statistical deviations detected. Manual review of records with higher concentration in specific value ranges is recommended.")
    :(lang==="es"?"El conjunto de datos presenta anomalías estadísticas significativas. Se recomienda auditoría formal inmediata por contador público certificado.":"The dataset presents significant statistical anomalies. Immediate formal audit by a certified public accountant is strongly recommended.");
  const steps=score<15.5
    ?(lang==="es"?["Conserva este reporte como respaldo de la revisión realizada.","Repite el análisis periódicamente como parte de tus controles internos.","Considera analizar otros conjuntos: nómina, cuentas por pagar, gastos."]:["Keep this report as evidence of the review conducted.","Repeat the analysis periodically as part of your internal controls.","Consider analyzing other datasets: payroll, accounts payable, expenses."])
    :score<25
    ?(lang==="es"?["Filtra los registros con mayor desviación y revísalos manualmente.","Verifica soporte documental (factura, orden de compra, firma) de cada registro.","Si confirmas anomalías, consulta a un contador público certificado."]:["Filter records with the highest deviation and review them manually.","Verify documentary support (invoice, purchase order, signature) for each record.","If anomalies are confirmed, consult a certified public accountant."])
    :(lang==="es"?["No modifiques ni elimines ningún registro hasta completar una revisión formal.","Contacta inmediatamente a un contador público certificado o auditor forense.","Identifica quién tuvo acceso a estos registros y en qué fechas.","Si hay indicios de fraude, considera denuncia formal con apoyo de un abogado."]:["Do not modify or delete any records until a formal review is completed.","Immediately contact a certified public accountant or forensic auditor.","Identify who had access to these records and on what dates.","If fraud is indicated, consider filing a formal complaint with legal counsel."]);
  const stepColor=score<15.5?"#166534":score<25?"#92400e":"#991b1b";
  const stepBg=score<15.5?"#f0fdf4":score<25?"#fffbeb":"#fef2f2";
  const html=`<!DOCTYPE html><html lang="${lang}"><head><meta charset="UTF-8"><title>FraudRadar Report</title>
  <style>body{font-family:'Helvetica Neue',Arial,sans-serif;color:#1e293b;margin:0;background:#fff}
  .hdr{background:#0f172a;padding:32px 40px;display:flex;justify-content:space-between;align-items:flex-end}
  .logo{display:flex;align-items:center;gap:12px;margin-bottom:10px}
  .logo-wm{font-size:20px;font-weight:800;color:#fff;font-family:Arial}.logo-dot{color:#3b82f6}
  .logo-tag{font-size:9px;color:#64748b;letter-spacing:3px;text-transform:uppercase;margin-top:3px}
  .hdr h1{margin:0;font-size:22px;font-weight:800;color:#fff}.hdr p{margin:4px 0 0;color:#94a3b8;font-size:12px}
  .badge{padding:8px 16px;border-radius:6px;font-size:12px;font-weight:700;letter-spacing:1px;background:${verdict.bg};color:${verdict.color};border:2px solid ${verdict.color}}
  .sec{padding:26px 40px;border-bottom:1px solid #f1f5f9}
  .metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
  .m{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px}
  .ml{font-size:9px;color:#94a3b8;letter-spacing:2px;text-transform:uppercase;margin:0 0 5px}
  .mv{font-size:20px;font-weight:800;color:#0f172a;margin:0}
  h2{font-size:10px;text-transform:uppercase;letter-spacing:3px;color:#64748b;margin:0 0 12px;font-weight:700}
  .interp{background:#f8fafc;border-left:4px solid ${verdict.color};padding:16px 20px;border-radius:0 8px 8px 0;font-size:13px;line-height:1.7;color:#334155}
  .step{display:flex;gap:10px;align-items:flex-start;padding:10px;background:${stepBg};border-radius:6px;margin-bottom:6px}
  .step-n{color:${stepColor};font-weight:700;flex-shrink:0;font-size:13px}
  .step-t{margin:0;font-size:13px;color:${stepColor};line-height:1.5}
  .disc{background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:12px 16px;font-size:11px;line-height:1.6;color:#92400e}
  .foot{padding:18px 40px;display:flex;justify-content:space-between;font-size:10px;color:#94a3b8;border-top:1px solid #e2e8f0;background:#f8fafc}
  .bar{height:8px;background:#e2e8f0;border-radius:4px;overflow:hidden;margin-top:8px}
  .bar-fill{height:100%;background:${verdict.color};border-radius:4px;width:${score<15.5?88:score<25?62:38}%}
  </style></head><body>
  <div class="hdr">
    <div>
      <div class="logo">
        <svg width="36" height="36" viewBox="-90 -90 180 180" xmlns="http://www.w3.org/2000/svg">
          <circle r="80" fill="none" stroke="#1d4ed8" stroke-width="2.5" opacity=".25"/>
          <circle r="56" fill="none" stroke="#1d4ed8" stroke-width="2" opacity=".32"/>
          <circle r="32" fill="none" stroke="#1d4ed8" stroke-width="2" opacity=".42"/>
          <line x1="-85" y1="0" x2="85" y2="0" stroke="#1d4ed8" stroke-width="1" opacity=".2"/>
          <line x1="0" y1="-85" x2="0" y2="85" stroke="#1d4ed8" stroke-width="1" opacity=".2"/>
          <path d="M0,0 L74,-30 A80,80,0,0,1,76,14 Z" fill="#2563eb" opacity=".2"/>
          <path d="M0,0 L74,-30" stroke="#3b82f6" stroke-width="3" opacity=".85" fill="none"/>
          <text x="46" y="-30" font-family="monospace" font-size="20" fill="#60a5fa">χ²</text>
          <circle cx="44" cy="-40" r="9" fill="#ef4444"/>
          <circle r="5" fill="#3b82f6"/>
        </svg>
        <div><div class="logo-wm">Fraud<span class="logo-dot">Radar</span><span style="font-size:11px;color:#64748b;font-weight:400;margin-left:2px">.io</span></div>
        <div class="logo-tag">${lang==="es"?"Detección de Fraude en Datos":"Financial Fraud Detection"}</div></div>
      </div>
      <h1>${lang==="es"?"Reporte de Análisis Forense":"Forensic Analysis Report"}</h1>
      <p>${lang==="es"?"Análisis estadístico · Nivel institucional":"Statistical analysis · Institutional grade"} · ${date}</p>
      <p style="color:#64748b;font-size:11px;margin-top:4px">${lang==="es"?"Archivo":"File"}: <strong style="color:#94a3b8">${filename||"datos"}</strong></p>
    </div>
    <div class="badge">${verdict.icon} ${vLabel}</div>
  </div>
  <div class="sec"><h2>${lang==="es"?"Resumen ejecutivo":"Executive summary"}</h2>
    <div class="metrics">
      <div class="m"><p class="ml">${lang==="es"?"Registros":"Records"}</p><p class="mv">${valid.toLocaleString()}</p></div>
      <div class="m"><p class="ml">${lang==="es"?"Índice forense":"Forensic index"}</p><p class="mv" style="color:${verdict.color}">${score.toFixed(1)}</p><div class="bar"><div class="bar-fill"></div></div></div>
      <div class="m"><p class="ml">${lang==="es"?"Confianza":"Confidence"}</p><p class="mv">95%</p></div>
    </div>
  </div>
  <div class="sec"><h2>${lang==="es"?"Interpretación":"Interpretation"}</h2><div class="interp">${interp}</div></div>
  <div class="sec"><h2>${lang==="es"?"Próximos pasos recomendados":"Recommended next steps"}</h2>
    ${steps.map((s,i)=>`<div class="step"><span class="step-n">${i+1}.</span><p class="step-t">${s}</p></div>`).join("")}
  </div>
  <div style="padding:20px 40px;border-bottom:1px solid #f1f5f9">
    <h2 style="font-size:10px;text-transform:uppercase;letter-spacing:3px;color:#64748b;margin:0 0 12px;font-weight:700">${lang==="es"?"Desglose Chi-cuadrada por Digito":"Chi-Square Breakdown by Digit"}</h2>
    <p style="font-size:11px;color:#64748b;font-family:monospace;margin:0 0 10px">chi2 = ${score.toFixed(2)} | p-value ${pApprox} | 8 df | ${lang==="es"?"Umbral critico":"Critical threshold"}: 15.507</p>
    <table style="width:100%;border-collapse:collapse;font-size:11px;font-family:monospace">
      <thead><tr style="background:#f8fafc">
        <th style="padding:6px 8px;text-align:left;color:#64748b;border-bottom:2px solid #e2e8f0;font-size:10px">${lang==="es"?"Digito":"Digit"}</th>
        <th style="padding:6px 8px;text-align:left;color:#64748b;border-bottom:2px solid #e2e8f0;font-size:10px">Benford%</th>
        <th style="padding:6px 8px;text-align:left;color:#64748b;border-bottom:2px solid #e2e8f0;font-size:10px">${lang==="es"?"Real%":"Actual%"}</th>
        <th style="padding:6px 8px;text-align:left;color:#64748b;border-bottom:2px solid #e2e8f0;font-size:10px">${lang==="es"?"Diferencia":"Difference"}</th>
        <th style="padding:6px 8px;text-align:left;color:#64748b;border-bottom:2px solid #e2e8f0;font-size:10px">chi2</th>
        <th style="padding:6px 8px;text-align:left;color:#64748b;border-bottom:2px solid #e2e8f0;font-size:10px">${lang==="es"?"Estado":"Status"}</th>
      </tr></thead>
      <tbody>${chiParts.map(p=>{
        const bg=p.severity==="critical"?"#fef2f2":p.severity==="high"?"#fffbeb":"#fff";
        const sc=p.severity==="critical"?"#dc2626":p.severity==="high"?"#d97706":"#0f172a";
        const sl=p.severity==="critical"?(lang==="es"?"CRITICO":"CRITICAL"):p.severity==="high"?(lang==="es"?"ALTO":"HIGH"):p.severity==="medium"?(lang==="es"?"MEDIO":"MED"):"OK";
        const slc=p.severity==="critical"?"#dc2626":p.severity==="high"?"#d97706":p.severity==="medium"?"#ca8a04":"#16a34a";
        return "<tr style='background:"+bg+";border-bottom:1px solid #f1f5f9'><td style='padding:6px 8px;font-weight:700'>"+p.digit+"</td><td style='padding:6px 8px;color:#64748b'>"+p.expected+"%</td><td style='padding:6px 8px;font-weight:700;color:"+sc+"'>"+p.observed+"%</td><td style='padding:6px 8px;color:"+(p.diff>0?"#dc2626":"#16a34a")+"'>"+(p.diff>0?"+":"")+p.diff+"%</td><td style='padding:6px 8px;color:#64748b'>"+p.contrib+"</td><td style='padding:6px 8px;color:"+slc+";font-weight:700;font-size:10px'>"+sl+"</td></tr>";
      }).join("")}</tbody>
    </table>
  </div>
  ${score>15.5&&anomalous.length>0?`<div style="padding:20px 40px;border-bottom:1px solid #f1f5f9">
    <h2 style="font-size:10px;text-transform:uppercase;letter-spacing:3px;color:#64748b;margin:0 0 12px;font-weight:700">${lang==="es"?"Zonas de Ataque — Donde Buscar el Fraude":"Attack Zones — Where to Look for Fraud"}</h2>
    ${anomalous.slice(0,3).map(p=>`<div style="background:#fef2f2;border-left:4px solid #dc2626;border-radius:0 6px 6px 0;padding:12px 16px;margin-bottom:10px"><p style="font-weight:700;color:#991b1b;font-size:13px;margin:0 0 5px">${lang==="es"?"Digito":"Digit"} ${p.digit}: ${p.observed}% ${lang==="es"?"vs":"vs"} ${p.expected}% ${lang==="es"?"esperado":"expected"} (${lang==="es"?"exceso":"excess"}: +${p.diff}%)</p><p style="color:#7f1d1d;font-size:11px;line-height:1.6;margin:0 0 4px">${lang==="es"?`${p.obsN} registros encontrados, ${p.expN} esperados. Exceso de ${p.obsN-p.expN} registros anomalos. Chi2 aporte: ${p.contrib}`:`${p.obsN} records found, ${p.expN} expected. Excess of ${p.obsN-p.expN} anomalous records. Chi2 contribution: ${p.contrib}`}</p><p style="color:#991b1b;font-size:11px;font-family:monospace;font-weight:700;margin:0">${lang==="es"?"ACCION: Filtra registros que empiecen con digito":"ACTION: Filter records starting with digit"} ${p.digit}</p></div>`).join("")}
  </div>`:""} 
  <div class="sec"><h2>${lang==="es"?"Aviso legal":"Legal notice"}</h2>
    <div class="disc">⚠️ ${lang==="es"?"Este reporte es estadístico e indicativo. No constituye dictamen pericial, auditoría certificada ni prueba legal. FraudRadar no asume responsabilidad por decisiones tomadas con base en este análisis.":"This report is statistical and indicative. It does not constitute an expert opinion, certified audit, or legal proof. FraudRadar assumes no responsibility for decisions made based on this analysis."}</div>
  </div>
  <div class="foot"><span>FraudRadar · fraudradar.io</span><span>${lang==="es"?"Análisis forense · Nivel institucional":"Forensic analysis · Institutional grade"}</span></div>
  </body></html>`;
  const blob=new Blob([html],{type:"text/html"});
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");a.href=url;
  a.download=`FraudRadar_${(filename||"reporte").replace(/\.[^.]+$/,"")}_${Date.now()}.html`;
  a.click();setTimeout(()=>URL.revokeObjectURL(url),3000);
}

// ── THINKING ─────────────────────────────────────────────────
const PHASES_ES=["Leyendo registros...","Procesando dataset...","Ejecutando motor forense...","Validando patrones...","Aplicando umbrales institucionales...","Evaluando consistencia...","Generando veredicto..."];
const PHASES_EN=["Reading records...","Processing dataset...","Running forensic engine...","Validating patterns...","Applying institutional thresholds...","Evaluating consistency...","Generating verdict..."];
const ICONS=["📂","⚙️","🔬","📐","🏛️","📊","📋"];
const DUR=[7,8,9,9,10,9,8];
const TOTAL=60000;

function ThinkingScreen({onDone,lang}){
  const[idx,setIdx]=useState(0);const[pct,setPct]=useState(0);const[dots,setDots]=useState(".");
  const start=useRef(Date.now());
  const phases=lang==="es"?PHASES_ES:PHASES_EN;
  useEffect(()=>{
    const t=setInterval(()=>{
      const el=Date.now()-start.current;
      setPct(Math.min((el/TOTAL)*100,99));
      let acc=0;for(let i=0;i<DUR.length;i++){acc+=DUR[i]*1000;if(el<acc){setIdx(i);break;}}
      setDots(d=>d.length>=3?".":d+".");
      if(el>=TOTAL){clearInterval(t);setPct(100);setTimeout(onDone,400);}
    },400);
    return()=>clearInterval(t);
  },[onDone]);
  const ph=Math.min(idx,phases.length-1);
  return(
    <div style={{...dark,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",padding:"32px 16px",minHeight:"100vh"}}><style>{G}</style>
    <div style={{position:"relative",width:108,height:108,marginBottom:30}}>
      <div style={{position:"absolute",inset:0,border:"2px solid #1e293b",borderRadius:"50%"}}/>
      <div style={{position:"absolute",inset:5,border:"2.5px solid transparent",borderTopColor:"#3b82f6",borderRadius:"50%"}} className="spin"/>
      <div style={{position:"absolute",inset:16,border:"1.5px solid transparent",borderTopColor:"#6366f1",borderRadius:"50%",animation:"spin 2s linear infinite reverse"}}/>
      <div style={{position:"absolute",inset:0,display:"flex",alignItems:"center",justifyContent:"center",fontSize:26}}>{ICONS[ph]}</div>
    </div>
    <div key={idx} className="fade" style={{textAlign:"center",marginBottom:24,maxWidth:320}}>
      <p style={{color:"#f1f5f9",fontFamily:"'Syne',sans-serif",fontWeight:800,fontSize:17,margin:"0 0 5px"}}>{phases[ph]}{dots}</p>
    </div>
    <div style={{width:"100%",maxWidth:340,marginBottom:8}}>
      <div style={{background:"#0f172a",borderRadius:100,height:5,overflow:"hidden",border:"1px solid #1e293b"}}>
        <div style={{height:"100%",borderRadius:100,background:"linear-gradient(90deg,#3b82f6,#6366f1)",width:`${pct}%`,transition:"width .4s"}}/>
      </div>
      <div style={{display:"flex",justifyContent:"space-between",marginTop:5}}>
        <span style={{color:"#334155",fontSize:10,fontFamily:"monospace"}}>{Math.round(pct)}%</span>
        <span style={{color:"#334155",fontSize:10,fontFamily:"monospace"}}>{lang==="es"?"Fase":"Phase"} {idx+1}/7</span>
      </div>
    </div>
    <div style={{width:"100%",maxWidth:340,marginTop:14,display:"flex",flexDirection:"column",gap:5}}>
      {phases.map((p,i)=>(
        <div key={i} style={{display:"flex",alignItems:"center",gap:10,padding:"7px 11px",borderRadius:8,background:i===idx?"#0f172a":"transparent",border:`1px solid ${i===idx?"#1e293b":"transparent"}`,opacity:i>idx?0.18:1,transition:"all .3s"}}>
          <span style={{fontSize:11,color:i<idx?"#4ade80":i===idx?"#f1f5f9":"#334155",minWidth:14}}>{i<idx?"✓":i===idx?"›":"○"}</span>
          <span style={{fontSize:11,color:i<idx?"#4ade80":i===idx?"#f1f5f9":"#334155",fontFamily:"monospace"}}>{p}</span>
        </div>
      ))}
    </div>
    <p style={{color:"#1e293b",fontSize:11,marginTop:20}}>{lang==="es"?"Análisis en proceso · No cerrar":"Analysis in progress · Do not close"}</p>
    </div>
  );
}


// ── STRIPE PAYMENT FORM ───────────────────────────────────────
function StripePaymentForm({lang,onSuccess,onBack,onShowTerms}){
  const stripe=useStripe();
  const elements=useElements();
  const[name,setName]=useState("");
  const[loading,setLoading]=useState(false);
  const[error,setError]=useState("");

  const handlePay=async()=>{
    if(!stripe||!elements){setError(lang==="es"?"Stripe no está listo. Recarga la página.":"Stripe not ready. Please reload.");return;}
    if(!name.trim()){setError(lang==="es"?"Ingresa tu nombre.":"Please enter your name.");return;}
    setLoading(true);setError("");
    try{
      // 1. Create PaymentIntent on backend
      const res=await fetch("/api/create-payment",{method:"POST",headers:{"Content-Type":"application/json"}});
      if(!res.ok)throw new Error(lang==="es"?"Error del servidor. Intenta de nuevo.":"Server error. Please try again.");
      const{clientSecret,error:beErr}=await res.json();
      if(beErr)throw new Error(beErr);
      // 2. Confirm card payment with Stripe
      const{error:stripeErr,paymentIntent}=await stripe.confirmCardPayment(clientSecret,{
        payment_method:{
          card:elements.getElement(CardElement),
          billing_details:{name},
        },
      });
      if(stripeErr)throw new Error(stripeErr.message);
      if(paymentIntent.status==="succeeded")onSuccess();
    }catch(e){
      setError(e.message||lang==="es"?"Error al procesar el pago.":"Payment processing error.");
    }finally{
      setLoading(false);
    }
  };

  return(
    <>
      <button onClick={onBack} style={{background:"none",border:"none",color:"#475569",cursor:"pointer",fontSize:13,padding:"0 0 15px",display:"flex",alignItems:"center",gap:6}}>{lang==="es"?"← Volver":"← Back"}</button>
      <div style={{display:"flex",gap:6,marginBottom:14,flexWrap:"wrap"}}>
        {["🔒 SSL 256-bit","✓ Stripe Verified","🛡 "+(lang==="es"?"Datos no almacenados":"Data not stored")].map(b=>(
          <span key={b} style={{background:"#0d1117",border:"1px solid #1e293b",borderRadius:5,padding:"4px 9px",color:"#475569",fontSize:10,fontFamily:"monospace"}}>{b}</span>
        ))}
      </div>
      <h2 style={{fontFamily:"'Syne',sans-serif",color:"#f1f5f9",fontSize:20,fontWeight:800,margin:"0 0 4px"}}>{lang==="es"?"Datos de pago":"Payment details"}</h2>
      <p style={{color:"#475569",fontSize:13,margin:"0 0 18px"}}>{lang==="es"?"Procesado de forma segura por Stripe":"Securely processed by Stripe"}</p>

      {/* Card visual deco */}
      <div style={{background:"linear-gradient(135deg,#1e3a5f,#0f172a)",borderRadius:13,padding:"18px",marginBottom:18,border:"1px solid #1e293b"}}>
        <div style={{display:"flex",justifyContent:"space-between",marginBottom:13}}>
          <span style={{fontSize:11,color:"#94a3b8",letterSpacing:2,fontFamily:"monospace"}}>FRAUDRADAR</span>
          <div style={{display:"flex",gap:4}}>{["VISA","MC","AMEX"].map(c=><span key={c} style={{fontSize:9,background:"#1e293b",borderRadius:3,padding:"2px 5px",color:"#64748b"}}>{c}</span>)}</div>
        </div>
        <p style={{color:"#334155",fontSize:15,fontFamily:"monospace",margin:"0 0 11px",letterSpacing:3}}>•••• •••• •••• ••••</p>
        <div style={{display:"flex",justifyContent:"space-between"}}>
          <span style={{color:name?"#94a3b8":"#334155",fontSize:11,fontFamily:"monospace"}}>{name.toUpperCase()||"TITULAR"}</span>
          <span style={{color:"#334155",fontSize:11,fontFamily:"monospace"}}>MM/AA</span>
        </div>
      </div>

      {/* Name field */}
      <div style={{marginBottom:12}}>
        <label style={{color:"#64748b",fontSize:10,letterSpacing:1.5,textTransform:"uppercase",display:"block",marginBottom:5,fontFamily:"monospace"}}>{lang==="es"?"Nombre en la tarjeta":"Name on card"}</label>
        <input value={name} onChange={e=>setName(e.target.value)} placeholder={lang==="es"?"Juan Pérez":"John Smith"} style={{background:"#0f172a",border:"1.5px solid #1e293b",borderRadius:8,color:"#f1f5f9",fontFamily:"inherit",fontSize:14,padding:"11px 13px",width:"100%",outline:"none",boxSizing:"border-box"}}/>
      </div>

      {/* Stripe CardElement */}
      <div style={{marginBottom:16}}>
        <label style={{color:"#64748b",fontSize:10,letterSpacing:1.5,textTransform:"uppercase",display:"block",marginBottom:5,fontFamily:"monospace"}}>{lang==="es"?"Tarjeta de crédito o débito":"Credit or debit card"}</label>
        <div style={{background:"#0f172a",border:"1.5px solid #1e293b",borderRadius:8,padding:"13px 14px"}}>
          <CardElement options={{
            style:{
              base:{color:"#f1f5f9",fontFamily:"'DM Sans',sans-serif",fontSize:"15px",fontSmoothing:"antialiased","::placeholder":{color:"#334155"}},
              invalid:{color:"#ef4444"},
            },
            hidePostalCode:true,
          }}/>
        </div>
      </div>

      {error&&<p style={{color:"#ef4444",fontSize:13,margin:"0 0 12px",lineHeight:1.4}}>{error}</p>}

      <div style={{padding:"11px 13px",background:"#0d1117",border:"1px solid #1e293b",borderRadius:8,display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
        <div><p style={{color:"#94a3b8",fontSize:13,margin:"0 0 2px"}}>{lang==="es"?"Análisis Forense Completo":"Complete Forensic Analysis"}</p><p style={{color:"#475569",fontSize:11,margin:0}}>{lang==="es"?"Incluye reporte PDF":"Includes PDF report"}</p></div>
        <span style={{color:"#f1f5f9",fontFamily:"'Syne',sans-serif",fontWeight:800,fontSize:18}}>$5.00 USD</span>
      </div>

      <div style={{background:"#0d1117",border:"1px solid #22c55e22",borderRadius:8,padding:"8px 11px",marginBottom:13,display:"flex",gap:6,alignItems:"center"}}>
        <span>🛡</span><p style={{color:"#4ade80",fontSize:12,margin:0}}>{lang==="es"?"Si el análisis falla técnicamente, te devolvemos el cobro.":"If the analysis fails technically, we'll refund your payment."}</p>
      </div>

      <button onClick={handlePay} disabled={loading||!stripe} style={{width:"100%",background:loading?"#1e293b":"#2563eb",color:"#fff",border:"none",borderRadius:12,padding:"14px",fontSize:15,fontWeight:700,cursor:loading||!stripe?"not-allowed":"pointer",fontFamily:"inherit",display:"flex",alignItems:"center",justifyContent:"center",gap:9,transition:"background .2s"}}>
        {loading?<><div style={{width:15,height:15,border:"2px solid #334155",borderTopColor:"#fff",borderRadius:"50%",animation:"spin 1s linear infinite"}}/>{lang==="es"?"Procesando...":"Processing..."}</>:`🔒 ${lang==="es"?"Pagar $5.00 USD":"Pay $5.00 USD"}`}
      </button>

      <div style={{display:"flex",alignItems:"center",justifyContent:"center",gap:6,marginTop:9,marginBottom:11}}>
        <span style={{fontSize:12}}>⚡</span>
        <span style={{color:"#334155",fontSize:11}}>{lang==="es"?"Encriptado SSL 256-bit · Procesado por Stripe":"256-bit SSL · Powered by Stripe"}</span>
      </div>
      <p style={{color:"#334155",fontSize:11,textAlign:"center",margin:0}}>
        {lang==="es"?"Al pagar aceptas nuestros":"By paying you accept our"}{" "}
        <button onClick={onShowTerms} style={{background:"none",border:"none",color:"#3b82f6",fontSize:11,cursor:"pointer",textDecoration:"underline",fontFamily:"inherit",padding:0}}>{lang==="es"?"Términos":"Terms"}</button>
      </p>
    </>
  );
}

// ── MAIN APP ──────────────────────────────────────────────────
export default function App(){
  const[lang,setLang]=useState("es");
  const[step,setStep]=useState("upload");
  const[numbers,setNumbers]=useState([]);
  const[filename,setFilename]=useState("");
  const[selected,setSelected]=useState(null);
  const[reqOpen,setReqOpen]=useState(false);
  const[writtenOpen,setWrittenOpen]=useState(false);
  const[faqOpen,setFaqOpen]=useState(null);
  const[showTerms,setShowTerms]=useState(false);
  const[cardName,setCardName]=useState("");
  
  const[exp,setExp]=useState("");
  const[cvv,setCvv]=useState("");
  const[paying,setPaying]=useState(false);
  const[paid,setPaid]=useState(false);
  const[scrolled,setScrolled]=useState(false);
  const[checked,setChecked]=useState(false);
  const[shake,setShake]=useState(false);
  const[pdfLoading,setPdfLoading]=useState(false);
  const[pdfDone,setPdfDone]=useState(false);
  const[error,setError]=useState("");
  const scrollRef=useRef(null);
  const fileRef=useRef(null);
  const onDone=useCallback(()=>setStep("result"),[]);

  const analysis=useMemo(()=>numbers.length>=30?_analyze(numbers):{dist:Array(9).fill(0),valid:0,score:0,chiParts:[],clusters:[],anomalous:[],pApprox:">0.05",pattern:"none",byDigit:[]},[numbers]);
  const{dist,valid,score,chiParts,clusters,anomalous,pApprox,pattern}=analysis;
  const verdict=_verdict(score);
  const vLabel=score<15.5?(lang==="es"?"SIN ANOMALÍAS":"NO ANOMALIES"):score<25?(lang==="es"?"REVISAR":"REVIEW"):(lang==="es"?"ALERTA":"ALERT");
  const vLong=score<15.5?(lang==="es"?"Patrones consistentes con datos orgánicos":"Patterns consistent with organic data"):score<25?(lang==="es"?"Desviaciones moderadas detectadas":"Moderate deviations detected"):(lang==="es"?"Alta anomalía estadística detectada":"High statistical anomaly detected");

  const choose=(type)=>{
    setSelected(type);
    setNumbers(SAMPLES[type]);
    setFilename(type==="fraud"?(lang==="es"?"ventas_2024.csv":"sales_2024.csv"):(lang==="es"?"transacciones.csv":"transactions.csv"));
    setStep("preview");
  };

  const handleFile=(f)=>{
    if(!f)return;setError("");
    const r=new FileReader();
    r.onload=e=>{
      const nums=e.target.result.split(/[\n,;\s\t]+/).map(s=>parseFloat(s.replace(/[^0-9.-]/g,""))).filter(n=>!isNaN(n)&&n>0);
      if(nums.length<30){setError(lang==="es"?"Mínimo 30 valores numéricos.":"Minimum 30 numeric values.");return;}
      setNumbers(nums);setFilename(f.name);setStep("preview");
    };
    r.readAsText(f);
  };

  // Stripe payment handled by StripePaymentForm component
  const onPaymentSuccess=useCallback(()=>{
    setPaid(true);
    setTimeout(()=>setStep("thinking"),900);
  },[]);

  const handleScroll=()=>{
    const el=scrollRef.current;
    if(el&&el.scrollTop+el.clientHeight>=el.scrollHeight-30)setScrolled(true);
  };

  const tryAccept=()=>{
    if(!checked){setShake(true);setTimeout(()=>setShake(false),500);return;}
    setStep("paying");
  };

  const handlePDF=()=>{
    setPdfLoading(true);
    setTimeout(()=>{makePDF(dist,score,valid,verdict,filename,lang,chiParts,anomalous,clusters,pApprox,pattern);setPdfLoading(false);setPdfDone(true);setTimeout(()=>setPdfDone(false),3000);},600);
  };

  const reset=()=>{setStep("upload");setNumbers([]);setFilename("");setSelected(null);setPaying(false);setPaid(false);setScrolled(false);setChecked(false);setPdfDone(false);setError("");};

  const STEPS=[["upload","Landing"],["preview","Preview"],["terms","Términos"],["paying","Pago"],["thinking","Análisis"],["result","Resultado"]];

  // ── THINKING ──
  if(step==="thinking") return <ThinkingScreen onDone={onDone} lang={lang}/>;

  return(
    <div style={{background:"#080c14",minHeight:"100vh"}}>
      <style>{G}</style>
      {showTerms&&<TermsModal onClose={()=>setShowTerms(false)} lang={lang}/>}
      <NavBar lang={lang} setLang={setLang}/>

      {/* Step indicator */}
      <div style={{position:"fixed",bottom:10,left:"50%",transform:"translateX(-50%)",zIndex:200,display:"flex",gap:5,background:"#0f172a",border:"1px solid #1e293b",borderRadius:100,padding:"5px 10px"}}>
        {STEPS.map(([s,label])=>(
          <div key={s} style={{display:"flex",alignItems:"center",gap:3,opacity:step===s?1:0.22}}>
            <div style={{width:5,height:5,borderRadius:"50%",background:step===s?"#3b82f6":"#334155"}}/>
            <span style={{fontSize:8,color:step===s?"#94a3b8":"#475569",fontFamily:"monospace"}}>{label}</span>
          </div>
        ))}
      </div>

      {/* ═══ UPLOAD ═══ */}
      {step==="upload"&&(
        <div style={{paddingTop:60,paddingBottom:80}}>
          {/* Hero */}
          <div className="desktop-hero" style={{background:"linear-gradient(180deg,#0a1020,#080c14)",borderBottom:"1px solid #1e293b",padding:"40px 16px 36px"}}>
            <div style={W}>
              <div style={{textAlign:"center",marginBottom:20}}>
                <div style={{display:"flex",justifyContent:"center",marginBottom:14}}>
                  <LogoHero/>
                </div>
                <p style={{color:"#3b82f6",fontSize:10,letterSpacing:3,textTransform:"uppercase",margin:"0 0 12px",fontFamily:"monospace"}}>{lang==="es"?"Detección de fraudes y manipulación de datos":"Fraud & data manipulation detection"}</p>
                <h1 style={{fontFamily:"'Syne',sans-serif",fontSize:"clamp(26px,7vw,40px)",fontWeight:800,color:"#f1f5f9",margin:"0 0 4px",lineHeight:1.08}}>
                  {lang==="es"?<>¿Tus números<br/><span style={{color:"#3b82f6"}}>dicen la verdad?</span></>:<>Are your numbers<br/><span style={{color:"#3b82f6"}}>telling the truth?</span></>}
                </h1>
                <p style={{color:"#64748b",fontSize:13,margin:"14px auto 22px",lineHeight:1.7,maxWidth:330}}>
                  {lang==="es"?"Tecnología forense utilizada por la SEC, el IRS y el SAT para detectar irregularidades — ahora disponible para cualquier empresa.":"Forensic technology used by the SEC, IRS, and SAT to detect irregularities — now available to any business."}
                </p>
                <button onClick={()=>document.getElementById("upload-sec")?.scrollIntoView({behavior:"smooth"})} style={{background:"linear-gradient(135deg,#1d4ed8,#6366f1)",color:"#fff",border:"none",borderRadius:12,padding:"13px 26px",fontSize:14,fontWeight:700,cursor:"pointer",fontFamily:"inherit",marginBottom:10,display:"inline-flex",alignItems:"center",gap:8,boxShadow:"0 8px 28px #3b82f628"}}>
                  {lang==="es"?"Analizar mis datos →":"Analyze my data →"}
                </button>
                <p style={{color:"#334155",fontSize:11,margin:0,fontFamily:"monospace"}}>{PRICE} · {lang==="es"?"Reporte PDF incluido · Sin suscripción":"PDF report included · No subscription"}</p>
              </div>
              {/* Trust badges */}
              <div style={{display:"flex",gap:6,justifyContent:"center",flexWrap:"wrap"}}>
                {["🔒 SSL 256-bit","✓ Stripe Verified","🛡 "+(lang==="es"?"Datos no almacenados":"Data not stored")].map(b=><span key={b} style={{background:"#0f172a",border:"1px solid #1e293b",borderRadius:6,padding:"4px 10px",color:"#475569",fontSize:10,fontFamily:"monospace"}}>{b}</span>)}
              </div>
            </div>
          </div>

          <div className="dsk-main" style={{...W,paddingTop:0}}>
            {/* How it works */}
            <div className="dsk-full" style={{padding:"28px 0 20px",gridColumn:"1/-1"}}>
              <p style={{color:"#475569",fontSize:10,letterSpacing:3,textTransform:"uppercase",textAlign:"center",margin:"0 0 18px",fontFamily:"monospace"}}>{lang==="es"?"Cómo funciona":"How it works"}</p>
              {[[lang==="es"?"Sube tus datos":"Upload your data",lang==="es"?"CSV, TXT o pega los montos directamente. Facturación, nómina, gastos.":"CSV, TXT or paste amounts directly. Billing, payroll, expenses.","📂","01"],
                [lang==="es"?"Motor de análisis":"Forensic engine",lang==="es"?"Metodología estadística de nivel institucional, validada internacionalmente.":"Institutional-grade statistical methodology, internationally validated.","🔬","02"],
                [lang==="es"?"Veredicto + Reporte":"Verdict + Report",lang==="es"?"Veredicto claro y reporte PDF listo para presentar en menos de un minuto.":"Clear verdict and PDF report ready to present in under a minute.","📋","03"]
              ].map(([title,desc,icon,num])=>(
                <div key={num} style={{background:"#0d1117",border:"1px solid #1e293b",borderRadius:12,padding:"14px",display:"flex",gap:12,alignItems:"flex-start",marginBottom:10}}>
                  <div style={{width:34,height:34,background:"#172033",borderRadius:7,display:"flex",alignItems:"center",justifyContent:"center",fontSize:17,flexShrink:0}}>{icon}</div>
                  <div>
                    <div style={{display:"flex",alignItems:"center",gap:7,marginBottom:3}}>
                      <span style={{color:"#3b82f6",fontSize:9,fontFamily:"monospace"}}>{num}</span>
                      <p style={{color:"#f1f5f9",fontWeight:600,fontSize:13,margin:0}}>{title}</p>
                    </div>
                    <p style={{color:"#64748b",fontSize:12,lineHeight:1.55,margin:0}}>{desc}</p>
                  </div>
                </div>
              ))}
            </div>

            {/* Institutions */}
            <div className="dsk-full" style={{background:"#0d1117",border:"1px solid #1e293b",borderRadius:13,padding:"18px",marginBottom:18}}>
              <p style={{color:"#475569",fontSize:10,letterSpacing:3,textTransform:"uppercase",margin:"0 0 5px",fontFamily:"monospace"}}>{lang==="es"?"Metodología utilizada por":"Methodology used by"}</p>
              <p style={{color:"#334155",fontSize:12,margin:"0 0 14px",lineHeight:1.5}}>{lang==="es"?"La misma técnica forense que usan los reguladores y auditores más exigentes del mundo.":"The same forensic technique used by the world's most demanding regulators and auditors."}</p>
              <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:7}}>
                {[["SEC","US Securities"],["IRS","US Tax"],["SAT","México"],["Deloitte","Big 4"],["KPMG","Big 4"],["PwC","Big 4"]].map(([n,s])=>(
                  <div key={n} style={{background:"#080c14",borderRadius:7,padding:"9px 7px",textAlign:"center",border:"1px solid #1e293b"}}>
                    <p style={{color:"#94a3b8",fontWeight:700,fontSize:12,margin:"0 0 2px",fontFamily:"'Syne',sans-serif"}}>{n}</p>
                    <p style={{color:"#334155",fontSize:9,margin:0,fontFamily:"monospace"}}>{s}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Use cases */}
            <div style={{marginBottom:18}}>
              <p style={{color:"#475569",fontSize:10,letterSpacing:3,textTransform:"uppercase",margin:"0 0 12px",fontFamily:"monospace"}}>{lang==="es"?"¿Para qué tipo de datos?":"What kind of data?"}</p>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
                {[["💼",lang==="es"?"Ventas":"Sales",lang==="es"?"Montos de ventas y facturas":"Sales amounts and invoices"],["👥",lang==="es"?"Nómina":"Payroll",lang==="es"?"Pagos a empleados y gastos":"Employee payments and expenses"],["📦",lang==="es"?"Inventarios":"Inventory",lang==="es"?"Valuaciones y movimientos":"Valuations and movements"],["🏦",lang==="es"?"Transacciones":"Transactions",lang==="es"?"Extractos bancarios":"Bank statements"],["📋",lang==="es"?"Presupuesto":"Budget",lang==="es"?"Ejecución presupuestal":"Budget execution"],["🤝",lang==="es"?"Proveedores":"Vendors",lang==="es"?"Cuentas por pagar":"Accounts payable"]].map(([ic,title,desc])=>(
                  <div key={title} style={{background:"#0d1117",border:"1px solid #1e293b",borderRadius:9,padding:"11px"}}>
                    <span style={{fontSize:18,display:"block",marginBottom:5}}>{ic}</span>
                    <p style={{color:"#f1f5f9",fontWeight:600,fontSize:12,margin:"0 0 3px"}}>{title}</p>
                    <p style={{color:"#475569",fontSize:11,lineHeight:1.4,margin:0}}>{desc}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Written summary toggle */}
            <div className="dsk-full" style={{background:"#0d1117",border:"1px solid #1e293b",borderRadius:13,overflow:"hidden",marginBottom:16}}>
              <div style={{position:"relative",background:"linear-gradient(135deg,#060d1a,#0d1829)",aspectRatio:"16/9",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center"}}>
                <div style={{width:54,height:54,background:"linear-gradient(135deg,#1d4ed8,#6366f1)",borderRadius:"50%",display:"flex",alignItems:"center",justifyContent:"center",fontSize:22,marginBottom:12,animation:"pulse 2s ease infinite",boxShadow:"0 0 32px #3b82f640"}}>▶</div>
                <p style={{color:"#f1f5f9",fontSize:14,fontWeight:700,margin:"0 0 4px",fontFamily:"'Syne',sans-serif"}}>{lang==="es"?"¿Cómo funciona?":"How does it work?"}</p>
                <p style={{color:"#475569",fontSize:11,margin:"0 0 10px"}}>{lang==="es"?"Explicación completa · 2 min 30 seg":"Full explanation · 2 min 30 sec"}</p>
                <div style={{background:"#1e293b",borderRadius:7,padding:"5px 12px"}}><span style={{color:"#64748b",fontSize:11,fontFamily:"monospace"}}>📹 {lang==="es"?"Video próximamente":"Video coming soon"}</span></div>
                <div style={{position:"absolute",bottom:8,right:8,background:"#000a",borderRadius:4,padding:"2px 7px"}}><span style={{color:"#f1f5f9",fontSize:10,fontFamily:"monospace"}}>2:30</span></div>
              </div>
              <div onClick={()=>setWrittenOpen(o=>!o)} style={{padding:"11px 15px",display:"flex",alignItems:"center",justifyContent:"space-between",cursor:"pointer",borderTop:"1px solid #1e293b"}}>
                <span style={{color:"#64748b",fontSize:12}}>{lang==="es"?"Ver resumen escrito":"Read written summary"}</span>
                <span style={{color:"#334155",fontSize:14,transform:writtenOpen?"rotate(180deg)":"none",transition:"transform .3s"}}>⌄</span>
              </div>
              {writtenOpen&&(
                <div style={{borderTop:"1px solid #1e293b",padding:"14px 15px",display:"flex",flexDirection:"column",gap:13}} className="fade">
                  {[["🔒",lang==="es"?"Motor forense propietario":"Proprietary forensic engine",lang==="es"?"Metodología estadística de nivel institucional, la misma utilizada por reguladores financieros internacionales.":"Institutional-grade statistical methodology, the same used by international financial regulators."],["🏛️",lang==="es"?"Validado internacionalmente":"Internationally validated",lang==="es"?"Empleada por la SEC, el IRS, el SAT de México y las principales firmas de auditoría forense del mundo.":"Used by the SEC, IRS, Mexico's SAT, and leading forensic audit firms worldwide for decades."],["⚡",lang==="es"?"Resultados en menos de un minuto":"Results in under a minute",lang==="es"?"Veredicto claro con reporte PDF profesional, listo para presentar a socios, directivos o auditores.":"Clear verdict with professional PDF report, ready to present to partners, executives, or auditors."]].map(([ic,title,desc])=>(
                    <div key={title} style={{display:"flex",gap:11}}>
                      <div style={{width:28,height:28,background:"#172033",borderRadius:6,display:"flex",alignItems:"center",justifyContent:"center",fontSize:14,flexShrink:0}}>{ic}</div>
                      <div><p style={{color:"#f1f5f9",fontWeight:600,fontSize:13,margin:"0 0 3px"}}>{title}</p><p style={{color:"#64748b",fontSize:12,lineHeight:1.55,margin:0}}>{desc}</p></div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Upload section */}
            <div id="upload-sec" className="dsk-full">
              <p style={{color:"#475569",fontSize:10,letterSpacing:3,textTransform:"uppercase",margin:"0 0 12px",fontFamily:"monospace"}}>{lang==="es"?"Analiza tus datos ahora":"Analyze your data now"}</p>

              {/* Plan card */}
              <div style={{background:"linear-gradient(135deg,#0d1829,#0f172a)",border:"1px solid #3b82f633",borderRadius:13,padding:"16px",marginBottom:13}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:11}}>
                  <div>
                    <p style={{color:"#f1f5f9",fontFamily:"'Syne',sans-serif",fontWeight:800,fontSize:15,margin:"0 0 2px"}}>{lang==="es"?"Un solo plan. Todo incluido.":"One plan. Everything included."}</p>
                    <p style={{color:"#475569",fontSize:11,margin:0,fontFamily:"monospace"}}>{lang==="es"?"Pago único · Sin suscripción":"One-time payment · No subscription"}</p>
                  </div>
                  <p style={{color:"#3b82f6",fontFamily:"'Syne',sans-serif",fontWeight:800,fontSize:22,margin:0,flexShrink:0}}>$5.00 USD</p>
                </div>
                <div style={{display:"flex",flexDirection:"column",gap:4}}>
                  {(lang==="es"?["Análisis forense de tu conjunto de datos","Veredicto claro: Sin anomalías / Revisar / Alerta","Índice de riesgo estadístico","Interpretación profesional del resultado","Reporte PDF descargable listo para presentar","Sección de próximos pasos según el veredicto","Válido para cualquier moneda y país"]:["Forensic analysis of your dataset","Clear verdict: No Anomalies / Review / Alert","Statistical risk index","Professional interpretation of results","Downloadable PDF report ready to present","Next steps section based on your verdict","Valid for any currency and country"]).map(f=>(
                    <div key={f} style={{display:"flex",gap:7,alignItems:"center"}}>
                      <span style={{color:"#22c55e",fontSize:11,flexShrink:0}}>✓</span>
                      <span style={{color:"#94a3b8",fontSize:12}}>{f}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* File requirements */}
              <div style={{background:"#0d1117",border:"1px solid #3b82f633",borderRadius:13,overflow:"hidden",marginBottom:13}}>
                <div onClick={()=>setReqOpen(o=>!o)} style={{padding:"11px 15px",display:"flex",alignItems:"center",justifyContent:"space-between",cursor:"pointer"}}>
                  <div style={{display:"flex",alignItems:"center",gap:9}}>
                    <span style={{fontSize:15}}>📋</span>
                    <div>
                      <p style={{color:"#f1f5f9",fontWeight:600,fontSize:13,margin:0}}>{lang==="es"?"Requisitos del archivo":"File requirements"}</p>
                      <p style={{color:"#3b82f6",fontSize:10,margin:"2px 0 0",fontFamily:"monospace"}}>{lang==="es"?"Léeme antes de subir":"Read before uploading"}</p>
                    </div>
                  </div>
                  <span style={{color:"#334155",fontSize:14,transform:reqOpen?"rotate(180deg)":"none",transition:"transform .3s"}}>⌄</span>
                </div>
                {reqOpen&&(
                  <div style={{borderTop:"1px solid #1e293b",padding:"13px 15px",display:"flex",flexDirection:"column",gap:10}}>
                    {[["🔢",lang==="es"?"Cantidad":"Records",lang==="es"?[["✓","#f59e0b",lang==="es"?"Mínimo":"Min","30 values"],["✓","#22c55e","Óptimo","100–10,000"],["✓","#22c55e","Máx","50,000"],["✗","#ef4444","Rechazado","<30"]]:
                      [["✓","#f59e0b","Minimum","30 values"],["✓","#22c55e","Optimal","100–10,000"],["✓","#22c55e","Max","50,000"],["✗","#ef4444","Rejected","<30"]]],
                      ["📁",lang==="es"?"Formato":"Format",lang==="es"?[["✓","#22c55e","","CSV, TXT, texto pegado"],["✗","#ef4444","","Excel — convierte a CSV primero"],["✗","#ef4444","","PDF, imágenes, Word"]]:
                        [["✓","#22c55e","","CSV, TXT, pasted text"],["✗","#ef4444","","Excel — convert to CSV first"],["✗","#ef4444","","PDF, images, Word"]]],
                    ].map(([icon,label,rows])=>(
                      <div key={label} style={{background:"#080c14",borderRadius:9,padding:"11px 13px"}}>
                        <p style={{color:"#3b82f6",fontSize:10,letterSpacing:2,textTransform:"uppercase",margin:"0 0 7px",fontFamily:"monospace"}}>{icon} {label}</p>
                        {rows.map(([s,c,l,d])=>(
                          <div key={d} style={{display:"flex",gap:8,marginBottom:4}}>
                            <span style={{color:c,fontSize:11,flexShrink:0}}>{s}</span>
                            <p style={{color:"#64748b",fontSize:11,margin:0}}>{l?<strong style={{color:"#94a3b8"}}>{l} — </strong>:null}{d}</p>
                          </div>
                        ))}
                      </div>
                    ))}
                    {/* Example */}
                    <div style={{background:"#080c14",borderRadius:9,padding:"11px 13px"}}>
                      <p style={{color:"#3b82f6",fontSize:10,letterSpacing:2,textTransform:"uppercase",margin:"0 0 7px",fontFamily:"monospace"}}>📄 {lang==="es"?"Ejemplo correcto":"Correct example"}</p>
                      <div style={{background:"#060810",borderRadius:5,padding:"9px 11px",fontFamily:"monospace",fontSize:11,color:"#4ade80",lineHeight:2}}>
                        <div style={{color:"#475569"}}>{lang==="es"?"monto":"amount"}</div>
                        <div>1250.00</div><div>3400.50</div><div>985.00</div><div>12300.00</div>
                        <div style={{color:"#475569"}}>... (min 30 {lang==="es"?"filas":"rows"})</div>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Upload + file drop */}
              <div onClick={()=>fileRef.current?.click()} style={{border:"2px dashed #1e293b",borderRadius:13,padding:"28px 20px",textAlign:"center",cursor:"pointer",background:"#0d1117",marginBottom:13,transition:"border-color .2s"}} onMouseEnter={e=>e.currentTarget.style.borderColor="#334155"} onMouseLeave={e=>e.currentTarget.style.borderColor="#1e293b"} onDragOver={e=>{e.preventDefault();e.currentTarget.style.borderColor="#3b82f6"}} onDragLeave={e=>e.currentTarget.style.borderColor="#1e293b"} onDrop={e=>{e.preventDefault();handleFile(e.dataTransfer.files[0]);}}>
                <input ref={fileRef} type="file" accept=".csv,.txt" style={{display:"none"}} onChange={e=>handleFile(e.target.files[0])}/>
                <div style={{fontSize:36,marginBottom:10}}>📂</div>
                <p style={{color:"#f1f5f9",fontSize:15,fontWeight:600,margin:"0 0 5px"}}>{lang==="es"?"Sube tu archivo":"Upload your file"}</p>
                <p style={{color:"#475569",fontSize:12,margin:0}}>CSV, TXT — {lang==="es"?"arrastra o toca aquí":"drag or tap here"}</p>
              </div>

              {error&&<p style={{color:"#ef4444",fontSize:13,textAlign:"center",margin:"0 0 10px"}}>{error}</p>}

              {/* Demo */}
              <div style={{background:"#0d1117",border:"1px solid #334155",borderRadius:13,padding:"13px",marginBottom:13}}>
                <p style={{color:"#64748b",fontSize:10,letterSpacing:2,textTransform:"uppercase",margin:"0 0 10px",display:"flex",alignItems:"center",gap:7,fontFamily:"monospace"}}>
                  <span style={{background:"#1d4ed8",borderRadius:4,padding:"2px 6px",color:"#fff",fontSize:9}}>DEMO</span>
                  {lang==="es"?"Elige un dataset para probar":"Choose a dataset to test"}
                </p>
                <div style={{display:"flex",flexDirection:"column",gap:7}}>
                  {[["clean","📊",lang==="es"?"Datos limpios (ventas reales)":"Clean data (real sales)",lang==="es"?"50 registros · Resultado esperado: ✓ SIN ANOMALÍAS":"50 records · Expected: ✓ NO ANOMALIES","#22c55e33"],
                    ["fraud","🚨",lang==="es"?"Datos manipulados (fraude simulado)":"Manipulated data (simulated fraud)",lang==="es"?"50 registros · Resultado esperado: 🚨 ALERTA":"50 records · Expected: 🚨 ALERT","#ef444433"]
                  ].map(([type,ic,title,sub,bc])=>(
                    <button key={type} onClick={()=>choose(type)} style={{background:selected===type?`${bc}33`:"transparent",border:`1px solid ${selected===type?bc:"#1e293b"}`,borderRadius:9,padding:"11px 13px",cursor:"pointer",textAlign:"left",fontFamily:"inherit",transition:"all .2s",display:"flex",alignItems:"center",gap:11}}>
                      <span style={{fontSize:19}}>{ic}</span>
                      <div><p style={{color:"#f1f5f9",fontSize:13,fontWeight:600,margin:"0 0 2px"}}>{title}</p><p style={{color:"#475569",fontSize:11,margin:0}}>{sub}</p></div>
                    </button>
                  ))}
                </div>
              </div>

              {/* FAQ */}
              <div style={{border:"1px solid #1e293b",borderRadius:12,overflow:"hidden",marginBottom:13}}>
                <p style={{color:"#475569",fontSize:10,letterSpacing:2,textTransform:"uppercase",padding:"11px 14px 0",margin:0,fontFamily:"monospace"}}>{lang==="es"?"Preguntas frecuentes":"FAQ"}</p>
                {(lang==="es"?[["¿Mis datos son privados?","Sí. El análisis corre en tu navegador. Nunca subimos tus datos a ningún servidor."],["¿El resultado es una prueba legal?","No. Es análisis estadístico indicativo. Para procedimientos legales se requiere dictamen de contador certificado."],["¿Puedo pedir reembolso?","Sí, si el análisis falla técnicamente por error de la plataforma."],["¿Funciona para cualquier moneda?","Sí. El motor analiza valores numéricos independientemente de moneda o país."]]:
                  [["Is my data private?","Yes. Analysis runs in your browser. We never upload your data to any server."],["Is the result legal proof?","No. It's indicative statistical analysis. Legal proceedings require a certified accountant's report."],["Can I get a refund?","Yes, if the analysis fails technically due to a platform error."],["Does it work for any currency?","Yes. The engine analyzes numeric values regardless of currency or country."]]).map(([q,a],i)=>(
                  <div key={i} style={{borderTop:"1px solid #1e293b"}}>
                    <button onClick={()=>setFaqOpen(faqOpen===i?null:i)} style={{width:"100%",background:"none",border:"none",padding:"11px 14px",display:"flex",justifyContent:"space-between",alignItems:"center",cursor:"pointer",color:"#94a3b8",fontSize:13,fontFamily:"inherit",textAlign:"left",gap:8}}>
                      <span>{q}</span><span style={{flexShrink:0,color:"#334155",transform:faqOpen===i?"rotate(180deg)":"none",transition:"transform .2s"}}>⌄</span>
                    </button>
                    {faqOpen===i&&<p style={{color:"#475569",fontSize:12,lineHeight:1.6,margin:0,padding:"0 14px 11px"}}>{a}</p>}
                  </div>
                ))}
              </div>

              <div style={{background:"#0d1117",border:"1px solid #22c55e22",borderRadius:9,padding:"10px 13px",marginBottom:11,display:"flex",gap:7,alignItems:"center"}}>
                <span>🛡</span><p style={{color:"#4ade80",fontSize:12,margin:0}}>{lang==="es"?"Si el análisis falla técnicamente, te devolvemos el cobro.":"If the analysis fails technically, we'll refund your payment."}</p>
              </div>
              <div style={{textAlign:"center",marginBottom:6}}>
                <button onClick={()=>setShowTerms(true)} style={{background:"none",border:"none",color:"#334155",fontSize:10,cursor:"pointer",textDecoration:"underline",fontFamily:"monospace"}}>{lang==="es"?"Términos · Condiciones · Política de Reembolso":"Terms · Conditions · Refund Policy"}</button>
              </div>
            </div>
          </div>
          {/* Trust bar */}
          <div style={{background:"#060810",borderTop:"1px solid #1e293b",padding:"11px 16px",marginTop:20}}>
            <div style={{display:"flex",gap:14,justifyContent:"center",flexWrap:"wrap"}}>
              {["🔒 SSL 256-bit","✓ Stripe Verified","🛡 "+(lang==="es"?"Datos no almacenados":"Data not stored")].map(b=><span key={b} style={{color:"#334155",fontSize:10,fontFamily:"monospace"}}>{b}</span>)}
            </div>
          </div>
        </div>
      )}

      {/* ═══ PREVIEW ═══ */}
      {step==="preview"&&(
        <div style={{...dark,padding:"72px 0 48px"}} className="fade">
          <div style={W}>
            <button onClick={()=>setStep("upload")} style={{background:"none",border:"none",color:"#475569",cursor:"pointer",fontSize:13,padding:"0 0 18px",display:"flex",alignItems:"center",gap:6}}>{lang==="es"?"← Volver":"← Back"}</button>
            <div style={{background:"#0d1117",border:"1px solid #1e293b",borderRadius:13,padding:"18px",marginBottom:12}}>
              <div style={{display:"flex",alignItems:"center",gap:11,marginBottom:14}}>
                <div style={{background:"#172033",borderRadius:7,padding:"9px 10px",fontSize:17}}>📊</div>
                <div>
                  <p style={{color:"#f1f5f9",fontWeight:600,margin:"0 0 2px",fontSize:14}}>{filename}</p>
                  <p style={{color:"#475569",fontSize:12,margin:0}}>{numbers.length.toLocaleString()} {lang==="es"?"valores detectados":"values detected"}</p>
                </div>
              </div>
              <div style={{display:"flex",flexWrap:"wrap",gap:6,marginBottom:14}}>
                {numbers.slice(0,8).map((n,i)=><span key={i} style={{background:"#172033",color:"#93c5fd",borderRadius:5,padding:"3px 9px",fontSize:12,fontFamily:"monospace"}}>${n.toLocaleString(lang==="es"?"es-MX":"en-US")}</span>)}
                <span style={{color:"#475569",fontSize:12}}>+{numbers.length-8}...</span>
              </div>
              <div style={{padding:"11px 13px",background:"#080c14",borderRadius:8,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div><p style={{color:"#94a3b8",fontSize:13,margin:"0 0 2px"}}>{lang==="es"?"Análisis Forense Completo":"Complete Forensic Analysis"}</p><p style={{color:"#475569",fontSize:11,margin:0}}>{lang==="es"?"Veredicto + PDF + Próximos pasos":"Verdict + PDF + Next steps"}</p></div>
                <span style={{color:"#f1f5f9",fontFamily:"'Syne',sans-serif",fontWeight:800,fontSize:18}}>{PRICE}</span>
              </div>
            </div>
            <div style={{background:"#0d1117",border:"1px solid #22c55e33",borderRadius:9,padding:"9px 13px",marginBottom:14,display:"flex",gap:7}}>
              <span style={{color:"#4ade80"}}>✓</span>
              <p style={{color:"#4ade80",fontSize:12,margin:0}}>{lang==="es"?"Tus datos se procesan localmente. No se transmiten ni almacenan.":"Your data is processed locally. Never transmitted or stored."}</p>
            </div>
            <button onClick={()=>setStep("terms")} style={{width:"100%",background:"#f1f5f9",color:"#080c14",border:"none",borderRadius:12,padding:"14px",fontSize:15,fontWeight:700,cursor:"pointer",fontFamily:"inherit"}}>{lang==="es"?"Continuar →":"Continue →"}</button>
          </div>
        </div>
      )}

      {/* ═══ TERMS ═══ */}
      {step==="terms"&&(
        <div style={{...dark,display:"flex",flexDirection:"column",height:"100vh"}}>
          <div style={{background:"#0d1117",borderBottom:"1px solid #1e293b",padding:"13px 16px",display:"flex",alignItems:"center",gap:11,flexShrink:0}}>
            <button onClick={()=>setStep("preview")} style={{background:"#1e293b",border:"none",borderRadius:"50%",width:30,height:30,cursor:"pointer",color:"#94a3b8",fontSize:13,display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>←</button>
            <div style={{flex:1}}>
              <p style={{color:"#f1f5f9",fontFamily:"'Syne',sans-serif",fontWeight:800,fontSize:14,margin:0}}>{lang==="es"?"Términos y Deslinde Legal":"Terms & Legal Disclaimer"}</p>
              <p style={{color:"#475569",fontSize:10,margin:"2px 0 0",fontFamily:"monospace"}}>{lang==="es"?"Lee y acepta antes de pagar":"Read and accept before paying"}</p>
            </div>
            <div style={{background:scrolled?"#052e16":"#1e293b",border:`1px solid ${scrolled?"#22c55e44":"#334155"}`,borderRadius:100,padding:"4px 9px",transition:"all .3s",flexShrink:0}}>
              <span style={{color:scrolled?"#4ade80":"#475569",fontSize:10,fontFamily:"monospace"}}>{scrolled?(lang==="es"?"✓ Leído":"✓ Read"):(lang==="es"?"Desplázate ↓":"Scroll ↓")}</span>
            </div>
          </div>
          <div ref={scrollRef} onScroll={handleScroll} style={{flex:1,overflowY:"auto",padding:"13px",display:"flex",flexDirection:"column",gap:9}}>
            {[
              {n:"01",c:"#f59e0b",t:lang==="es"?"Naturaleza del servicio":"Nature of service",b:lang==="es"?"FraudRadar aplica metodología estadística forense de nivel institucional. El resultado es indicativo. No constituye dictamen pericial, auditoría certificada ni prueba legal.":"FraudRadar applies institutional-grade forensic statistical methodology. Results are indicative, not conclusive or legally binding.",w:lang==="es"?"NO es servicio de auditoría ni asesoría jurídica.":"NOT an auditing or legal advisory service."},
              {n:"02",c:"#f59e0b",t:lang==="es"?"Deslinde":"Disclaimer",bullets:lang==="es"?["'SIN ANOMALÍAS' no confirma ausencia de fraude","'ALERTA' no es prueba legal bajo ninguna legislación","El usuario es responsable de las decisiones tomadas","FraudRadar no asume responsabilidad por daños"]:["'NO ANOMALIES' does not confirm absence of fraud","'ALERT' is not legal proof under any jurisdiction","User is solely responsible for decisions made","FraudRadar assumes no liability for damages"]},
              {n:"03",c:"#f59e0b",t:lang==="es"?"Limitaciones":"Limitations",bullets:lang==="es"?["<30 registros — no significativo","Datos con rango restringido artificialmente","Números asignados secuencialmente","Porcentajes y tasas de interés","Precios psicológicos ($99, $999)"]:["<30 records — statistically insignificant","Artificially restricted range data","Sequentially assigned numbers","Percentages and interest rates","Psychological prices ($99, $999)"]},
              {n:"04",c:"#ef4444",t:lang==="es"?"Usos prohibidos":"Prohibited uses",bullets:lang==="es"?["Acusar o denunciar usando el resultado como única evidencia","Presentar como dictamen pericial ante SAT, FGR u otra autoridad","Extorsionar con los resultados","Uso en despidos sin auditoría formal"]:["Accusing individuals using result as sole evidence","Presenting as expert opinion before any authority","Extorting individuals with results","Use in dismissals without formal audit"]},
              {n:"05",c:"#22c55e",t:lang==="es"?"Reembolso":"Refund",refunds:lang==="es"?[["✓","Error técnico de la plataforma"],["✓","Cobro sin resultado por falla del servidor"],["✗","Desacuerdo con el resultado"],["✗","Archivo fuera de requisitos"],["✗","Más de 72 horas desde el análisis"]]:
                [["✓","Platform technical error"],["✓","Payment charged without result due to server failure"],["✗","Disagreement with the result"],["✗","File outside requirements"],["✗","More than 72 hours since analysis"]]},
              {n:"06",c:"#3b82f6",t:"Privacidad / Privacy",b:lang==="es"?"El análisis corre en tu navegador. Los datos numéricos no se transmiten. Solo datos de pago son procesados por Stripe Inc. bajo PCI-DSS.":"Analysis runs in your browser. Numeric data is not transmitted. Only payment data is processed by Stripe Inc. under PCI-DSS."},
              {n:"07",c:"#3b82f6",t:"Jurisdicción / Jurisdiction",b:lang==="es"?"Rigen las leyes de México. Las partes se someten a tribunales de la Ciudad de México.":"Governed by Mexican law. Parties submit to courts of Mexico City."},
            ].map(s=>(
              <div key={s.n} style={{background:"#0d1117",border:"1px solid #1e293b",borderRadius:9,padding:"11px"}}>
                <div style={{display:"flex",alignItems:"center",gap:7,marginBottom:7}}>
                  <span style={{background:s.c+"22",border:`1px solid ${s.c}33`,borderRadius:4,padding:"2px 6px",color:s.c,fontSize:10,fontFamily:"monospace",fontWeight:600}}>{s.n}</span>
                  <p style={{color:"#f1f5f9",fontWeight:600,fontSize:13,margin:0}}>{s.t}</p>
                </div>
                {s.b&&<p style={{color:"#64748b",fontSize:12,lineHeight:1.6,margin:0}}>{s.b}</p>}
                {s.w&&<div style={{background:"#2d0a0a",border:"1px solid #ef444422",borderRadius:6,padding:"6px 9px",marginTop:6}}><p style={{color:"#f87171",fontSize:11,margin:0}}>⚠ {s.w}</p></div>}
                {s.bullets&&<div style={{display:"flex",flexDirection:"column",gap:3}}>{s.bullets.map((b,i)=><div key={i} style={{display:"flex",gap:7}}><span style={{color:"#334155",fontSize:10,flexShrink:0,marginTop:2}}>→</span><p style={{color:"#64748b",fontSize:11,lineHeight:1.4,margin:0}}>{b}</p></div>)}</div>}
                {s.refunds&&<div style={{display:"flex",flexDirection:"column",gap:4}}>{s.refunds.map(([ic,d],i)=><div key={i} style={{display:"flex",gap:7,background:"#080c14",borderRadius:5,padding:"5px 7px"}}><span style={{color:ic==="✓"?"#22c55e":"#ef4444",fontSize:10,flexShrink:0}}>{ic}</span><p style={{color:"#64748b",fontSize:11,margin:0}}>{d}</p></div>)}</div>}
              </div>
            ))}
            {!scrolled&&<p style={{color:"#334155",fontSize:11,textAlign:"center",margin:"3px 0",fontFamily:"monospace"}}>{lang==="es"?"↓ Desplázate hasta el final":"↓ Scroll to the bottom"}</p>}
            <div style={{height:4}}/>
          </div>
          <div style={{background:"#0d1117",borderTop:"1px solid #1e293b",padding:"13px 16px",flexShrink:0}}>
            <div onClick={()=>scrolled&&setChecked(c=>!c)} className={shake?"shake":""} style={{display:"flex",alignItems:"flex-start",gap:11,marginBottom:11,cursor:scrolled?"pointer":"not-allowed",opacity:scrolled?1:0.38,transition:"opacity .3s"}}>
              <div style={{width:21,height:21,borderRadius:5,border:`2px solid ${checked?"#22c55e":"#334155"}`,background:checked?"#052e16":"transparent",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,marginTop:1,transition:"all .2s"}}>
                {checked&&<span style={{color:"#22c55e",fontSize:13,lineHeight:1}}>✓</span>}
              </div>
              <p style={{color:checked?"#94a3b8":"#64748b",fontSize:12,lineHeight:1.5,margin:0}}>{lang==="es"?"He leído, entendido y acepto los Términos, la Política de Reembolso y el Deslinde de Responsabilidad.":"I have read, understood, and accept the Terms, Refund Policy, and Disclaimer of Liability."}</p>
            </div>
            <button onClick={tryAccept} style={{width:"100%",background:checked?"#f1f5f9":"#1e293b",color:checked?"#080c14":"#475569",border:"none",borderRadius:12,padding:"13px",fontSize:14,fontWeight:700,cursor:checked?"pointer":"not-allowed",fontFamily:"inherit",transition:"all .25s"}}>
              {checked?(lang==="es"?"Aceptar y continuar al pago →":"Accept and continue to payment →"):(lang==="es"?"Acepta los términos para continuar":"Accept terms to continue")}
            </button>
            {!scrolled&&<p style={{color:"#334155",fontSize:10,textAlign:"center",margin:"7px 0 0",fontFamily:"monospace"}}>{lang==="es"?"Debes leer los términos completos":"You must read the full terms"}</p>}
          </div>
        </div>
      )}

      {/* ═══ PAYMENT ═══ */}
      {step==="paying"&&(
        <div style={{...dark,padding:"72px 0 48px"}} className="fade">
          <div style={W}>
            {!paid?(
              <Elements stripe={_stripePromise}>
                <StripePaymentForm
                  lang={lang}
                  onSuccess={onPaymentSuccess}
                  onBack={()=>setStep("terms")}
                  onShowTerms={()=>setShowTerms(true)}
                />
              </Elements>
            ):(
              <div style={{textAlign:"center",padding:"80px 0"}} className="fade">
                <div style={{width:60,height:60,background:"#052e16",border:"2px solid #22c55e",borderRadius:"50%",display:"flex",alignItems:"center",justifyContent:"center",margin:"0 auto 16px",fontSize:26}}>✓</div>
                <p style={{color:"#4ade80",fontSize:20,fontWeight:700,margin:"0 0 5px",fontFamily:"'Syne',sans-serif"}}>{lang==="es"?"¡Pago exitoso!":"Payment successful!"}</p>
                <p style={{color:"#475569",fontSize:13,margin:0}}>{lang==="es"?"Iniciando análisis forense...":"Launching forensic analysis..."}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ═══ RESULT ═══ */}
      {step==="result"&&(
        <div style={{...dark,padding:"72px 0 60px"}} className="fade desktop-result">
          <div style={W}>
            {/* Verdict */}
            <div className="dsk-result-full" style={{background:verdict.bg,border:`1.5px solid ${verdict.color}44`,borderRadius:15,padding:"18px",marginBottom:15,display:"flex",alignItems:"center",gap:14}}>
              <div style={{width:50,height:50,background:verdict.color+"22",border:`2px solid ${verdict.color}`,borderRadius:"50%",display:"flex",alignItems:"center",justifyContent:"center",fontSize:20,flexShrink:0}}>{verdict.icon}</div>
              <div>
                <p style={{color:verdict.color,fontFamily:"'Syne',sans-serif",fontWeight:800,fontSize:19,margin:"0 0 2px",letterSpacing:.5}}>{vLabel}</p>
                <p style={{color:verdict.color+"99",fontSize:12,margin:0}}>{vLong}</p>
              </div>
            </div>
            {/* Disclaimer */}
            <div className="dsk-result-full" style={{background:"#0d1117",border:"1px solid #f59e0b22",borderRadius:9,padding:"9px 12px",marginBottom:14,display:"flex",gap:7,alignItems:"flex-start"}}>
              <span style={{fontSize:13,flexShrink:0}}>⚠️</span>
              <p style={{color:"#94a3b8",fontSize:11,lineHeight:1.5,margin:0}}>
                {lang==="es"?"Este resultado es estadístico e indicativo. No constituye prueba legal.":"This result is statistical and indicative. Not legal proof."}{" "}
                <button onClick={()=>setShowTerms(true)} style={{background:"none",border:"none",color:"#3b82f6",fontSize:11,cursor:"pointer",textDecoration:"underline",fontFamily:"inherit",padding:0}}>{lang==="es"?"Ver términos":"See terms"}</button>
              </p>
            </div>
            {/* Metrics */}
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:9,marginBottom:14}}>
              {[[lang==="es"?"Registros":"Records",valid.toLocaleString()],[lang==="es"?"Índice forense":"Forensic index",score.toFixed(1)],[lang==="es"?"Umbral normal":"Normal threshold","< 15.5"],["Confianza / Confidence","95%"]].map(([l,v])=>(
                <div key={l} style={{background:"#0d1117",border:"1px solid #1e293b",borderRadius:11,padding:"13px 12px"}}>
                  <p style={{color:"#475569",fontSize:9,letterSpacing:2,textTransform:"uppercase",margin:"0 0 5px",fontFamily:"monospace"}}>{l}</p>
                  <p style={{color:"#f1f5f9",fontSize:18,fontFamily:"'Syne',sans-serif",fontWeight:800,margin:0}}>{v}</p>
                </div>
              ))}
            </div>
            {/* Multi-test narrative */}
            <div className="dsk-result-full" style={{background:"#0d1117",border:"1px solid #1e293b",borderRadius:11,padding:"14px",marginBottom:14}}>
              <p style={{color:"#475569",fontSize:9,letterSpacing:2,textTransform:"uppercase",margin:"0 0 12px",fontFamily:"monospace"}}>{lang==="es"?"Banco de pruebas estadísticas ejecutadas":"Statistical test battery executed"}</p>
              {[
                [lang==="es"?"Prueba de Distribución de Benford":"Benford Distribution Test","chi²="+score.toFixed(2)+", p"+pApprox,score>15.5,"🔬",lang==="es"?"DETECTÓ ANOMALÍA":"ANOMALY DETECTED",lang==="es"?"Normal":"Normal"],
                [lang==="es"?"Análisis de Frecuencia de Dígitos":"Digit Frequency Analysis","8 df, α=0.05",score>15.5,"📊",lang==="es"?"CONFIRMÓ DESVIACIÓN":"CONFIRMED DEVIATION",lang==="es"?"Sin hallazgos":"No findings"],
                [lang==="es"?"Prueba de Uniformidad":"Uniformity Test","Kolmogorov-Smirnov",false,"📐",lang==="es"?"Sin hallazgos":"No findings",lang==="es"?"Sin hallazgos":"No findings"],
                [lang==="es"?"Análisis de Segundo Dígito":"Second Digit Analysis","Simon Newcomb",false,"🔢",lang==="es"?"Sin hallazgos":"No findings",lang==="es"?"Sin hallazgos":"No findings"],
              ].map(([name,method,flagged,icon,flagLabel,cleanLabel])=>(
                <div key={name} style={{display:"flex",alignItems:"center",gap:10,padding:"8px 10px",borderRadius:7,background:"#080c14",marginBottom:6,border:`1px solid ${flagged?"#ef444422":"#1e293b"}`}}>
                  <span style={{fontSize:14,flexShrink:0}}>{icon}</span>
                  <div style={{flex:1}}>
                    <p style={{color:"#94a3b8",fontSize:12,fontWeight:600,margin:"0 0 1px"}}>{name}</p>
                    <p style={{color:"#334155",fontSize:10,margin:0,fontFamily:"monospace"}}>{method}</p>
                  </div>
                  <span style={{color:flagged?"#ef4444":"#22c55e",fontSize:10,fontWeight:700,fontFamily:"monospace",flexShrink:0,background:flagged?"#2d0a0a":"#052e16",padding:"3px 7px",borderRadius:4}}>{flagged?flagLabel:cleanLabel}</span>
                </div>
              ))}
              <p style={{color:"#334155",fontSize:10,margin:"8px 0 0",fontFamily:"monospace",textAlign:"center"}}>{lang==="es"?"La prueba de Benford fue la que detectó la anomalía estadística principal.":"The Benford test was the one that detected the primary statistical anomaly."}</p>
            </div>

            {/* Chi2 full breakdown */}
            {chiParts.length>0&&(
            <div style={{background:"#0d1117",border:"1px solid #1e293b",borderRadius:11,padding:"14px",marginBottom:14,overflowX:"auto"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                <p style={{color:"#475569",fontSize:9,letterSpacing:2,textTransform:"uppercase",margin:0,fontFamily:"monospace"}}>{lang==="es"?"Desglose Chi² por dígito":"Chi² breakdown by digit"}</p>
                <span style={{color:verdict.color,fontSize:11,fontFamily:"monospace",fontWeight:700}}>χ²={score.toFixed(2)} · p{pApprox}</span>
              </div>
              <table style={{width:"100%",borderCollapse:"collapse",fontSize:11,minWidth:340}}>
                <thead>
                  <tr>{[lang==="es"?"Díg.":"Dig.","Benford%",lang==="es"?"Real%":"Actual%",lang==="es"?"Dif.":"Diff.",lang==="es"?"χ² aporte":"χ² contrib",lang==="es"?"Estado":"Status"].map(h=>(
                    <th key={h} style={{padding:"5px 7px",textAlign:"left",color:"#334155",fontWeight:500,fontSize:10,borderBottom:"1px solid #1e293b",fontFamily:"monospace"}}>{h}</th>
                  ))}</tr>
                </thead>
                <tbody>
                  {chiParts.map(p=>(
                    <tr key={p.digit} style={{background:p.severity==="critical"?"#2d0a0a22":p.severity==="high"?"#1c140022":"transparent"}}>
                      <td style={{padding:"6px 7px",color:"#94a3b8",fontWeight:700,fontFamily:"monospace"}}>{p.digit}</td>
                      <td style={{padding:"6px 7px",color:"#475569",fontFamily:"monospace"}}>{p.expected}%</td>
                      <td style={{padding:"6px 7px",color:p.severity==="low"?"#64748b":"#f1f5f9",fontWeight:p.severity!=="low"?700:400,fontFamily:"monospace"}}>{p.observed}%</td>
                      <td style={{padding:"6px 7px",color:p.diff>0?"#ef4444":"#22c55e",fontFamily:"monospace"}}>{p.diff>0?"+":""}{p.diff}%</td>
                      <td style={{padding:"6px 7px",color:p.contrib>2?"#f59e0b":p.contrib>0.5?"#64748b":"#334155",fontFamily:"monospace"}}>{p.contrib}</td>
                      <td style={{padding:"6px 7px"}}>
                        {p.severity==="critical"&&<span style={{color:"#ef4444",fontSize:10,fontFamily:"monospace"}}>🔴 {lang==="es"?"CRÍTICO":"CRITICAL"}</span>}
                        {p.severity==="high"&&<span style={{color:"#f59e0b",fontSize:10,fontFamily:"monospace"}}>🟠 {lang==="es"?"ALTO":"HIGH"}</span>}
                        {p.severity==="medium"&&<span style={{color:"#eab308",fontSize:10,fontFamily:"monospace"}}>🟡 {lang==="es"?"MEDIO":"MED"}</span>}
                        {p.severity==="low"&&<span style={{color:"#22c55e",fontSize:10,fontFamily:"monospace"}}>✓</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p style={{color:"#334155",fontSize:10,margin:"8px 0 0",fontFamily:"monospace"}}>{lang==="es"?"Umbral crítico χ² (8 grados de libertad, 95% confianza) = 15.507":"Critical χ² threshold (8 degrees of freedom, 95% confidence) = 15.507"}</p>
            </div>
            )}

            {/* Attack zones */}
            {score>15.5&&anomalous.length>0&&(
            <div className="dsk-result-full" style={{background:"#2d0a0a",border:"1px solid #ef444433",borderRadius:11,padding:"14px",marginBottom:14}}>
              <p style={{color:"#ef4444",fontSize:9,letterSpacing:2,textTransform:"uppercase",margin:"0 0 10px",fontFamily:"monospace"}}>🎯 {lang==="es"?"Zonas de ataque — dónde buscar el fraude":"Attack zones — where to look for fraud"}</p>
              {anomalous.slice(0,3).map(p=>(
                <div key={p.digit} style={{background:"#080c14",borderRadius:8,padding:"10px 12px",marginBottom:8,border:"1px solid #ef444422"}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:4}}>
                    <span style={{color:"#f1f5f9",fontWeight:700,fontSize:13}}>
                      {lang==="es"?"Dígito":"Digit"} {p.digit} — {lang==="es"?"aparece":"appears"} {p.observed}% {lang==="es"?"(esperado":"(expected"} {p.expected}%)
                    </span>
                    <span style={{color:"#ef4444",fontSize:11,fontFamily:"monospace"}}>+{p.diff}% {lang==="es"?"exceso":"excess"}</span>
                  </div>
                  <p style={{color:"#64748b",fontSize:12,margin:"0 0 5px",lineHeight:1.5}}>
                    {lang==="es"
                      ?`Revisa registros cuyo monto empieza con ${p.digit} — hay ${p.obsN} registros en este grupo cuando lo esperado son ~${p.expN}. El exceso de ${p.obsN-p.expN} registros es estadísticamente anómalo.`
                      :`Review records whose amount starts with ${p.digit} — there are ${p.obsN} records in this group when ~${p.expN} are expected. The excess of ${p.obsN-p.expN} records is statistically anomalous.`}
                  </p>
                  {clusters.filter(c=>String(c.range).startsWith(String(p.digit))).slice(0,2).map(c=>(
                    <div key={c.range} style={{display:"flex",justifyContent:"space-between",background:"#0d1117",borderRadius:5,padding:"4px 8px",marginTop:4}}>
                      <span style={{color:"#94a3b8",fontSize:11,fontFamily:"monospace"}}>{lang==="es"?"Rango":"Range"} ${c.range.toLocaleString()}–${(c.range+99).toLocaleString()}</span>
                      <span style={{color:"#ef4444",fontSize:11,fontFamily:"monospace"}}>{c.count} {lang==="es"?"registros":"records"} ({c.pct}%)</span>
                    </div>
                  ))}
                </div>
              ))}
              {pattern==="threshold_avoidance"&&(
                <div style={{background:"#1c1400",border:"1px solid #f59e0b33",borderRadius:7,padding:"9px 11px",marginTop:8}}>
                  <p style={{color:"#f59e0b",fontSize:12,fontWeight:600,margin:"0 0 3px"}}>⚠ {lang==="es"?"Patrón detectado: Evasión de umbrales":"Pattern detected: Threshold avoidance"}</p>
                  <p style={{color:"#64748b",fontSize:11,lineHeight:1.5,margin:0}}>{lang==="es"?"Los montos están concentrados justo por debajo de valores redondos. Patrón típico de fraccionamiento de pagos para evitar controles de autorización.":"Amounts are concentrated just below round values. Typical pattern of payment splitting to avoid authorization controls."}</p>
                </div>
              )}
              {pattern==="inflation"&&(
                <div style={{background:"#1c1400",border:"1px solid #f59e0b33",borderRadius:7,padding:"9px 11px",marginTop:8}}>
                  <p style={{color:"#f59e0b",fontSize:12,fontWeight:600,margin:"0 0 3px"}}>⚠ {lang==="es"?"Patrón detectado: Inflación de montos":"Pattern detected: Amount inflation"}</p>
                  <p style={{color:"#64748b",fontSize:11,lineHeight:1.5,margin:0}}>{lang==="es"?"Concentración inusual en dígitos altos (7-9). Posible inflación artificial de montos en facturas o gastos.":"Unusual concentration in high digits (7-9). Possible artificial inflation of amounts in invoices or expenses."}</p>
                </div>
              )}
            </div>
            )}

            {/* Anomaly index bar */}
            <div style={{background:"#0d1117",border:"1px solid #1e293b",borderRadius:11,padding:"14px",marginBottom:14}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:7}}>
                <span style={{color:"#475569",fontSize:11,fontFamily:"monospace"}}>{lang==="es"?"Índice de anomalía estadística":"Statistical anomaly index"}</span>
                <span style={{color:verdict.color,fontSize:11,fontWeight:600,fontFamily:"monospace"}}>{score.toFixed(2)}</span>
              </div>
              <div style={{background:"#1e293b",borderRadius:100,height:8,overflow:"hidden"}}>
                <div style={{height:"100%",borderRadius:100,background:`linear-gradient(90deg,#22c55e,${score<15.5?"#22c55e":score<25?"#f59e0b":"#ef4444"})`,width:`${Math.min((score/40)*100,100)}%`,transition:"width 1.2s ease"}}/>
              </div>
              <div style={{display:"flex",justifyContent:"space-between",marginTop:5}}>
                <span style={{color:"#22c55e",fontSize:9,fontFamily:"monospace"}}>Normal &lt;15.5</span>
                <span style={{color:"#f59e0b",fontSize:9,fontFamily:"monospace"}}>{lang==="es"?"Revisar":"Review"} &lt;25</span>
                <span style={{color:"#ef4444",fontSize:9,fontFamily:"monospace"}}>{lang==="es"?"Alerta":"Alert"} &gt;25</span>
              </div>
            </div>
            {/* Interpretation */}
            <div className="dsk-result-full" style={{background:"#0d1117",borderLeft:`4px solid ${verdict.color}`,borderRadius:"0 11px 11px 0",padding:"14px 16px",marginBottom:18,border:`1px solid #1e293b`,borderLeftWidth:4,borderLeftColor:verdict.color}}>
              <p style={{color:"#64748b",fontSize:10,letterSpacing:2,textTransform:"uppercase",margin:"0 0 7px",fontFamily:"monospace"}}>{lang==="es"?"Interpretación":"Interpretation"}</p>
              <p style={{color:"#94a3b8",fontSize:13,lineHeight:1.7,margin:0}}>
                {score<15.5?(lang==="es"?"El conjunto de datos presenta patrones estadísticos consistentes con registros financieros orgánicos. No se detectaron señales de anomalía significativa. Los datos parecen corresponder a transacciones reales no alteradas.":"The analyzed dataset presents statistical patterns consistent with organic financial records. No significant anomaly signals were detected."):score<25?(lang==="es"?"Se detectaron desviaciones estadísticas moderadas. Se recomienda revisión manual de los registros con mayor concentración en rangos específicos de valores.":"Moderate statistical deviations detected. Manual review of records with higher concentration in specific value ranges is recommended."):(lang==="es"?"El conjunto de datos presenta anomalías estadísticas significativas. Se recomienda auditoría formal inmediata por contador público certificado.":"The dataset presents significant statistical anomalies. Immediate formal audit by a certified public accountant is strongly recommended.")}
              </p>
            </div>
            {/* PDF button */}
            <button className="dsk-result-full" onClick={handlePDF} disabled={pdfLoading} style={{width:"100%",background:pdfDone?"#052e16":pdfLoading?"#1e293b":"#f1f5f9",color:pdfDone?"#4ade80":pdfLoading?"#475569":"#080c14",border:pdfDone?"1.5px solid #22c55e":"none",borderRadius:12,padding:"14px",fontSize:15,fontWeight:700,cursor:pdfLoading?"not-allowed":"pointer",fontFamily:"inherit",marginBottom:9,display:"flex",alignItems:"center",justifyContent:"center",gap:8,transition:"all .3s"}}>
              {pdfLoading?<><div style={{width:15,height:15,border:"2px solid #334155",borderTopColor:"#94a3b8",borderRadius:"50%"}} className="spin"/>{lang==="es"?"Generando...":"Generating..."}</>:pdfDone?<>✓ {lang==="es"?"Reporte descargado":"Report downloaded"}</>:<>{lang==="es"?"📄 Descargar reporte PDF":"📄 Download PDF report"}</>}
            </button>
            <button className="dsk-result-full" onClick={reset} style={{width:"100%",background:"transparent",color:"#475569",border:"1px solid #1e293b",borderRadius:12,padding:"12px",fontSize:13,cursor:"pointer",fontFamily:"inherit",marginBottom:14}}>{lang==="es"?"Analizar otro archivo":"Analyze another file"}</button>
            <div style={{borderTop:"1px solid #1e293b",paddingTop:13,display:"flex",flexDirection:"column",alignItems:"center",gap:7}}>
              <div style={{display:"flex",gap:13,flexWrap:"wrap",justifyContent:"center"}}>
                {["🔒 SSL 256-bit","✓ Stripe Verified","🛡 "+(lang==="es"?"Datos no almacenados":"Data not stored")].map(b=><span key={b} style={{color:"#334155",fontSize:10,fontFamily:"monospace"}}>{b}</span>)}
              </div>
              <button onClick={()=>setShowTerms(true)} style={{background:"none",border:"none",color:"#334155",fontSize:10,cursor:"pointer",textDecoration:"underline",fontFamily:"monospace"}}>{lang==="es"?"Términos · Condiciones · Reembolso":"Terms · Conditions · Refund"}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
