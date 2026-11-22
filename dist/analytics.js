'use strict';
(()=>{
  const el=document.getElementById('visitor-counter');
  const num=document.getElementById('visitor-count');
  if(!el||!num)return;
  el.hidden=false;
  num.textContent='読込中';
  let ref='';
  try{
    if(document.referrer){
      const u=new URL(document.referrer);
      if(u.origin!==location.origin)ref=u.origin;
    }
  }catch{}
  window.goatcounter={referrer:ref};
  const s=document.createElement('script');
  s.src='https://gc.zgo.at/count.js';
  s.async=true;
  s.dataset.goatcounter='https://leakradar-mofu.goatcounter.com/count';
  document.head.appendChild(s);
  fetch('https://leakradar-mofu.goatcounter.com/counter/TOTAL.json',{
    mode:'cors',
    credentials:'omit',
    referrerPolicy:'no-referrer'
  })
    .then(r=>{
      if(!r.ok)throw Error('counter unavailable');
      return r.json();
    })
    .then(d=>{
      if(typeof d.count!=='string')throw Error('counter unavailable');
      num.textContent=d.count;
    })
    .catch(()=>{
      num.textContent='取得できません';
    });
})();
