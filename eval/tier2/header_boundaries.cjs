const proxyCommon=String.raw`
  const process={env:{}};
  CONTEXT
  let settings;const getProxyForUrl=url=>url.includes('/redirect')&&settings.redirectProxy!==undefined?settings.redirectProxy:(settings.envProxy??'http://user:pass@proxy.test:8080');
  class AxiosError extends Error{static ERR_BAD_OPTION='ERR_BAD_OPTION';constructor(message,code){super(message);this.code=code;}}
  let setProxy;const f=SOURCE;setProxy=f;
  const snapshot=options=>({hostname:options.hostname,host:options.host,port:options.port,path:options.path,protocol:options.protocol,headers:options.headers,hasCallback:typeof options.beforeRedirects.proxy==='function'});
  async function run(opts={}){
    settings=opts;process.env={no_proxy:opts.noProxy||''};
    const location=opts.location||'http://origin.test/start';const headers={ordinary:'keep',...(opts.stale?{'Proxy-Authorization':'stale-upper','pRoXy-AuThOrIzAtIoN':'stale-mixed'}:{})};
    const initial={hostname:'origin.test',port:80,path:'/start',protocol:'http:',headers,beforeRedirects:{}};
    const proxy=opts.proxy===undefined?undefined:JSON.parse(JSON.stringify(opts.proxy));
    const result=await capture(()=>f(initial,proxy,location));const before=snapshot(initial);let redirect;
    if(opts.redirect){const target=new URL(opts.redirect);const redirected={hostname:target.hostname,port:target.port,path:target.pathname,href:opts.redirect,protocol:target.protocol,headers:{...initial.headers},beforeRedirects:{}};const outcome=await capture(()=>initial.beforeRedirects.proxy(redirected));redirect={result:outcome,options:snapshot(redirected)};}
    return {result,initial:before,redirect};
  }
  const controls=[];
  for(const opts of [{},{stale:true,proxy:false},{stale:true,envProxy:''},{noProxy:'*'},{location:'http://internal.test./path',noProxy:'internal.test'},{location:'http://sub.internal.test/path',noProxy:'.internal.test'},{location:'http://internal.test:8080/path',noProxy:'internal.test:8080'},{noProxy:'unrelated.test'},{proxy:{host:'explicit.test',port:3128,protocol:'http',auth:{username:'a',password:'b'}}},{proxy:{host:'explicit.test',auth:{}}},{proxy:{host:'explicit.test',auth:'u:p'}},{redirect:'http://elsewhere.test/redirect',redirectProxy:'',stale:true},{redirect:'http://elsewhere.test/redirect',redirectProxy:'http://new:secret@second.test:8080',stale:true},{redirect:'http://localhost/redirect',stale:true},{proxy:false,redirect:'http://elsewhere.test/redirect',stale:true}])controls.push(await run(opts));
`;
const harnesses={
  cookie_domain:String.raw`
    CONTEXT
    const f=SOURCE;const boundary=await capture(()=>f('example.test\r\nInjected: yes'));const controls=[];
    for(const domain of ['example.test','a-b.test','localhost',' ','','-a','a-','a.','.a','a..b','a'.repeat(63)+'.test','a'.repeat(64)+'.test',Array(4).fill('a'.repeat(63)).join('.'),Array(4).fill('a'.repeat(63)).join('.')+'a',...Array.from({length:256},(_,n)=>'a'+String.fromCharCode(n)+'b.test')])controls.push(await capture(()=>f(domain)));
    return {witness:boundary.error==='Invalid cookie domain',boundary,controls};
  `,
  cookie_attributes:String.raw`
    CONTEXT
    const f=SOURCE;
    async function run(opts={}){const cookie={name:'session',value:'ok',unparsed:[],...opts};const result=await capture(()=>f(cookie));return {result,cookie};}
    const boundary=await run({unparsed:['x=ok\r\nInjected: yes']});const controls=[];
    for(const opts of [{},{unparsed:['x=ok']},{unparsed:['x=a=b']},{unparsed:['bad']},{unparsed:['bad key=ok']},{unparsed:[' x =ok']},{name:''},{name:'__Host-session',domain:'example.test',path:'/bad'},{name:'__Secure-session'},{httpOnly:true,secure:true,maxAge:30,sameSite:'Strict',path:'/',domain:'example.test'},{maxAge:-1},{domain:'bad\r\ndomain'},{path:'/bad;path'},{expires:new Date('2020-01-02T03:04:05Z')},{expires:new Date('bad')},...Array.from({length:256},(_,n)=>({unparsed:['x=a'+String.fromCharCode(n)+'b']})),...Array.from({length:128},(_,n)=>({unparsed:['x'+String.fromCharCode(n)+'y=ok']}))])controls.push(await run(opts));
    return {witness:!!boundary.result.error,boundary,controls};
  `,
  proxy_bypass:proxyCommon+String.raw`
    const boundary=await run({location:'http://internal.test./path',noProxy:'internal.test'});
    return {witness:!boundary.result.error&&boundary.initial.hostname==='origin.test'&&!boundary.initial.headers['Proxy-Authorization'],boundary,controls};
  `,
  proxy_redirect:proxyCommon+String.raw`
    const boundary=await run({redirect:'http://elsewhere.test/redirect',redirectProxy:'',stale:true});
    return {witness:!!boundary.redirect&&!boundary.redirect.result.error&&!Object.keys(boundary.redirect.options.headers).some(k=>k.toLowerCase()==='proxy-authorization'),boundary,controls};
  `,
};
require('./boundary_runtime.cjs')(harnesses,{URL,Buffer}).catch(e=>{process.stderr.write(e.stack);process.exitCode=1;});
