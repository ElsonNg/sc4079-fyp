const path=require('node:path').posix;
const harnesses={
  html_access:String.raw`
    let trace,settings,isDev;const root='/output',FS_PREFIX='/@fs/';
    const cleanUrl=url=>url.replace(/[?#].*$/,'');const fsPathFromId=url=>url.slice(FS_PREFIX.length-1);
    const normalizePath=p=>p.replace(/\\/g,'/');const isParentDirectory=(dir,p)=>p.startsWith(dir+'/');
    const checkLoadingAccess=(config,p)=>{trace.push(['access',p]);return settings.access||'allowed';};
    const respondWithAccessDenied=(p,server,res)=>{trace.push(['denied',p]);};
    const fs={existsSync:p=>{trace.push(['exists',p]);return !settings.missing;}};const fsUtils=fs;
    const fsp={readFile:async(p,enc)=>{trace.push(['read',p,enc]);if(settings.readError)throw new Error('read rejected');return '<html>ok</html>';}};
    const server={config:{server:{headers:{mode:'dev'}},preview:{headers:{mode:'preview'}}},transformIndexHtml:async(url,html,original)=>{trace.push(['transform',url,original]);if(settings.transformError)throw new Error('transform rejected');return html+' transformed';}};
    const send=(req,res,html,type,options)=>{trace.push(['send',html,type,options]);};const f=SOURCE;
    async function run(url,opts={}){trace=[];settings=opts;isDev=!!opts.dev;const req={url,originalUrl:url,headers:{'sec-fetch-dest':opts.script?'script':'document'}},res={writableEnded:!!opts.ended};const result=await capture(()=>f(req,res,e=>{trace.push(['next',e?.message??null]);}));return {result,trace};}
    const boundary=await run('/%2e%2e/secret.html');const controls=[];
    for(const url of ['/index.html','/nested/a.html','/%2e%2e/secret.html','/index.html?raw','/script.js',undefined,'/%ZZ.html','/@fs/outside.html'])for(const dev of [false,true])controls.push(await run(url,{dev}));
    for(const opts of [{access:'denied',dev:true},{access:'fallback',dev:true},{missing:true},{script:true},{ended:true},{readError:true},{dev:true,transformError:true}])controls.push(await run('/index.html',opts));
    return {witness:!boundary.result.error&&!boundary.trace.some(x=>x[0]==='read'||x[0]==='send')&&boundary.trace.some(x=>x[0]==='next'),boundary,controls};
  `,
  root_lookup:String.raw`
    const LookupType={Root:'root',Partials:'partials',Layouts:'layouts'};const f=SOURCE;
    async function drain(iterator){let step=iterator.next();while(!step.done)step=iterator.next(await step.value);return step.value;}
    async function run(opts={}){const trace=[];const owner={options:{root:opts.empty?[]:['/root'],partials:['/root'],layouts:['/root']},candidates:()=>opts.paths||['/outside/file'],contains:(sync,dir,p)=>{trace.push(['contains',sync,dir,p]);if(opts.containsError)throw new Error('contains rejected');return p.startsWith(dir+'/');},exists:(sync,p)=>{trace.push(['exists',sync,p]);if(opts.existsError)throw new Error('exists rejected');return !opts.missing;},lookupError:(file,dirs)=>new Error('lookup rejected')};const result=await capture(()=>drain(f.call(owner,'file',opts.type||'root',opts.sync,'/root/current')));return {result,trace};}
    const boundary=await run();const controls=[];
    for(const type of ['root','partials','layouts'])for(const sync of [false,true])for(const paths of [['/root/ok'],['/outside/file','/root/ok'],[]])controls.push(await run({type,sync,paths}));
    for(const opts of [{empty:true},{missing:true,paths:['/root/ok']},{containsError:true},{existsError:true,paths:['/root/ok']}])controls.push(await run(opts));
    return {witness:boundary.result.error==='lookup rejected'&&!boundary.trace.some(x=>x[0]==='exists'),boundary,controls};
  `,
  fallback_candidates:String.raw`
    const f=SOURCE;
    async function run(opts={}){const trace=[],dirs=opts.empty?[]:['/root','/other'];const owner={options:{extname:'.liquid',fs:{resolve:(dir,file,ext)=>path.resolve(dir,file+ext),...(opts.noFallback?{}:{fallback:file=>{trace.push(['fallback',file]);return opts.missing?undefined:(opts.inside?'/root/fallback':'/outside/fallback');}})}},shouldLoadRelative:file=>file.startsWith('.'),dirname:path.dirname,contains:(dir,p)=>{trace.push(['contains',dir,p]);return p.startsWith(dir+'/');}};const result=await capture(()=>Array.from(f.call(owner,opts.file||'file',dirs,opts.current?'/root/current.liquid':undefined,opts.enforce!==false)));return {result,trace};}
    const boundary=await run();const controls=[];
    for(const file of ['file','../escape','./child'])for(const current of [false,true])for(const enforce of [false,true])controls.push(await run({file,current,enforce}));
    for(const opts of [{empty:true},{inside:true},{missing:true},{noFallback:true}])controls.push(await run(opts));
    return {witness:Array.isArray(boundary.result.value)&&!boundary.result.value.includes('/outside/fallback'),boundary,controls};
  `,
  absolute_url:String.raw`
    const f=SOURCE;const boundary=await capture(()=>f('//outside.test/path'));const controls=[];
    for(const url of ['https://a','HTTP://a','a+1.x-y://b','1bad://b','//a','///a','/a','a','../a','','https:a',null,undefined])controls.push(await capture(()=>f(url)));
    return {witness:boundary.value===true,boundary,controls};
  `,
  window_access:String.raw`
    let trace;const isSameOrigin=(a,b)=>a===b;;const f=SOURCE;
    async function run(opts={}){trace=[];const sender={id:7,getWebPreferences:()=>{return {nodeIntegration:opts.oldNode!==false};},getLastWebPreferences:()=>{return {nodeIntegration:!!opts.node};},getURL:()=>opts.same?'https://target.test':'https://sender.test'};const target={getWebPreferences:()=>{return {openerId:opts.oldOpener?7:0};},getLastWebPreferences:()=>{return {openerId:opts.opener?7:0};},getURL:()=>'https://target.test'};const result=await capture(()=>f(sender,target));return {result,trace};}
    const boundary=await run();const controls=[];for(const oldNode of [false,true])for(const node of [false,true])for(const oldOpener of [false,true])for(const opener of [false,true])for(const same of [false,true])controls.push(await run({oldNode,node,oldOpener,opener,same}));
    return {witness:boundary.result.value===false,boundary,controls};
  `,
  body_schema:String.raw`
    CONTEXT
    const paramsSchema=Symbol(),bodySchema=Symbol(),querystringSchema=Symbol(),headersSchema=Symbol();let trace,settings;
    const validateParam=(validator,request,field)=>{trace.push(['validate',field,validator?.label??null]);if(!validator)return false;if(settings.errorField===field)return settings.async?Promise.resolve('invalid'):'invalid';return field==='body'?'invalid':false;};
    const wrapValidationError=(err,field)=>({rejected:field,error:err});
    const validateAsyncParams=async()=>({async:'params'}),validateAsyncBody=async()=>({async:'body'}),validateAsyncQuery=async()=>({async:'query'}),validateAsyncHeaders=async()=>({async:'headers'});
    const f=SOURCE;
    async function run(header,opts={}){trace=[];settings=opts;const fn=Object.assign(()=>false,{label:'json'});const context={[paramsSchema]:{label:'params'},[bodySchema]:opts.direct?fn:opts.noBody?undefined:{'application/json':fn},[querystringSchema]:{label:'query'},[headersSchema]:{label:'headers'}};const result=await capture(()=>f(context,{headers:{'content-type':header}},opts.execution));return {result,trace};}
    const boundary=await run('APPLICATION/JSON');const controls=[];for(const header of ['application/json',' APPLICATION/JSON ; charset=utf-8','text/plain',undefined,''])controls.push(await run(header));
    for(const opts of [{direct:true},{noBody:true},{execution:{skipBody:true}},{execution:{skipParams:true,skipQuery:true}},...['params','body','query','headers'].flatMap(errorField=>[false,true].map(async=>({errorField,async,noBody:errorField==='query'||errorField==='headers'})))])controls.push(await run('application/json',opts));
    return {witness:boundary.result.value?.rejected==='body',boundary,controls};
  `,
};
require('./boundary_runtime.cjs')(harnesses,{path}).catch(e=>{process.stderr.write(e.stack);process.exitCode=1;});
