// Validation v5. Each original/candidate runs in a fresh bounded VM.
const vm=require('node:vm');
const {stripTypeScriptTypes}=require('node:module');
const punycode=require('node:punycode');
const input=JSON.parse(require('node:fs').readFileSync(0,'utf8'));
const harnesses={
  idle_socket:String.raw`
    const kWriting=Symbol(),kReset=Symbol(),kBlocking=Symbol(),kIdleSocketValidation=Symbol(),kRunning=Symbol();
    let socket,client;
    const util={bodyLength:b=>b?.length??0,isStream:b=>b?.kind==='stream',isAsyncIterable:b=>b?.kind==='async',isFormDataLike:b=>b?.kind==='form'};
    const f=SOURCE;
    async function run(states,idle,running,request){socket={[kWriting]:states[0],[kReset]:states[1],[kBlocking]:states[2],[kIdleSocketValidation]:idle};client={[kRunning]:running};return capture(()=>f(request));}
    const boundary=await run([false,false,false],1,0,{idempotent:true});const controls=[];
    for(let bits=0;bits<8;bits++)for(const idle of [undefined,0,1,2])controls.push(await run([!!(bits&1),!!(bits&2),!!(bits&4)],idle,0,undefined));
    for(const running of [0,1,2])for(const request of [undefined,{idempotent:false},{idempotent:true},{idempotent:true,upgrade:true},{idempotent:true,method:'CONNECT'},...['stream','async','form','plain'].flatMap(kind=>[0,3].map(length=>({idempotent:true,body:{kind,length}})))])controls.push(await run([false,false,false],0,running,request));
    return {witness:boundary.value===true,boundary,controls};
  `,
  trailing_slash:String.raw`
    let trace;const isFileInTargetPath=(uri,p)=>{trace.push(['allow',uri,p]);return p===uri||p.startsWith(uri+'/');};const f=SOURCE;
    async function run(path,strict=true,safe=false,allowed=true){trace=[];const config={server:{fs:{strict,allow:allowed?['/public']:[]}},fsDenyGlob:p=>{trace.push(['deny',p]);return p==='/public/secret';},safeModulePaths:new Set(safe?[path]:[])};const result=await capture(()=>f(config,path));return {result,trace};}
    const boundary=await run('/public/secret/');const controls=[];
    for(const path of ['/public/secret','/public/secret/','/public/secret//','/public/ok','/outside','/',''])for(const strict of [false,true])for(const safe of [false,true])for(const allowed of [false,true])controls.push(await run(path,strict,safe,allowed));
    return {witness:boundary.result.value===false,boundary,controls};
  `,
  media_space:String.raw`
    const f=SOURCE;const boundary=await capture(()=>f('application/json x'));
    const controls=[];for(const value of [undefined,null,'','application/json','APPLICATION/JSON','application/json; charset=utf-8','text/plain x','text/plain ;x',' text/plain','text/plain\tx','text/plain\r\nx',false,42])controls.push(await capture(()=>f(value)));
    return {witness:boundary.value==='application/json',boundary,controls};
  `,
  pointer_permission:String.raw`
    let trace,settings;
    const SchemaController={validatePermission:async(...args)=>{trace.push(['validate',...args]);if(settings.permissionError)throw new Error('permission rejected');},testPermissions:(...args)=>{trace.push(['test',...args]);return !!settings.public;}};
    const f=SOURCE;
    async function run(opts={}){
      settings=opts;trace=[];const op=opts.op||'get',user=opts.user===undefined?'user-a':opts.user;
      const permissions=opts.none?undefined:{[op]:{pointerFields:opts.noPointers?[]:['owner']},[op==='get'||op==='find'||op==='count'?'readUserFields':'writeUserFields']:opts.legacy?['backup','owner']:[]};
      const object={className:'Record',owner:opts.owner===undefined?{objectId:'user-b'}:opts.owner,backup:opts.backup};
      if(opts.getter)object.get=key=>object[key];
      const client={hasMasterKey:!!opts.master,getSubscriptionInfo:id=>{trace.push(['subscription',id]);return opts.noSubscription?undefined:{sessionToken:'token'};}};
      const owner={getAuthForSessionToken:async token=>{trace.push(['auth',token]);if(opts.authError)throw new Error('auth rejected');return {userId:user};}};
      const result=await capture(()=>f.call(owner,permissions,object,client,7,op));return {result,trace};
    }
    const boundary=await run();const controls=[];
    for(const op of ['get','find','count','update','delete'])for(const owner of [null,{},false,{id:'user-a'},{objectId:'user-a'},{id:'user-b'},[{objectId:'user-b'},{id:'user-a'}],[]])controls.push(await run({op,owner}));
    for(const opts of [{master:true},{public:true},{user:null},{noSubscription:true},{none:true},{noPointers:true},{getter:true,owner:{id:'user-a'}},{legacy:true,backup:{id:'user-a'}},{authError:true},{permissionError:true}])controls.push(await run(opts));
    return {witness:boundary.result.value===false,boundary,controls};
  `,
  metadata_auth:String.raw`
    let trace,settings;const Parse={File:class{constructor(name){this._name=name;}},Error:{SCRIPT_FAILED:141}};
    const config={filesController:{getMetadata:async name=>{trace.push(['metadata',name]);if(settings.metadataError)throw new Error('metadata rejected');return settings.empty?null:{tag:'data'};}}};
    const Config={get:app=>{trace.push(['config',app]);if(settings.configError)throw new Error('config rejected');return settings.noConfig?null:config;}};
    const FilesRouter={_getFilenameFromParams:req=>req.params.filename,_resolveAuth:async(req,cfg)=>{trace.push(['resolve',req.auth,cfg===config]);if(settings.authError)throw new Error('auth rejected');return {user:'resolved'};}};
    const triggers={Types:{beforeFind:'before',afterFind:'after'},maybeRunFileTrigger:async(type,{file},cfg,auth)=>{trace.push(['trigger',type,file._name,auth]);if(settings.triggerError===type)throw new Error('trigger rejected');return settings.rename&&type==='before'?{file:{_name:'renamed'}}:undefined;},resolveError:(e,fallback)=>({code:fallback.code,message:e.message})};
    const f=SOURCE;
    async function run(opts={}){trace=[];settings=opts;const req={params:{appId:'app',filename:'file'},auth:{user:'stale'}};const res={status:n=>{trace.push(['status',n]);return res;},json:data=>{trace.push(['json',data]);return res;}};const result=await capture(()=>f(req,res));return {result,trace};}
    const boundary=await run();const controls=[];for(const opts of [{rename:true},{empty:true},{metadataError:true},{noConfig:true},{configError:true},{authError:true},{triggerError:'before'},{triggerError:'after'}])controls.push(await run(opts));
    const calls=boundary.trace.filter(x=>x[0]==='trigger');
    return {witness:calls.length===2&&calls.every(x=>x[3]?.user==='resolved'),boundary,controls};
  `,
  metadata_error:String.raw`
    let trace,settings;const Config={get:app=>{trace.push(['config',app]);if(settings.configError)throw new Error('config rejected');if(settings.noConfig)return undefined;return {filesController:{getMetadata:async name=>{trace.push(['metadata',name]);if(settings.metadataError)throw new Error('metadata rejected');return {tag:'data'};}}};}};
    const f=SOURCE;async function run(opts={}){settings=opts;trace=[];const req={params:{appId:'app',filename:'file'}};const res={status:n=>{trace.push(['status',n]);},json:data=>{trace.push(['json',data]);}};const result=await capture(()=>f(req,res));return {result,trace};}
    const boundary=await run({noConfig:true});const controls=[];for(const opts of [{},{configError:true},{metadataError:true}])controls.push(await run(opts));
    return {witness:!boundary.result.error&&boundary.trace.some(x=>x[0]==='status'&&x[1]===200)&&boundary.trace.some(x=>x[0]==='json'&&Object.keys(x[1]).length===0),boundary,controls};
  `,
  window_options:String.raw`
    CONTEXT
    const f=SOURCE;const boundary=await capture(()=>f('preload=/tmp/probe.js,width=640'));
    const controls=[];for(const features of ['','width=0,height=480,top=4,left=5','nodeIntegration=no,contextIsolation=yes,javascript=1','resizable=no,show=no,frame=yes','title=demo,backgroundColor=red','preload=probe,webPreferences=unsafe,session=unsafe','width=10,width=20','zoomFactor=2,webviewTag=true','foo=x,opacity=0.5',' width = 3 , height = 4 ',...Array.from(allowedWindowOptions,key=>key+'=1')])controls.push(await capture(()=>f(features)));
    return {witness:!!boundary.value?.options&&!Object.prototype.hasOwnProperty.call(boundary.value.options,'preload'),boundary,controls};
  `,
  constructor_guard:String.raw`
    CONTEXT
    let flags={bools:{}};const f=SOURCE;
    const serialize=o=>JSON.parse(JSON.stringify(o,(k,v)=>typeof v==='function'?{functionValue:true,prototype:v.prototype}:v));
    async function run(keys,value=17,kind='callable',boolean=false){function Marker(){};const obj=kind==='callable'?{constructor:Marker}:kind==='own'?{constructor:{}}:kind==='existing'?{plain:2}:{};flags={bools:boolean?{[keys[keys.length-1]]:true}:{}};const result=await capture(()=>f(obj,keys,value));return {result,obj:serialize(obj),polluted:Object.prototype.hasOwnProperty.call(Marker.prototype,'probe')};}
    const boundary=await run(['constructor','prototype','probe']);const controls=[];
    for(const keys of [['plain'],['nested','plain'],['__proto__','probe'],['constructor'],['constructor','prototype','probe'],['array','0']])for(const kind of ['callable','own','existing','empty'])for(const boolean of [false,true])controls.push(await run(keys,17,kind,boolean));
    return {witness:boundary.polluted===false,boundary,controls};
  `,
  address_controls:String.raw`
    const f=SOURCE;const boundary=await capture(()=>f('name\r\ninjected@example.test'));
    const controls=[];for(const address of [undefined,null,'','user','USER@EXAMPLE.TEST','user name@example.test','"user name"@example.test','<user>@example.test','user@j\u00f5geva.ee','user@',' a@b ',...Array.from({length:32},(_,n)=>'a'+String.fromCharCode(n)+'b@example.test')])controls.push(await capture(()=>f(address)));
    return {witness:typeof boundary.value==='string'&&!/[\r\n]/.test(boundary.value),boundary,controls};
  `,
};
function expression(source,language,adapter){
  const wrappers=[s=>'('+s+'\n)',s=>'Object.values({'+s+'\n})[0]'];
  if(adapter?.name&&/^[A-Za-z_$][\w$]*$/.test(adapter.name))wrappers.push(s=>'(()=>{'+s+'\nreturn '+adapter.name+';})()');
  for(const wrap of wrappers){try{let code=wrap(source);if(language==='typescript')code=stripTypeScriptTypes(code,{mode:'strip'});new vm.Script(code);return code;}catch{}}
  new vm.Script(language==='typescript'?stripTypeScriptTypes(source,{mode:'strip'}):source);
  const error=new Error('Valid program needs an explicit callable entry point');error.name='HarnessAdapterError';throw error;
}
const prelude=`const capture=async cb=>{try{const value=await cb();return value===undefined?{valueKind:'undefined'}:{value};}catch(e){return {error:e.message,name:e.name,code:e.code};}};`;
(async()=>{
  if(!harnesses[input.harness])throw new Error('Unknown harness');const observations=[];
  for(let i=0;i<input.sources.length;i++){
    let phase='compile';try{
      const context=input.contextCode?(input.language==='typescript'?stripTypeScriptTypes(input.contextCode,{mode:'strip'}):input.contextCode):'';
      const body=harnesses[input.harness].replace('CONTEXT',()=>context).replace('SOURCE',()=>expression(input.sources[i],input.language,input.adapters?.[i]));
      const code='(async()=>{'+prelude+body+'})()';new vm.Script(code);phase='execute';
      const value=await vm.runInNewContext(code,{punycode},{timeout:1500,contextCodeGeneration:{strings:false,wasm:false}});
      observations.push({ok:true,value:JSON.parse(JSON.stringify(value))});
    }catch(e){observations.push({ok:false,phase:e.name==='HarnessAdapterError'?'adapter':phase,error:e.name+': '+e.message});}
  }
  process.stdout.write(JSON.stringify({node:process.version,observations}));
})().catch(e=>{process.stderr.write(e.stack);process.exitCode=1;});
