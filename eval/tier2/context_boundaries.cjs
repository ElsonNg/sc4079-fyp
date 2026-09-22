// Security witnesses with recovered helper context and generated-code execution.
const vm=require('node:vm');
const {stripTypeScriptTypes}=require('node:module');
const input=JSON.parse(require('node:fs').readFileSync(0,'utf8'));
const harnesses={
  axios_keys:String.raw`
    const utils={isUndefined:x=>x===undefined,hasOwnProperty:(obj,key)=>Object.prototype.hasOwnProperty.call(obj,key)};
    let config,mergeMap,trace,value;const mergeDeepProperties=key=>{trace.push(['deep',key]);return value;};
    const mergeDirectKeys=key=>{trace.push(['direct',key]);return value;};const f=SOURCE;
    async function run(key,returned,inherited=false,direct=false){
      config={};trace=[];value=returned;mergeMap=inherited?Object.create({inherited:()=>{trace.push(['inherited']);return 9;}}):{};
      if(direct)mergeMap[key]=mergeDirectKeys;
      const result=await capture(()=>f(key));return {result,trace,config,prototypeMarker:Object.getPrototypeOf(config).marker===true};
    }
    const boundary=await run('__proto__',{marker:true});const controls=[];
    for(const key of ['__proto__','constructor','prototype','ordinary','inherited'])for(const value of [undefined,null,3,{marker:true}])
      controls.push(await run(key,value,true));
    controls.push(await run('ordinary',undefined,false,true));
    return {witness:!boundary.result.error && !boundary.prototypeMarker && boundary.trace.length===0,boundary,controls};
  `,
  moment_locale:String.raw`
    CONTEXT
    let locales,trace,fail;const module={exports:{}};const globalLocale={_abbr:'en'};
    const require=name=>{trace.push(['require',name]);if(fail)throw new Error('missing locale');};
    const getSetGlobalLocale=name=>trace.push(['restore',name]);const f=SOURCE;
    async function run(name,present=false,reject=false){
      locales={};trace=[];fail=reject;if(present)locales[name]={loaded:true};
      const result=await capture(()=>f(name));return {result,trace,locales};
    }
    const boundary=await run('../../target');const controls=[];
    for(const name of ['en','en-US','../target','..\\target','nested/path','nested\\path',''])for(const present of [false,true])for(const reject of [false,true])
      controls.push(await run(name,present,reject));
    return {witness:boundary.trace.length===0,boundary,controls};
  `,
  undici_header:String.raw`
    CONTEXT
    class InvalidArgumentError extends Error {} class NotSupportedError extends Error {}
    const f=SOURCE;
    async function run(key,val,existing=false){
      const request={host:null,contentLength:null,contentType:existing?'existing':null,headers:''};
      const result=await capture(()=>f(request,key,val));return {result,request};
    }
    const boundary=await run('Content-Type','text/plain\r\nx-injected: yes');const controls=[];
    for(const key of ['content-type','CONTENT-TYPE','x-normal','bad key','content-length','transfer-encoding','connection','keep-alive','upgrade','expect','host'])
      for(const val of ['text/plain','a\r\nb',null,undefined,17,{},''])controls.push(await run(key,val));
    controls.push(await run('content-type','a\r\nb',true));
    return {witness:!!boundary.result.error && boundary.request.headers==='',boundary,controls};
  `,
  route_rules:String.raw`
    let trace,reject;const console={error:(...args)=>trace.push(['logged',args[0]])};
    const routeRulesMatcher=path=>{trace.push(['match',path]);if(reject)throw new Error('matcher');return {path};};
    const f=SOURCE;
    async function run(arg,fail=false){trace=[];reject=fail;return {result:await capture(()=>f(arg)),trace};}
    const boundary=await run('/ADMIN');const controls=[];
    for(const arg of ['/safe','/MiXeD',{path:'/API'},{path:'/safe'},{path:0},{}])for(const fail of [false,true])controls.push(await run(arg,fail));
    return {witness:boundary.trace[0]?.[1]==='/admin',boundary,controls};
  `,
  multer_cleanup:String.raw`
    let isDone,req,busboy,trace,queue;const setImmediate=fn=>{queue.push(fn);trace.push('schedule');};
    const drainStream=()=>trace.push('drain');const next=err=>trace.push(['next',err]);const f=SOURCE;
    async function run(present,done=false){
      isDone=done;trace=[];queue=[];busboy=present?{removeAllListeners:()=>trace.push('removeListeners')}:undefined;
      req={unpipe:target=>trace.push(['unpipe',target===busboy]),resume:()=>trace.push('resume')};
      const result=await capture(()=>f('request error'));
      const scheduled=[];for(const task of queue)scheduled.push(await capture(task));
      return {result,trace,scheduled,isDone};
    }
    const boundary=await run(false);const controls=[];
    for(const present of [false,true])for(const done of [false,true])controls.push(await run(present,done));
    return {witness:boundary.scheduled.length===0 && boundary.trace.some(x=>Array.isArray(x)&&x[0]==='next'),boundary,controls};
  `,
  parse_me:String.raw`
    const Parse={Error:{INVALID_SESSION_TOKEN:101}};const createSanitizedError=(code,message)=>Object.assign(new Error(message),{code});
    const Auth={master:()=>({role:'master'})};let trace,scenario;
    const UsersRouter={removeHiddenProperties:user=>{trace.push('stripHidden');delete user.password;}};
    const rest={find:async(config,auth,cls,query,options,sdk,context)=>{
      trace.push({method:'find',auth,cls,query,options,sdk,context});
      if(scenario==='find_reject')throw new Error('find failed');
      if(scenario==='no_session')return {results:[]};
      if(scenario==='no_user')return {results:[{}]};
      return {results:[{user:{objectId:'user',password:'hidden',secret:'master-only'}}]};
    },get:async(config,auth,cls,id,options,sdk,context)=>{
      trace.push({method:'get',auth,cls,id,options,sdk,context});
      if(scenario==='get_reject')throw new Error('get failed');
      return {results:scenario==='get_empty'?[]:[{objectId:'user',password:'hidden'}]};
    }};const f=SOURCE;
    async function run(mode){scenario=mode;trace=[];const req={config:{},auth:{role:'caller'},info:{sessionToken:'token',clientSDK:'sdk',context:{marker:true}}};
      if(mode==='missing_info')delete req.info;if(mode==='missing_token')req.info.sessionToken='';
      return {result:await capture(()=>f(req)),trace};}
    const boundary=await run('normal');const controls=[];
    for(const mode of ['normal','missing_info','missing_token','no_session','no_user','find_reject','get_reject','get_empty'])controls.push(await run(mode));
    return {witness:boundary.trace.some(x=>x.method==='get'&&x.auth.role==='caller') && !boundary.trace.some(x=>x.method==='find'&&x.options.include==='user'),boundary,controls};
  `,
  websocket_upgrade:String.raw`
    let trace;const socketOnError=()=>{},keyRegex=/^[+/0-9A-Za-z]{22}==$/;
    const abortHandshake=(socket,code,message)=>trace.push(['abort',code,message]);
    const abortHandshakeOrEmitwsClientError=(owner,req,socket,code,message)=>trace.push(['abort',code,message]);
    const subprotocol={parse:value=>new Set(value.split(','))};const f=SOURCE;
    async function run(upgrade,method='GET',version=13,verify='none'){
      trace=[];const socket={authorized:false,encrypted:false,on:event=>trace.push(['on',event])};
      const req={headers:{upgrade,'sec-websocket-key':'dGhlIHNhbXBsZSBub25jZQ==','sec-websocket-version':String(version)},method,socket,connection:socket};
      const owner={options:{perMessageDeflate:false},shouldHandle:()=>true,completeUpgrade:()=>trace.push('complete')};
      if(verify==='deny')owner.options.verifyClient=()=>false;
      if(verify==='allow')owner.options.verifyClient=()=>true;
      if(verify==='async_deny')owner.options.verifyClient=(info,cb)=>cb(false,403);
      const result=await capture(()=>f.call(owner,req,socket,Buffer.alloc(0),()=>{}));return {result,trace};
    }
    const boundary=await run(undefined);const controls=[];
    for(const upgrade of [undefined,'websocket','WebSocket','http',''])for(const method of ['GET','POST'])for(const version of [13,8,7])
      controls.push(await run(upgrade,method,version));
    for(const verify of ['allow','deny','async_deny'])controls.push(await run('websocket','GET',13,verify));
    return {witness:!boundary.result.error && boundary.trace.some(x=>Array.isArray(x)&&x[0]==='abort'&&x[1]===400),boundary,controls};
  `,
  handlebars_name:String.raw`
    const f=SOURCE;const owner={aliasable:name=>name};
    async function run(name){return capture(()=>{const code=f.call(owner,name).join('');return evaluateGenerated(code,'handlebars',{});});}
    const boundary=await run('x"), (globalThis.injected = true), container.lookup(depths, "y');const controls=[];
    for(const name of ['normal','a"b','a\\b','line\nname','x"), (globalThis.injected = true), container.lookup(depths, "y'])controls.push(await run(name));
    return {witness:boundary.value?.injected===false && boundary.value?.calls.length===1,boundary,controls};
  `,
  vite_document:String.raw`
    const getResolveUrl=args=>args,escapeId=x=>x,partialEncodeURIPath=x=>x;const f=SOURCE;
    async function run(tag,umd,documentMissing=false){return capture(()=>{
      const code=f('asset.js',umd);return evaluateGenerated(code,'vite',{tag,documentMissing});
    });}
    const boundary=await run('IMG',false);const controls=[];
    for(const tag of ['SCRIPT','script','IMG',null])for(const umd of [false,true])controls.push(await run(tag,umd));
    controls.push(await run(null,true,true));
    return {witness:boundary.value?.base==='https://trusted.test/page',boundary,controls};
  `,
  fastify_mime:String.raw`
    CONTEXT
    const f=SOURCE;const ContentTypeParser=caseKind==='ContentTypeParser'?f:ORIGINAL_CTOR;
    ContentTypeParser.prototype.hasParser=HAS_PARSER;
    ContentTypeParser.prototype.existingParser=EXISTING_PARSER;
    ContentTypeParser.prototype.getParser=caseKind==='ContentTypeParser.prototype.getParser'?f:ORIGINAL_GETTER;
    ContentTypeParser.prototype.add=caseKind==='ContentTypeParser.prototype.add'?f:ORIGINAL_ADDER;
    const kDefaultJsonParse=Symbol('json');const defaultPlainTextParser=Object.assign(()=>{}, {label:'plain'});
    const getDefaultJsonParser=()=>Object.assign(()=>{}, {label:'json'});
    const lru=()=>new Map();
    class FST_ERR_CTP_INVALID_TYPE extends Error{} class FST_ERR_CTP_EMPTY_TYPE extends Error{}
    class FST_ERR_CTP_ALREADY_PRESENT extends Error{} class FST_ERR_CTP_INVALID_HANDLER extends Error{}
    class FST_ERR_CTP_INVALID_PARSE_TYPE extends Error{}
    async function run(header,custom=false,regexp=false){
      return capture(()=>{
        const owner=new ContentTypeParser(1024,'error','error');
        if(custom)owner.add(regexp?/application\/custom/:'application/custom',{parseAs:'string'},Object.assign(()=>{}, {label:'custom'}));
        const first=owner.getParser(header);const second=owner.getParser(header);
        return {parser:first?.fn?.label??'none',cached:second===first};
      });
    }
    const boundary=await run('text/plain; x="application/custom"',true);const controls=[];
    for(const header of ['application/json','text/plain','text/plain; x="application/json"','application/json; charset=utf-8','APPLICATION/JSON','bad content type','application/custom','text/plain; x="application/custom"'])
      for(const custom of [false,true])for(const regexp of [false,true])controls.push(await run(header,custom,regexp));
    return {witness:boundary.value?.parser==='plain',boundary,controls};
  `,
};

function expression(source,language,adapter){
  const wrappers=[s=>'('+s+'\n)',s=>'Object.values({'+s+'\n})[0]'];
  if(adapter?.name && /^[A-Za-z_$][\w$]*$/.test(adapter.name))wrappers.push(s=>'(()=>{'+s+'\nreturn '+adapter.name+';})()');
  const errors=[];for(const wrap of wrappers){
    try{let code=wrap(source);if(language==='typescript')code=stripTypeScriptTypes(code,{mode:'strip'});new vm.Script(code);return code;}catch(e){errors.push(e.message);}
  }
  // A valid program with no identified function entry is a harness limitation,
  // not a demonstrated JavaScript syntax defect.
  try{new vm.Script(language==='typescript'?stripTypeScriptTypes(source,{mode:'strip'}):source);}
  catch(e){throw new Error(errors.join('; '));}
  const error=new Error('Valid program needs an explicit callable entry point');error.name='HarnessAdapterError';throw error;
}
function evaluateGenerated(code,kind,options){
  // Only generated expressions run here; no filesystem/network/module APIs.
  let prefix,body;
  if(kind==='handlebars'){
    prefix='globalThis.injected=false;const calls=[];const depths=[];const container={lookup:(depths,name)=>{calls.push(name);return name;}};';
    body='const value=('+code+');JSON.stringify({value,calls,injected:globalThis.injected});';
  }else{
    prefix='const location={href:"https://trusted.test/location"};'+(options.documentMissing?'':
      'const document='+JSON.stringify({baseURI:'https://trusted.test/page',currentScript:options.tag?{tagName:options.tag,src:'https://evil.test/script.js'}:null})+';');
    body='const args=['+code+'];JSON.stringify({path:args[0],base:args[1]});';
  }
  return JSON.parse(vm.runInNewContext(prefix+body,Object.create(null),{timeout:500,contextCodeGeneration:{strings:false,wasm:false}}));
}
const prelude=`const capture=async cb=>{try{const value=await cb();return value===undefined?{valueKind:'undefined'}:{value};}catch(e){return {error:e.message,name:e.name,code:e.code};}};`;
(async()=>{
  const observations=[];if(!harnesses[input.harness])throw new Error('Unknown harness');
  for(let i=0;i<input.sources.length;i++){
    let phase='compile';try{
      let code=harnesses[input.harness].replace('SOURCE',()=>expression(input.sources[i],input.language,input.adapters?.[i]));
      code=code.replace('CONTEXT',()=>input.contextCode||'');
      for(const [token,source] of Object.entries(input.contexts?.[i]||{}))code=code.replace(token,()=>expression(source,'javascript'));
      code='(async()=>{'+prelude+code+'})()';new vm.Script(code);phase='execute';
      const result=await vm.runInNewContext(code,{Buffer,caseKind:input.functionName,evaluateGenerated},{timeout:1500,contextCodeGeneration:{strings:false,wasm:false}});
      observations.push({ok:true,value:JSON.parse(JSON.stringify(result))});
    }catch(e){observations.push({ok:false,phase:e.name==='HarnessAdapterError'?'adapter':phase,error:e.name+': '+e.message});}
  }
  process.stdout.write(JSON.stringify({node:process.version,observations}));
})().catch(e=>{process.stderr.write(e.stack);process.exitCode=1;});
