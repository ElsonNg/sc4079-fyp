// Additional bounded security regressions. Originals and candidates use fresh VMs.
const vm = require('node:vm');
const {stripTypeScriptTypes} = require('node:module');
const input = JSON.parse(require('node:fs').readFileSync(0,'utf8'));
const harnesses = {
  electron_options: `
    const hasProp=Object.prototype.hasOwnProperty;
    const f=SOURCE; const mergeOptions=(...args)=>f(...args);
    const cases=[
      [{webPreferences:{}},{webPreferences:{sandbox:true,contextIsolation:true}}],
      [{webPreferences:{sandbox:false}},{webPreferences:{sandbox:true,contextIsolation:true}}],
      [{width:10},{width:20,height:30}],
      [{},{webPreferences:{sandbox:true},isBrowserView:true}],
      [{webPreferences:{nested:{a:1}}},{webPreferences:{nested:{b:2}}}],
    ];
    const controls=[];
    for(const [child,parent] of cases) controls.push(await capture(()=>f(child,parent)));
    const cyclic={};cyclic.loop=cyclic;controls.push(await capture(()=>f({},cyclic)));
    return {witness:controls[0].value?.webPreferences?.sandbox===true,controls};
  `,
  liquid_pop: `
    const toArray=x=>Array.isArray(x)?x:[x]; const f=SOURCE; const controls=[];
    async function run(value,limit) {
      const charges=[];let used=0;
      const owner={context:{memoryLimit:{use:n=>{charges.push(n);used+=n;if(used>limit)throw new Error('memory limit');}}}};
      return {result:await capture(()=>f.call(owner,value)),charges,input:value};
    }
    const boundary=await run([1,2,3,4,5,6],4);
    for(const value of [[],[1],[1,2,3]]) for(const limit of [0,2,100]) controls.push(await run(value,limit));
    return {witness:boundary.result.error==='memory limit',boundary,controls};
  `,
  liquid_sample: `
    const toValue=x=>x,isNil=x=>x==null,isArray=Array.isArray,stringify=x=>x==null?'':String(x);
    Math.random=()=>0.75;const f=SOURCE;const controls=[];
    async function run(value,count,limit) {
      const charges=[];let used=0;
      const owner={context:{memoryLimit:{use:n=>{charges.push(n);used+=n;if(used>limit)throw new Error('memory limit');}}}};
      return {result:await capture(()=>f.call(owner,value,count)),charges,input:value};
    }
    const boundary=await run([1,2,3,4,5,6],1,4);
    for(const value of [null,[],[1,2,3],'abc']) for(const count of [0,1,2,9]) controls.push(await run(value,count,100));
    return {witness:boundary.result.error==='memory limit',boundary,controls};
  `,
  liquid_replace: `
    const stringify=x=>x==null?'':String(x);const f=SOURCE;const controls=[];
    async function run(str,pattern,replacement,limit) {
      const charges=[];let used=0;
      const owner={context:{memoryLimit:{use:n=>{charges.push(n);used+=n;if(used>limit)throw new Error('memory limit');}}}};
      return {result:await capture(()=>f.call(owner,str,pattern,replacement)),charges};
    }
    const boundary=await run('aaaa','a','xxxx',10);
    for(const args of [['abc','z','x'],['aaa','a',''],['abc','','x'],['','',''],['aaa','aa','b'],[null,'a','b']])
      controls.push(await run(...args,100));
    return {witness:boundary.result.error==='memory limit',boundary,controls};
  `,
  fastify_backpressure: `
    const f=SOURCE; const onRead=(...args)=>f(...args); const controls=[];
    let sourceOpen,waitingDrain,trace,res,reader;const reply={};
    const noop=()=>{},onReadError=error=>trace.push(['readError',String(error)]),onDrain=()=>trace.push('drain');
    const sendTrailer=()=>trace.push('trailer');
    async function run(done,destroyed,writeResult) {
      sourceOpen=true;waitingDrain=false;trace=[];
      res={destroyed,write:value=>{trace.push(['write',value]);return writeResult;},once:(name,fn)=>trace.push(['once',name,typeof fn])};
      reader={cancel:()=>{trace.push('cancel');return Promise.resolve();},
        read:()=>{trace.push('read');return Promise.resolve({done:true});}};
      const result=await capture(()=>f({done,value:'chunk'}));
      for(let turn=0;turn<4;turn++)await Promise.resolve();
      return {result,trace,sourceOpen,waitingDrain};
    }
    const boundary=await run(false,false,false);
    for(const done of [false,true]) for(const destroyed of [false,true]) for(const w of [true,false,0,null]) controls.push(await run(done,destroyed,w));
    return {witness:boundary.waitingDrain===true && !boundary.trace.includes('read'),boundary,controls};
  `,
  nuxt_redirect: `
    const encodeURL=HELPER;
    let location,isExternalHost,options,nuxtApp,encodedInputs;
    const encodeForHtmlAttr=x=>{encodedInputs.push(x);return String(x).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;');};
    const sanitizeStatusCode=(x,fallback)=>typeof x==='number'?x:fallback;
    const f=SOURCE;const controls=[];
    async function run(loc,external,code) {
      location=loc;isExternalHost=external;options={redirectCode:code};encodedInputs=[];
      const hooks=[];nuxtApp={callHook:async name=>{hooks.push(name);},ssrContext:{}};
      const result=await capture(()=>f('response'));
      return {result,encodedInputs,hooks,response:nuxtApp.ssrContext['~renderResponse']};
    }
    const boundary=await run('//evil.test/path',false,302);
    for(const loc of ['/safe?a=1#x','//evil.test/path','http://localhost//evil.test/x','/a"b'])
      for(const external of [false,true]) for(const code of [undefined,301]) controls.push(await run(loc,external,code));
    return {witness:boundary.encodedInputs[0]==='/path',boundary,controls};
  `,
  undici_url: `
    class InvalidArgumentError extends Error {} const f=SOURCE;const controls=[];
    const run=x=>capture(()=>{const url=f(x);return {href:url.href,origin:url.origin,pathname:url.pathname};});
    const boundary=await run({origin:'https://trusted.test',path:'https://evil.test/secret'});
    for(const path of ['/safe','safe','//evil.test/x','?query=1','']) for(const origin of ['https://trusted.test','https://trusted.test/'])
      controls.push(await run({path,origin}));
    for(const value of ['https://trusted.test/safe',null,42,{origin:'ftp://host',path:'/x'},
      {origin:'https://trusted.test',path:3},{protocol:'https:',hostname:'trusted.test',port:'invalid'},
      {protocol:'https:',hostname:'trusted.test',pathname:'/x',search:'?y=1'}]) controls.push(await run(value));
    return {witness:boundary.value?.origin==='https://trusted.test',boundary,controls};
  `,
  cookie_path: `
    const f=SOURCE;const controls=[];
    const boundary=await capture(()=>f('/safe'+String.fromCharCode(0x13b)));
    for(let code=0;code<256;code++)controls.push(await capture(()=>f('/a'+String.fromCharCode(code))));
    for(const path of ['','/','/normal/path', '/é','/Ā'])controls.push(await capture(()=>f(path)));
    return {witness:boundary.error==='Invalid cookie path',boundary,controls};
  `,
  unicode_length: `
    const assertString=x=>{if(typeof x!=='string')throw new TypeError('Expected string');};
    const f=SOURCE;const controls=[];
    const boundary=await capture(()=>f('abc'+'\uFE0F'.repeat(10),{max:3}));
    for(const value of ['','abc','\uFE0F','a\uFE0F','a\uFE0F\uFE0F','😀','😀\uFE0F'])
      for(const options of [{min:0,max:3},{min:1,max:1},{min:0,discreteLengths:[0,2]},undefined,2])
        controls.push(await capture(()=>f(value,options,3)));
    return {witness:boundary.value===false,boundary,controls};
  `,
  session_fields: `
    class ParseError extends Error {constructor(code,message){super(message);this.code=code;}}
    for(const name of ['INVALID_KEY_NAME','INVALID_SESSION_TOKEN','INTERNAL_SERVER_ERROR'])ParseError[name]=name;
    const Parse={Error:ParseError};const RestWrite={createSession:()=>{throw new Error('creation outside scope');}};
    const f=SOURCE;const controls=[];
    async function run(data,role='user',extra={}) {
      const owner={className:'_Session',auth:{user:{id:'u'},isMaster:role==='master',isMaintenance:role==='maintenance'},data,query:{objectId:'session'},...extra};
      const result=await capture(()=>f.call(owner));return {result,data:owner.data,query:owner.query};
    }
    const boundary=await run({sessionToken:null});
    for(const key of ['installationId','sessionToken','expiresAt','createdWith','ordinary'])
      for(const value of [null,'',false,0,'value']) for(const role of ['user','master','maintenance']) controls.push(await run({[key]:value},role));
    controls.push(await run({}),await run({ACL:{}},'user'),await run({sessionToken:null},'user',{className:'Other'}));
    return {witness:boundary.result.code==='INVALID_KEY_NAME',boundary,controls};
  `,
  reset_token: `
    class ParseError extends Error {constructor(code,message){super(message);this.code=code;}}
    for(const name of ['USERNAME_MISSING','OTHER_CAUSE','PASSWORD_MISSING'])ParseError[name]=name;
    const Parse={Error:ParseError};let config,trace,reject,failStringify;
    const Config={get:()=>config};
    const qs={stringify:x=>{if(failStringify)throw new Error('stringify failed');return JSON.stringify(x);}};
    const f=SOURCE;const controls=[];
    const owner={invalidRequest:()=>{throw new Error('invalidRequest');},missingPublicServerURL:()=>({missingURL:true}),
      invalidLink:()=>({invalidLink:true}),invalidVerificationLink:()=>({invalidVerificationLink:true})};
    async function run(token,scenario='normal',xhr=false) {
      trace=[];reject=scenario==='rejected';failStringify=scenario==='stringify_failed';
      const call=(name,args)=>{trace.push({name,args,tokenType:typeof args[1]});return reject?Promise.reject('rejected'):Promise.resolve();};
      config={publicServerURL:'https://app.test',applicationId:'app',appName:'app',choosePasswordURL:'/choose',passwordResetSuccessURL:'/reset',verifyEmailSuccessURL:'/verified',
        userController:{checkResetTokenValidity:(...args)=>call('check',args),updatePassword:(...args)=>call('update',args),verifyEmail:(...args)=>call('verify',args)}};
      if(scenario==='no_config')config=null;
      if(scenario==='no_url')config.publicServerURL='';
      const fields={username:scenario==='no_username'?'':'user',token,new_password:scenario==='no_password'?'':'password'};
      const result=await capture(()=>f.call(owner,{config,query:fields,body:fields,params:{appId:'app'},xhr}));
      return {result,trace};
    }
    const boundary=await run({$ne:null});
    for(const token of ['token',{$ne:null},['a','b'],5,0,null,''])
      for(const scenario of ['normal','rejected','no_username','no_password','stringify_failed'])
        for(const xhr of [false,true])controls.push(await run(token,scenario,xhr));
    controls.push(await run('token','no_config'),await run('token','no_url'));
    return {witness:boundary.trace[0]?.tokenType==='string',boundary,controls};
  `,
  graphql_limits: `
    const f=SOURCE;const controls=[];
    function nested(n){return n?{selections:[{kind:'Field',selectionSet:nested(n-1)}]}:undefined;}
    const spread=name=>({kind:'FragmentSpread',name:{value:name}});
    const boundary=await capture(()=>f({selectionSet:nested(10)},{},{maxDepth:2}));
    for(const depth of [0,1,4,10]) for(const limits of [{},{maxDepth:2},{maxFields:2},{maxDepth:-1,maxFields:-1},{maxFields:0}])
      controls.push(await capture(()=>f({selectionSet:nested(depth)},{},limits)));
    for(const repeats of [1,3,8]) {
      const fragments={A:{selectionSet:nested(3)},B:{selectionSet:{selections:[spread('B'),spread('A')]}}};
      controls.push(await capture(()=>f({selectionSet:{selections:Array.from({length:repeats},()=>spread('B'))}},fragments,{})));
    }
    return {witness:boundary.value?.fields===3,boundary,controls};
  `,
};

function expression(source,language) {
  const errors=[];
  for(const wrap of [s=>'('+s+'\n)',s=>'Object.values({'+s+'\n})[0]']) {
    try {let code=wrap(source);if(language==='typescript')code=stripTypeScriptTypes(code,{mode:'strip'});new vm.Script(code);return code;}
    catch(e){errors.push(e.message);}
  }
  throw new Error(errors.join('; '));
}
const prelude=`const capture=async cb=>{try{const value=await cb();return value===undefined?{valueKind:'undefined'}:{value};}catch(e){return {error:e.message,name:e.name,code:e.code};}};`;
(async()=>{
  if(!harnesses[input.harness])throw new Error('Unknown harness');
  const observations=[];
  for(let i=0;i<input.sources.length;i++) {
    let phase='compile';
    try {
      let code=harnesses[input.harness].replace('SOURCE',()=>expression(input.sources[i],input.language));
      if(code.includes('HELPER'))code=code.replace('HELPER',()=>expression(input.helper.source,input.helper.language));
      code='(async()=>{'+prelude+code+'})()';new vm.Script(code);phase='execute';
      const value=await vm.runInNewContext(code,{URL,Buffer},{timeout:1500,contextCodeGeneration:{strings:false,wasm:false}});
      observations.push({ok:true,value:JSON.parse(JSON.stringify(value))});
    }catch(e){observations.push({ok:false,phase,error:e.name+': '+e.message});}
  }
  process.stdout.write(JSON.stringify({node:process.version,observations}));
})().catch(e=>{process.stderr.write(e.stack);process.exitCode=1;});
