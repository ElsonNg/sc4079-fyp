// Bounded extracted-function tests, not full-package exploit tests.
const vm = require('node:vm');
const {stripTypeScriptTypes} = require('node:module');
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const harnesses = {
  qs: `
    const parseArrayValue = value => value;
    const f = SOURCE;
    const parseObject = (chain,value,options) => f(chain,value,options,true);
    const out = [];
    for(const parseArrays of [false,true]) for(const plainObjects of [false,true])
      for(const chain of [['__proto__'],['[__proto__]'],['safe'],['[0]'],['[]'],[]]) {
        const value={boundaryMarker:'marker'}, argument=chain.slice();
        const result=f(argument,value,{parseArrays,plainObjects,arrayLimit:20},true);
        out.push({keys:Object.keys(result),ownMarker:Object.hasOwn(result,'boundaryMarker'),
          inheritedMarker:!Object.hasOwn(result,'boundaryMarker') && result.boundaryMarker==='marker',
          json:JSON.stringify(result),remainingChain:argument,nullPrototype:Object.getPrototypeOf(result)===null});
      }
    return out;
  `,
  lodash: `
    const objectProto=Object.prototype; const f=SOURCE;
    const encode=x=>x===undefined?'undefined':x===objectProto?'Object.prototype':x;
    return [encode(f({prototype:objectProto},'prototype')),encode(f({},'__proto__')),
      encode(f({safe:7},'safe')),encode(f({prototype:3},'prototype'))];
  `,
  minimist_predicate: `
    const f=SOURCE;
    return [f({},'__proto__'),f({},'constructor'),f({constructor:1},'constructor'),f({},'safe')];
  `,
  semver: `
    const MAX_LENGTH=256,LOOSE=0,FULL=1,re=[/./,/./];
    const SemVer=function(version,loose) {if(version==='throw') throw new Error('invalid');this.version=version;this.loose=loose;};
    const f=SOURCE; const out=[];
    for(const version of ['1.2.3','','x'.repeat(257),'throw']) for(const loose of [false,true]) {
      try {out.push({value:f(version,loose)});} catch(e) {out.push({error:e.message});}
    }
    return out;
  `,
  moment: `
    const f=SOURCE;
    return ['Mon, 25 Dec 1995 13:30:00 GMT','((a))','(comment)','  a\\tb\\nc  ','((unclosed'].map(x=>f(x));
  `,
  headers: `
    const util = {headerNameToString: h => h.toString().toLowerCase()};
    const f = SOURCE; const out = [];
    for (const h of ['host','Host','authorization','AUTHORIZATION','cookie','Cookie',
      'proxy-authorization','Proxy-Authorization','content-length','Content-Type','x-safe']) {
      for (const binary of [false,true]) for (const content of [false,true]) for (const origin of [false,true])
        out.push(f(binary ? Buffer.from(h) : h,content,origin));
    }
    return out;
  `,
  framing: `
    const f = SOURCE; const out = [];
    for (const method of ['DELETE','OPTIONS','GET','POST'])
      for (const length of [undefined,'0','12','',0,null]) for (const transfer of [undefined,'chunked','']) {
        const headers = {}; if (length !== undefined) headers['content-length'] = length;
        if (transfer !== undefined) headers['transfer-encoding'] = transfer;
        const req = {method,headers}; f(req,{},{}); out.push(req);
      }
    for (const headers of [undefined,null]) for (const method of ['GET','DELETE']) {
      const req={method,headers};
      try {f(req,{},{});out.push({req});} catch(e) {out.push({error:e.name});}
    }
    return out;
  `,
  redirect_url: `
    const f = SOURCE; const out = [];
    for (const location of ['/safe','http://localhost//evil.test/x?y=1#z',
      'https://example.test///evil.test','//example.test/path','/a%2Fb','/\\\\evil.test'])
      for (const external of [false,true]) out.push(f(location,external));
    return out;
  `,
  proxy_redirect: `
    const getProxyForUrl = () => '', shouldBypassProxy = () => false;
    const AxiosError = Error;
    const setProxy = HELPER;
    let configProxy; const f = SOURCE; const out = [];
    for (const proxy of [false, {hostname:'proxy.test',port:8080,auth:'new:secret',protocol:'http'}]) {
      configProxy = proxy;
      const options = {href:'https://target.test/',hostname:'target.test',port:443,
        headers:{'Proxy-Authorization':'old','proxy-authorization':'old2',safe:'keep'},beforeRedirects:{}};
      f(options); out.push({headers:options.headers,host:options.hostname,path:options.path});
    }
    return out;
  `,
  minimist_set: `
    const flags = {bools:{}}; const isConstructorOrProto = HELPER;
    const f = SOURCE; const out = [];
    for (const keys of [['safe'],['nested','safe'],['__proto__','polluted'],
      ['constructor'],['constructor','prototype','polluted'],['safe','__proto__']]) {
      for (const initial of [{}, {safe:false}, {safe:[1]}]) {
        const obj = JSON.parse(JSON.stringify(initial));
        f(obj,keys.slice(),'marker');
        out.push({obj,constructorType:typeof obj.constructor,
          ownConstructor:Object.hasOwn(obj,'constructor'),polluted:({}).polluted});
      }
    }
    return out;
  `,
  quoted_address: `
    const addressparser = () => {throw new Error('out-of-scope group parser');};
    const f = SOURCE; const out = [];
    const text = value => ({type:'text',value}); const op = value => ({type:'operator',value});
    for (const tokens of [[],[text('user@example.test')],
      [text('Display'),op('<'),text('user@example.test'),op('>')],
      [op('"'),text('attacker@evil.test'),op('"'),text('@example.test')],
      [op('"'),text('Display attacker@evil.test name'),op('"'),text('@example.test')],
      [op('('),text('Comment'),op(')'),text('user@example.test')]]) out.push(f(tokens));
    return out;
  `,
  jwt_policy: `
    class ParseError extends Error { constructor(code,message) {super(message);this.code=code;} }
    ParseError.OBJECT_NOT_FOUND=101; const Parse={Error:ParseError};
    const TOKEN_ISSUER='issuer', HTTPS_TOKEN_ISSUER='https://issuer';
    let algorithm,claims,trace,throws;
    const authUtils={getHeaderFromToken:()=>({kid:'key',alg:algorithm})};
    const key = async (...args) => {trace.push({key:args}); return {publicKey:'PUBLIC'};};
    const getAppleKeyByKeyId=key, getFacebookKeyByKeyId=key, getGoogleKeyByKeyId=key;
    const jwt={verify:(token,signingKey,options)=>{
      trace.push({token,signingKey,options}); if(throws) throw new Error('bad signature'); return claims;
    }};
    const f = SOURCE; const out=[];
    for (algorithm of ['HS256','RS256','none']) for (const cache of [undefined,0,null,10])
      for (const scenario of ['normal','bad_signature','wrong_issuer','wrong_subject','missing']) {
        trace=[]; throws=scenario==='bad_signature';
        claims={iss:scenario==='wrong_issuer'?'bad':TOKEN_ISSUER,sub:scenario==='wrong_subject'?'bad':'id',aud:'client'};
        const token=scenario==='missing'?'':'encoded';
        let value; try {value=await f({token,id_token:token,id:'id'}, {clientId:'client',cacheMaxAge:cache,cacheMaxEntries:cache});}
        catch(e) {value={error:e.message,code:e.code};}
        out.push({trace,value});
      }
    return out;
  `,
};

// Normalization wraps an extracted function/method; it does not rewrite its body.
function expression(source, language) {
  const wrappers = [s => '('+s+'\n)', s => 'Object.values({'+s+'\n})[0]'];
  const errors=[];
  for (const wrap of wrappers) {
    try {
      let code=wrap(source);
      if(language==='typescript') code=stripTypeScriptTypes(code,{mode:'strip'});
      new vm.Script(code);
      return code;
    } catch(e) {errors.push(e.message);}
  }
  throw new Error('Cannot wrap extracted function: '+errors.join('; '));
}

(async () => {
  if (!harnesses[input.harness]) throw new Error('Unknown harness');
  const observations=[];
  for(let i=0;i<input.sources.length;i++) {
    let phase='compile';
    try {
      let code=harnesses[input.harness].replace('SOURCE',()=>expression(input.sources[i],input.language));
      if (code.includes('HELPER')) code=code.replace('HELPER',()=>expression(input.helpers[i],'javascript'));
      new vm.Script('(async()=>{'+code+'})()');
      phase='execute';
      const result=await vm.runInNewContext('(async()=>{'+code+'})()', {URL,Buffer},
        {timeout:1500,contextCodeGeneration:{strings:false,wasm:false}});
      observations.push({ok:true,value:JSON.parse(JSON.stringify(result))});
    } catch(e) {observations.push({ok:false,phase,error:e.name+': '+e.message});}
  }
  process.stdout.write(JSON.stringify({node:process.version,observations}));
})().catch(e=>{process.stderr.write(e.stack);process.exitCode=1;});
