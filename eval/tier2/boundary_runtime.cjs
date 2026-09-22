// Shared v6+ test runtime; preserve this file once referenced by a sealed run.
const vm=require('node:vm');
const {stripTypeScriptTypes}=require('node:module');
function expression(source,language,adapter){
  const wrappers=[s=>'('+s+'\n)',s=>'Object.values({'+s+'\n})[0]',
    s=>'Object.entries(Object.getOwnPropertyDescriptors(class{'+s+'\n}.prototype)).filter(([k,v])=>k!=="constructor"&&typeof v.value==="function")[0][1].value'];
  if(adapter?.name&&/^[A-Za-z_$][\w$]*$/.test(adapter.name))wrappers.push(s=>'(()=>{'+s+'\nreturn '+adapter.name+';})()');
  for(const wrap of wrappers){try{let code=wrap(source);if(language==='typescript')code=stripTypeScriptTypes(code,{mode:'strip'});new vm.Script(code);return code;}catch{}}
  new vm.Script(language==='typescript'?stripTypeScriptTypes(source,{mode:'strip'}):source);
  const error=new Error('Valid program needs an explicit callable entry point');error.name='HarnessAdapterError';throw error;
}
const prelude=`const capture=async cb=>{try{const value=await cb();return value===undefined?{valueKind:'undefined'}:{value};}catch(e){return {error:e.message,name:e.name,code:e.code};}};`;
module.exports=async function run(harnesses,globals={}){
  const input=JSON.parse(require('node:fs').readFileSync(0,'utf8'));
  if(!harnesses[input.harness])throw new Error('Unknown harness');const observations=[];
  for(let i=0;i<input.sources.length;i++){
    let phase='compile';try{
      const context=input.contextCode?(input.contextLanguage==='typescript'?stripTypeScriptTypes(input.contextCode,{mode:'strip'}):input.contextCode):'';
      const body=harnesses[input.harness].replace('CONTEXT',()=>context).replace('SOURCE',()=>expression(input.sources[i],input.language,input.adapters?.[i]));
      const code='(async()=>{'+prelude+body+'})()';new vm.Script(code);phase='execute';
      const value=await vm.runInNewContext(code,globals,{timeout:1500,contextCodeGeneration:{strings:false,wasm:false}});
      observations.push({ok:true,value:JSON.parse(JSON.stringify(value))});
    }catch(e){observations.push({ok:false,phase:e.name==='HarnessAdapterError'?'adapter':phase,error:e.name+': '+e.message});}
  }
  process.stdout.write(JSON.stringify({node:process.version,observations}));
};
