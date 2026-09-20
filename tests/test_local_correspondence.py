"""Fail-closed controls for the optional whole-function correspondence fallback."""
import pytest

from provtrail.pipeline.controller.local_correspondence import compare_regex, compare_structural, decide_local_correspondence

GV='function get(obj,key){return obj[key];}'
GP='function get(obj,key){if(key === "blocked") return undefined; return obj[key];}'
OV='function read(obj,key){if(isNil(obj)) return obj; obj=toLiquid(obj); return readJSProperty(obj,key);}'
OP='function read(obj,key){obj=toLiquid(obj); if(isNil(obj)) return obj; return readJSProperty(obj,key);}'
RV='function check(input){return /a+/.test(input);}'
RP='function check(input){return /^a+$/.test(input);}'

# All negatives are different or unsupported code, not alternate vuln labels.
CONTROLS=[
 ('guard_v','guard',GV,'vulnerable'),
 ('guard_p','guard',GP,'patched'),
 ('renamed','guard','function renamed(value,name){if(name === "blocked") return undefined; return value[name];}','patched'),
 ('return_temp','guard','function get(obj,key){if(key === "blocked") return undefined; const answer=obj[key]; return answer;}','patched'),
 ('ternary','guard','function get(obj,key){return key === "blocked" ? undefined : obj[key];}','patched'),
 ('wrong_input','guard',GP.replace('key ===','obj ==='),'uncertain'),
 ('weak_operator','guard',GP.replace('===','=='),'uncertain'),
 ('wrong_literal','guard',GP.replace('blocked','other'),'uncertain'),
 ('partial_guard','guard',GP.replace('if(key','if(flag && key'),'uncertain'),
 ('bypass','guard',GP.replace('{if','{if(flag) return obj[key]; if'),'uncertain'),
 ('late_guard','guard','function get(obj,key){const answer=obj[key]; if(key === "blocked") return undefined; return answer;}','uncertain'),
 ('ignored_guard','guard','function get(obj,key){key === "blocked"; return obj[key];}','uncertain'),
 ('mutation','guard',GP.replace('return obj[key]','key=other; return obj[key]'),'uncertain'),
 ('side_effect','guard',GP.replace('return obj[key]','audit(obj); return obj[key]'),'uncertain'),
 ('double_read','guard',GP.replace('return obj[key]','obj[key]; return obj[key]'),'uncertain'),
 ('async_guard','guard','async '+GP,'uncertain'),
 ('generator','guard',GP.replace('function get','function* get'),'uncertain'),
 ('default_param','guard',GP.replace('obj,key','obj,key=sideEffect()'),'uncertain'),
 ('extra_param','guard',GP.replace('obj,key','obj,key,extra'),'uncertain'),
 ('rest_param','guard',GP.replace('obj,key','obj,...key'),'uncertain'),
 ('destructure','guard',GP.replace('obj,key','{obj},key'),'uncertain'),
 ('duplicate_binding','guard',GP.replace('obj,key','obj,obj'),'uncertain'),
 ('shadowed_block','guard',GP.replace('return obj[key]','{ let obj=other; return obj[key]; }'),'uncertain'),
 ('shadowed_parameter','guard',GP.replace('return obj[key]','var obj=other; return obj[key]'),'uncertain'),
 ('trailing_code','guard',GP+'; sideEffect();','uncertain'),
 ('second_function','guard',GP+' function extra(){sideEffect();}','uncertain'),
 ('try','guard','function get(obj,key){try {if(key === "blocked") return undefined; return obj[key];} catch(e){return obj[key];}}','uncertain'),
 ('loop','guard',GP.replace('return obj[key]','while(flag) { sideEffect(); } return obj[key]'),'uncertain'),
 ('order_v','order',OV,'vulnerable'),
 ('order_p','order',OP,'patched'),
 ('order_alias','order','function read(input,key){const value=toLiquid(input); if(isNil(value)) return value; return readJSProperty(value,key);}','patched'),
 ('global_write','order','function read(obj,key){globalValue=toLiquid(obj); if(isNil(globalValue)) return globalValue; return readJSProperty(globalValue,key);}','uncertain'),
 ('stale_guard','order','function read(obj,key){const value=toLiquid(obj); if(isNil(obj)) return obj; return readJSProperty(value,key);}','uncertain'),
 ('stale_use','order','function read(obj,key){const value=toLiquid(obj); if(isNil(value)) return value; return readJSProperty(obj,key);}','uncertain'),
 ('order_mutation','order',OP.replace('if(isNil','obj=other; if(isNil'),'uncertain'),
 ('wrong_converter','order',OP.replace('toLiquid(obj)','toLiquid(key)'),'uncertain'),
 ('late_conversion','order',OP.replace('obj=toLiquid(obj);','setImmediate(()=>toLiquid(obj));'),'uncertain'),
 ('async_order','order','async '+OP,'uncertain'),
 ('regex_v','regex',RV,'vulnerable'),
 ('regex_p','regex',RP,'patched'),
 ('regex_temp','regex','function check(value){const yes=/^a+$/.test(value); return yes;}','patched'),
 ('regex_changed','regex',RP.replace('^a+$','^b+$'),'uncertain'),
 ('regex_flags','regex',RP.replace('/.test','/i.test'),'uncertain'),
 ('regex_wrong_argument','regex',RP.replace('.test(input)','.test(other)'),'uncertain'),
 ('regex_discard','regex',RP.replace('return /^a+$/.test(input);','/^a+$/.test(input); return true;'),'uncertain'),
 ('regex_negation','regex',RP.replace('return /','return !/'),'uncertain'),
 ('regex_bypass','regex',RP.replace('{return','{if(flag) return true; return'),'uncertain'),
 ('regex_mutation','regex',RP.replace('{return','{input=other; return'),'uncertain'),
 ('regex_async','regex','async '+RP,'uncertain'),
 ('regex_default','regex',RP.replace('(input)','(input=sideEffect())',1),'uncertain'),
 ('regex_extra_param','regex',RP.replace('(input)','(input,extra)',1),'uncertain'),
 ('regex_arrow','regex','input => /^a+$/.test(input)','uncertain'),
 ('regex_outer','regex',RP+' sideEffect();','uncertain'),
]

def check(kind,candidate):
    if kind=='regex':return compare_regex(RV,RP,candidate)
    return compare_structural(GV if kind=='guard' else OV,GP if kind=='guard' else OP,candidate,kind)

@pytest.mark.parametrize('name,kind,candidate,expected',CONTROLS,ids=[c[0] for c in CONTROLS])
def test_controls(name,kind,candidate,expected):
    assert check(kind,candidate)['status']==expected

@pytest.mark.parametrize('v,p,c',[
 ('function f(x){return {safe};}','function f(x){if(x) return undefined; return {safe};}',
  'function f(x){if(x) return undefined; return {unsafe};}'),
 ('function f(x){return x;}','function f(x){return arguments[0];}',
  'function f(x){const copy=arguments[0]; return copy;}'),
 ('function f(x){return x;}','function f(x){return y; const y=x;}',
  'function f(x){return y; const y=x;}'),
 ('function f(x){return x;}','function f(x){const y=y; return y;}',
  'function f(x){const z=y; return z;}'),
 ('function f(x){return x;}','function f(x){return eval(x);}',
  'function f(x){return eval(x);}'),
 ('function f(x){return x;}','function f(x){return f(x);}',
  'function renamed(x){return f(x);}'),
])
def test_binding_and_property_edges(v,p,c):
    assert compare_structural(v,p,c,'guard')['status']=='uncertain'

def test_multi_change_regex_reference_abstains():
    assert compare_regex(RV,RP.replace('(input)','(input,extra)',1),RP)['status']=='uncertain'

def test_combined_decision_uses_one_decisive_recognizer():
    result=decide_local_correspondence(GV,GP,GP)
    assert result['status']=='patched'
    assert result['decisive']=={'guard':'patched'}

def test_combined_decision_abstains_when_nothing_bounded_applies():
    result=decide_local_correspondence(GV,GP,'function unrelated(x){return other(x);}')
    assert result['status']=='uncertain'
    assert not result['decisive']
