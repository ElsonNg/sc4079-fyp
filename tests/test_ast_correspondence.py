"""Independent controls for expanded copied-function correspondence."""
import pytest
from eval.ablation.ast_correspondence import ast_form, compare_ast


@pytest.fixture(params=["experiment", "production"], autouse=True)
def correspondence_implementation(request, monkeypatch):
    """Run independent syntax and safety controls against both implementations."""
    if request.param == "production":
        from provtrail.pipeline.controller import ast_correspondence
        monkeypatch.setitem(globals(), "ast_form", ast_correspondence.ast_form)
        monkeypatch.setitem(globals(), "compare_ast", ast_correspondence.compare_ast)


V = 'function get(obj,key){return obj[key];}'
P = 'function get(obj,key){if(key === "blocked") return undefined; return obj[key];}'


@pytest.mark.parametrize("source", [
    'function renamed(value,name){if(name === "blocked") return undefined; return value[name];}',
    "function renamed(value,name){if(name === 'blocked') { return undefined; } return value[name];}",
    'function renamed(value,name){if(name === "blocked") return undefined; const answer=value[name]; return answer;}',
    'function renamed(value,name){if(name === "blocked") return undefined; let answer=value[name]; return answer;}',
    'function renamed(value: any,name: string): any {if(name === "blocked") return undefined; return value[name];}',
])
def test_patched_rewrites(source):
    assert compare_ast(V,P,source,'candidate.ts')['status']=='patched'


@pytest.mark.parametrize("source", [
    P.replace('key ===','obj ==='), P.replace('===','=='), P.replace('blocked','other'),
    P.replace('return obj[key]','return obj.other'), P.replace('return obj[key]','return obj[other]'),
    P.replace('if(key','if(flag && key'), P.replace('{if','{if(flag) return obj[key]; if'),
    P.replace('return obj[key]','audit(obj); return obj[key]'),
    P.replace('return obj[key]','key=other; return obj[key]'),
    P.replace('return obj[key]','const answer=obj[key]; return obj[key];'),
    P.replace('return obj[key]','return get(obj,key);'),
    P.replace('return obj[key]','return obj[key].name'),
    P+' sideEffect();', 'async '+P, P.replace('obj,key','obj,key=other'),
])
def test_security_changes_do_not_match(source):
    assert compare_ast(V,P,source)['status']=='uncertain'


@pytest.mark.parametrize("a,b", [
    ('async function f(x){const y=await read(x); if(y) return y; throw Error("bad");}',
     'async function z(input){let value=await read(input); if(value){return value;} throw Error("bad");}'),
    ('function f(x){for(let i=0;i<x.length;i++){if(x[i])return x[i];} return null;}',
     'function z(list){for(let index=0;index<list.length;index++){if(list[index]){return list[index];}} return null;}'),
    ('function f(x){return x.map(value=>{const y=read(value);return y;});}',
     'function z(list){return list.map(item=>{return read(item);});}'),
    ('function f(x){try{return read(x);}catch(e){return e.message;}}',
     'function z(input){try{return read(input);}catch(error){return error.message;}}'),
    ('function f({token,value}, [a,b]){return token+a+value+b;}',
     'function z({token:key,value:data},[c,d]){return key+c+data+d;}'),
    ('function f(x){const y=x; return {y};}',
     'function z(input){const value=input; return {y:value};}'),
    ('function f(x){if(x)throw Error("bad");else{return read(x);}}',
     'function z(input){if(input){throw Error("bad");} return read(input);}'),
    ('function f(x){for(const y of x){consume(y);}return x;}',
     'function z(input){for(const item of input){consume(item);}return input;}'),
    ('function f(x){var y=x; var y; return y;}',
     'function z(input){var value=input; var value; return value;}'),
    ('function f(x){let y=x;{let y=other;consume(y);}return y;}',
     'function z(input){let first=input;{let second=other;consume(second);}return first;}'),
])
def test_binding_control_flow_and_complex_syntax(a,b):
    assert ast_form(a)==ast_form(b)


@pytest.mark.parametrize("a,b", [
    ('function f(x){let y=x;{let y=other;consume(y);}return y;}',
     'function z(input){let first=input;{let second=other;consume(first);}return first;}'),
    ('function f(x){const y=x;return {y};}',
     'function z(input){const value=input;return {value};}'),
    ('function f(x){return check(x);}', 'function z(input){return otherCheck(input);}'),
    ('function f(x){if(x)return first();return second();}',
     'function z(input){if(input)return second();return first();}'),
    ('function f(x){return (x?.child).value;}', 'function z(input){return input?.child.value;}'),
    ('function f(x){const y=x; return y;}', 'function z(input){let value=input; value=other; return value;}'),
    ('function f(x){return x+1;}', 'function z(input){return input+2;}'),
    ('function f(x){const {token}=x; return token;}', 'function z(input){const {other:key}=input; return key;}'),
    ('function f(x){return "a\\n";}', 'function z(input){return "a\\r";}'),
    ('function f(x){if(x)consume(x);return x;}', 'function z(input){if(input)consume(input);else consume(input);return input;}'),
    ('function f(x){if(x)throw Error();return x;}', 'function z(input){if(input)return Error();return input;}'),
    ('function f(x){return read(x);}', 'function z(input){return await read(input);}'),
    ('function f(__proto__){return {__proto__};}', 'function z(input){return {__proto__:input};}'),
])
def test_meaningful_differences_remain_distinct(a,b):
    assert ast_form(a)!=ast_form(b)


@pytest.mark.parametrize("source", [
    'function f(x){return eval(x);}', 'function f(x){return arguments[0];}',
    'function f(x){with(x){return value;}}', 'function f(x){return f.name;}',
    'function f(x){const alias=f;return alias["name"]}',
    'function f(x){const g=()=>x;return g.toString();}',
    'f(x){return this.f(x);}',
    'function f(x){let alias;alias=f;return alias.name;}',
    'function f(x){if(x){function helper(){return x;}}return helper;}',
    'function f(undefined){return undefined;}',
    'f(x){return this["f"](x);}',
])
def test_reflection_and_dynamic_scope_abstain(source):
    assert compare_ast('function f(x){return x;}',source,source)['status']=='uncertain'


def test_dead_void_branch_is_an_explicit_arm():
    candidate=P.replace('{if','{if(false){void 0;} if',1)
    assert compare_ast(V,P,candidate)['status']=='uncertain'
    assert compare_ast(V,P,candidate,remove_noop=True)['status']=='patched'
    for body in ('var secret;', 'let secret;', 'function secret(){}', 'sideEffect();'):
        altered=P.replace('{if','{if(false){'+body+'} if',1)
        assert compare_ast(V,P,altered,remove_noop=True)['status']=='uncertain'


def test_no_reference_distinction_is_not_a_verdict():
    assert compare_ast(P,P,P)['status']=='uncertain'


def test_same_function_method_name_is_not_enough():
    assert compare_ast(V,P,'function get(x){return unrelated(x);}')['status']=='uncertain'


def test_prior_patch_can_still_be_later_vulnerable():
    earlier='function get(obj,key){if(key === "blocked") return undefined; return obj[key];}'
    later=earlier.replace('key === "blocked"','key === "blocked" || key === "another"')
    candidate=earlier.replace('obj','value').replace('key','name')
    assert compare_ast(V,earlier,candidate)['status']=='patched'
    assert compare_ast(earlier,later,candidate)['status']=='vulnerable'
