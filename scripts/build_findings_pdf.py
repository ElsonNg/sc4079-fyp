import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tmp/pdfs/packages'))
import json, statistics, hashlib
from xml.sax.saxutils import escape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from pypdf import PdfReader

OUT = ROOT / 'output/pdf/provtrail-findings-and-ablation.pdf'
OUT.parent.mkdir(parents=True, exist_ok=True)
sources = {}
def read(path):
    p = ROOT / path
    sources[path] = hashlib.sha256(p.read_bytes()).hexdigest()
    return json.loads(p.read_text(encoding='utf-8'))
DERIVED = 'eval/comparison_raw/hash-rule-summary-v1/'
component = read(DERIVED+'active-component-ablation-gpu-v1/summary.json')
gpu = read(DERIVED+'active-shortlist-gpu-v1/summary.json')
tuning = read(DERIVED+'active-tuning-v2/summary.json')
cpu_eval = read(DERIVED+'active-evaluation-shortlist-v2/summary.json')
llm_review = read(DERIVED+'llm-review/summary.json')
operating = read(DERIVED+'operating-point-summary.json')['metrics']
parity = read('eval/frozen/active-shortlist-gpu-v1/combined/cpu-gpu-comparison.json')
stress = read('eval/frozen/containment-targeted-100-gpu-v1/combined/summary.json')
read('eval/comparison_raw/sca-copy-v1/verification.json')
read('eval/comparison_raw/sast-ten-v1/final-results.json')
read('eval/comparison_raw/sast-ten-dependencies-v1/paired-results.json')

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name='TitleX', fontName='Helvetica-Bold', fontSize=24, leading=28, textColor=colors.HexColor('#14334b'), spaceAfter=15))
styles.add(ParagraphStyle(name='SubX', fontName='Helvetica-Bold', fontSize=13, leading=17, textColor=colors.HexColor('#146b72'), spaceBefore=13, spaceAfter=7))
styles.add(ParagraphStyle(name='BodyX', fontSize=9.5, leading=13.8, spaceAfter=8))
styles.add(ParagraphStyle(name='SmallX', fontSize=8, leading=11, spaceAfter=7, textColor=colors.HexColor('#405365')))
styles.add(ParagraphStyle(name='CellX', fontSize=8, leading=10.5))
styles.add(ParagraphStyle(name='HeadX', fontName='Helvetica-Bold', fontSize=8, leading=10, textColor=colors.white))
story=[]
def p(text, style='BodyX'):
    story.append(Paragraph(text, styles[style]))
def h(text): p(text,'SubX')
def page(num,title,subtitle):
    if story: story.append(PageBreak())
    p(f'PROVTRAIL / FINDINGS &amp; ABLATION / {num:02d}', 'SmallX')
    p(title,'TitleX');p(subtitle,'SmallX')
def table(headers,rows,widths=None,small=False):
    cells=[[Paragraph(escape(str(x)),styles['HeadX']) for x in headers]]
    cells += [[Paragraph(escape(str(x)),styles['CellX']) for x in row] for row in rows]
    t=Table(cells,colWidths=widths,repeatRows=1,hAlign='LEFT')
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#14334b')),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),7 if not small else 4),('RIGHTPADDING',(0,0),(-1,-1),7 if not small else 4),('TOPPADDING',(0,0),(-1,-1),7 if not small else 5),('BOTTOMPADDING',(0,0),(-1,-1),7 if not small else 5),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.HexColor('#eef4f6'),colors.white]),('LINEBELOW',(0,0),(-1,0),.5,colors.HexColor('#146b72'))]))
    story.extend([t,Spacer(1,9)])
def fraction(x): return f"{x['count']}/{x['denominator']} ({100*x['rate']:.2f}%)"
def subset(data,name,tier,split='full'):
    return next(s for s in data['summaries'] if s['configuration']==name and s['tier']==tier and s['split']==split and s['scope']=='all')
def times(data,name):
    parts=[t['total_seconds_per_pass'] for t in data['timing'] if t['configuration']==name and t['split']=='full' and t['scope']=='all']
    return [sum(v) for v in zip(*parts)]
def source(text):p('Evidence: '+text,'SmallX')

page(1,'Findings and ablation','Corrected hash-rule edition | 30 September 2026 | Saved-evidence recomputation; no new scans or model calls')
p('<b>Main conclusion:</b> ProvTrail can recognize code matching known vulnerable implementations even when the source package is not declared as a dependency. This complements the tested SAST and dependency-SCA configurations. The experiments do not establish application exploitability or detection of novel vulnerabilities.')
h('Recommended operating point')
p('<b>K5/B10, R96/V3, containment OFF, hashing ON, contrastive scoring ON, LLM OFF.</b> Structure/token thresholds 0.70; edit-side threshold 0.90; margin 0.10. CUDA FP32 embeddings with the frozen CPU reference index. This is a supported balance among tested settings, rather than a proven global optimum.')
p('<b>Revision:</b> exact hashes determine the fix side when abstracted hashes match both sides. Abstracted-only ambiguity remains for review without a contradiction label. Quality is recomputed from preserved evidence; timing and repetition claims describe the original runs.','SmallX')
table(['Report section','Primary evidence','What it establishes'],[
('Main findings','600 release-source + 600 transformed cases','Known-origin recognition, attribution, false alerts and abstention'),
('Parameter ablation','38 CPU tuning settings; 4 evaluation settings; 3 GPU repetitions','Sensitivity to thresholds, K, budgets and region caps'),
('Component ablation','4 settings x 1,200 cases x 3 GPU repetitions','Contribution of hashing, contrastive scoring and containment'),
('Containment stress test','100 designed cases; on/off; 3 repetitions','No aggregate detection gain; exposes benign review burden'),
('Tool comparison','10 advisories, SAST metadata arms, SCA declared/copy arms','Complementary coverage when copied code lacks package declarations'),
('LLM review','119 selected-boundary reviews; completed local/hosted studies','Recall, false-alert and dismissal tradeoffs')],[105,168,234])
h('How to use this document')
p('Use pages 2-7 for the main findings and ablation tables. Page 8 gives reporting limits and an evidence map. Pages 9-10 list every CPU tuning configuration. Keep denominators and workload conditions visible when copying tables.')
p('<b>Counting:</b> the main cohort contains 601 vulnerable and 599 patched cases. Repetitions establish stability and timing; they do not increase the number of independent quality examples. The tool comparison contains ten advisory units, with correlated original/renamed variants.','SmallX')

page(2,'Main detector findings','K5/B10 with containment OFF | Corrected quality replay; original GPU timing retained')
a=subset(component,'no_containment','tier1'); b=subset(component,'no_containment','tier2')
rows=[]
for label,key in [('Automatic vulnerable recall','automatic_vulnerability_recall_all'),('Correct-origin automatic recall','correct_origin_automatic'),('Automatic precision','automatic_vulnerability_precision'),('Patched false-alert rate','patched_fpr_all'),('Manual-review abstention','abstained'),('Vulnerable abstention','positive_abstention'),('Patched abstention','patched_abstention')]:
    x,y=a[key],b[key]; comb={'count':x['count']+y['count'],'denominator':x['denominator']+y['denominator']};comb['rate']=comb['count']/comb['denominator']
    rows.append((label,fraction(x),fraction(y),fraction(comb)))
table(['Metric','Tier 1: release source','Tier 2: transformed','Combined'],rows,[147,120,120,120])
h('Retrieval and automatic decisions measure different things')
table(['Hybrid retrieval','Tier 1','Tier 2'],[(f'Recall@{k}',f"{a['retrieval'][f'recall_at_{k}']*100:.2f}%",f"{b['retrieval'][f'recall_at_{k}']*100:.2f}%") for k in (1,5,10)]+[('MRR',f"{a['retrieval']['mrr']:.4f}",f"{b['retrieval']['mrr']:.4f}")],[247,130,130])
p('All 601 vulnerable-labelled cases reached an automatic alert or manual review. This is <b>routing coverage</b>, not 100% automatic detection or correct-advisory attribution. Five automatic positives lacked a correct-origin vulnerable verdict.')
p('The corrected queue contains <b>596 automatic alerts</b> (564 vulnerable-labelled, 32 patched-labelled) and <b>118 reviews</b>. The Next.js tuning case changes from review to an exact vulnerable-side finding; all other main-cohort verdicts are unchanged. Automatic patched disposition remains 486/599. Original median detector time: <b>349.413 seconds (5.82 minutes)</b>; revised runtime has not been measured.')
h('Interpretation for the report')
p('Release-source correct-origin automatic recall is now <b>300/300 (100%)</b>, versus 86.05% on transformed candidates. This is performance against advisory-labelled known-origin cases, not proof of exploitability. Report abstentions alongside recall rather than quoting conditional recall alone.')
source('eval/comparison_raw/hash-rule-summary-v1/operating-point-summary.json and active-component-ablation-gpu-v1/summary.json; original runs remain under eval/frozen/.')

page(3,'Parameter ablation','CPU tuning/evaluation followed by GPU validation of four independent alternatives')
p('Original runs: <b>38 CPU settings x 359 tuning cases</b>; four settings x <b>841 evaluation cases</b>; three full-cohort GPU repetitions per shortlisted setting. The corrected replay changes one Tier 1 tuning case in every hash-enabled setting. All parameter evaluation-partition outcomes are unchanged. The grouped split is retrospective, not a pristine holdout.')
h('GPU evaluation: the 422 transformed-clone cases')
rows=[]
for name in ('control','S0.80','R64','K5_B10'):
    s=subset(gpu,name,'tier2','evaluation')
    rows.append((name.replace('control','Baseline').replace('_','/'),fraction(s['automatic_vulnerability_recall_all']),fraction(s['correct_origin_automatic']),fraction(s['patched_fpr_all']),str(s['abstained']['count'])))
table(['Setting','Auto recall','Origin recall','Patched FPR','Reviews / 422'],rows,[83,117,117,117,73])
p('Tier 1 evaluation is identical in all four: 210/210 vulnerable detections, 7/209 patched false alerts and zero abstentions. Hash recognition makes this tier insensitive to the tested region controls.','SmallX')
h('GPU timing: full 1,200-case passes')
rows=[]
baseline=statistics.median(times(gpu,'control'))
for name in ('control','S0.80','R64','K5_B10'):
    values=times(gpu,name);med=statistics.median(values)
    rows.append((name.replace('control','Baseline').replace('_','/'),', '.join(f'{v:.1f}' for v in values),f'{med:.1f}s',f'{(med/baseline-1)*100:+.1f}%'))
table(['Setting','Seconds: repeats 1 / 2 / 3','Median','Change vs baseline'],rows,[92,230,75,110])
p('<b>K5/B10:</b> preserves evaluation detection/error counts with four extra reviews; the full-cohort GPU speed difference is only about 2%. <b>S0.80:</b> six fewer reviews but two fewer correct detections and no evaluation FP reduction. <b>R64:</b> about 25% faster, but four fewer net correct-origin detections and one fewer FP. These alternatives were not combined.')
p('CPU evaluation showed the same origin/FP tradeoffs, but single-pass speed reductions were larger (K5 about 19%; R64 about 38%). Do not transfer those percentages to GPU. GPU repeats reproduced decisions/ranks. Each setting differs from its CPU counterpart in 131-139 tracked cases, mainly intermediate ranks/evidence; K5 also changes one priority/abstention.','SmallX')
source('Recomputed quality: eval/comparison_raw/hash-rule-summary-v1/active-{tuning-v2,evaluation-shortlist-v2,shortlist-gpu-v1}/summary.json. Timings and CPU/GPU parity are original frozen measurements.')

page(4,'Component ablation','K5/B10 control, containment ON | Corrected quality replay of one-component removals')
for tier,title in [('tier1','Tier 1: 300 vulnerable + 300 patched'),('tier2','Tier 2: 301 vulnerable + 299 patched')]:
    h(title)
    rows=[]
    for name in ('control','no_hash','no_containment','no_contrastive'):
        s=subset(component,name,tier)
        rows.append((name.replace('_',' '),fraction(s['automatic_vulnerability_recall_all']),fraction(s['correct_origin_automatic']),fraction(s['patched_fpr_all']),str(s['abstained']['count'])))
    table(['Setting','Auto recall','Origin recall','Patched FPR','Reviews / 600'],rows,[97,112,112,112,74])
h('What each removal demonstrates')
p('<b>Remove hashing:</b> corrected Tier 1 origin detections fall 300 to 269, patched alerts rise 13 to 28, and reviews rise 0 to 146. The no-hash run itself is unchanged. Tier 2 origin detections fall 259 to 250. Hash recognition is a substantial contributor, especially for release-source reuse.')
p('<b>Remove contrastive scoring:</b> Tier 2 correct-origin detections fall 259 to 231 and reviews rise 128 to 188; patched alerts remain 19. Comparing vulnerable and patched fix-side evidence contributes to automatic discrimination on transformed candidates.')
p('<b>Remove containment:</b> automatic detection and patched-alert counts remain unchanged. Tier 2 reviews fall 128 to 118, with Tier 1 unchanged. This directly tests the recommended <b>K5/B10 + containment OFF</b> combination; it is not inferred by merging separate parameter results.')
h('Timing caveat')
p('Median full-pass detector times: control 318.6s; no hash 1,029.3s; no containment 349.4s; no contrastive 334.3s. The component batches ran under different conditions, and one no-hash repetition spans an interruption. These timings support workload observations, but do <b>not</b> establish that disabling containment speeds up the full cohort. The targeted study on page 5 is the cleaner containment timing comparison.','SmallX')
source('eval/comparison_raw/hash-rule-summary-v1/active-component-ablation-gpu-v1/summary.json and changes.json. First-pass quality replay; original study had three repetitions per setting. Historical timings retained.')

page(5,'Containment and review burden','Designed 100-case stress test | Ten advisory origins | Three repetitions per setting')
p('The stress set contains 40 vulnerable clones, 40 patched clones and 20 unrelated benign controls. It includes prefix/distributed additions and exact/rename controls. It is exploratory and designed to challenge containment; it is not a representative deployment sample.')
table(['Metric','Containment ON','Containment OFF'],[
('Automatic vulnerable recall','32/40 (80.00%)','32/40 (80.00%)'),
('Correct-origin recall','31/40 (77.50%)','31/40 (77.50%)'),
('Patched false alerts','3/40 (7.50%)','3/40 (7.50%)'),
('Benign automatic alerts','0/20','0/20'),
('Total manual reviews','34/100','34/100'),
('Benign manual reviews','20/20','20/20'),
('Median detector time','60.843s','55.363s')],[247,130,130])
p('Containment OFF was about <b>9% faster</b> here, with unchanged aggregate detection and false alerts. One case enters review and one leaves it, so equal review totals do not imply identical dispositions. Thirteen forced whole-function correspondence checks were rescued diagnostically; these were not additional final vulnerability detections.')
h('Main-cohort conflict audit')
table(['Observation at the final operating point','Count','Interpretation'],[
('Patched reviews already marked patched at expected boundary','45/81','Another uncertain boundary kept the case in review'),
('Patched false alerts already marked patched at expected boundary','30/32','Another boundary produced an automatic alert'),
('Vulnerable automatic alerts without correct-origin verdict','5','Binary alerting overstates correct attribution')],[270,55,182])
p('<b>Report finding:</b> containment provided no observed aggregate detection benefit in these tested workloads. Disabling it preserves quality and can reduce unnecessary abstentions. Avoid concluding that containment never helps, or that zero benign automatic alerts implies zero workload: every benign control still required review.')
p('<b>Next improvement:</b> audit fix-boundary attribution and conflicting evidence. A case labelled patched for one advisory may contain another genuine issue; do not automatically treat every additional-boundary alert as a confirmed false positive.','SmallX')
source('eval/frozen/containment-targeted-100-gpu-v1/combined/tables.md; active-component-ablation-gpu-v1/combined/operating-point-review.md and operating-point-case-audit.json.')

page(6,'SAST and dependency-SCA findings','Ten advisories across five packages | Same exact-copy and local-rename targets across paired arms')
h('SAST: target-overlapping alerts')
table(['Tool','Vulnerable: no metadata','Vulnerable: metadata added','Patched: both arms'],[
('ProvTrail','20/20','20/20','0/20'),('Semgrep Code','2/20','2/20','2/20'),('CodeQL','0/20','0/20','0/20')],[100,135,145,127])
p('Semgrep target alerts concern Validator rtrim custom-character regex handling; the selected advisory fixes default whitespace trimming. They persist on the patched variants. Therefore overlap is not intended-issue detection. CodeQL has background warnings, including related Vite access paths; zero target-overlap detections does not mean zero findings or no related coverage.')
p('Adding authentic upstream metadata (40 manifests; 20 available lockfiles) changes no selected-target outcome. It adds 28 Semgrep configuration warnings and four CodeQL background regex warnings. The conservative count of advisories with no SAST alerts anywhere falls from <b>6/10 to 3/10</b>. Installed dependencies and complete applications were not added.','SmallX')
h('SCA: declared versions versus undeclared copied implementations')
table(['Input condition','Semgrep Supply Chain','OSV-Scanner','ProvTrail'],[
('Declared vulnerable package','10/10','10/10','N/A: source absent'),
('Declared fixed package','0/10','0/10','N/A: source absent'),
('Copied vulnerable; package undeclared','0/20','0/20','20/20'),
('Copied patched; package undeclared','0/20','0/20','0/20')],[210,110,82,105])
p('Both SCA tools identified all declared package/version controls and read the valid empty inventories in copied projects. Reachable, unreachable and no-reachability-analysis findings all counted; the misses were not caused by an exploitability filter. This demonstrates a dependency-inventory coverage boundary for the tested configurations.')
p('<b>Scope:</b> the 20 vulnerable variants are ten exact reference copies and ten local renames. All ProvTrail detections used exact/abstracted hashes, with no embedding retrieval needed. There were 5,166 manual-review records across the 40 snapshots; these are workload, not confirmed false positives. Five advisories concern Undici. No external holdout or application exploitability claim follows.','SmallX')
p('Semgrep 1.177.0 used the available Pro cross-file engine and saved account policy; CodeQL 2.27.0 used security-extended; OSV-Scanner 2.6.0 used verified lockfile scans. Fresh Semgrep controls passed 12/12 unsafe and 12/12 safe sinks. No generative AI actions or findings uploads were requested.','SmallX')
source('eval/comparison_raw/sast-ten-v1/RESULTS.md; sast-ten-dependencies-v1/RESULTS.md; sca-copy-v1/RESULTS.md and verification.json.')

page(7,'LLM review and clone sensitivity','Reprojected saved reviews | No new model calls; no new latency or cost measurements')
p('The corrected baseline leaves <b>118 reviews</b> (37 vulnerable-labelled, 81 patched-labelled), with 40 expected-origin primary boundaries. Each original full study reviewed 119 cases; the now-automatic Next.js case is excluded from the revised projection. Hosted models have one saved pass; Qwen3 has three.')
def compact(x):return f"{x['count']} ({x['rate']*100:.2f}%)"
llm_rows=[('LLM OFF',*[compact(operating['combined'][k]) for k in ('automatic_vulnerability_recall_all','correct_origin_automatic','patched_fpr_all')],str(operating['combined']['abstained']['count']))]
for name,label in [('qwen3','Qwen3-8B'),('glm5','GLM-5'),('gemini_flash_lite','Gemini Flash-Lite'),('gemini_pro','Gemini Pro')]:
    matches=[r for r in llm_review['passes'] if r['name']==name]
    # Names are bound by the original hosted study, not guessed from labels.
    if not matches and name=='gemini_flash_lite':matches=[r for r in llm_review['passes'] if 'flash-lite' in str(r['model'])]
    assert matches,(name,[r['name'] for r in llm_review['passes']])
    for r in matches:
        q=r['groups']['combined']['triage_projection']
        llm_rows.append((label+(f" (r{r['repeat']})" if name=='qwen3' else ''),*[compact(q[k]) for k in ('automatic_vulnerability_recall_all','correct_origin_automatic','patched_fpr_all')],str(q['abstained']['count'])))
table(['Mode / reviewer','Vuln recall / 601','Origin recall / 601','Patched FPR / 599','Reviews / 1200'],llm_rows,[117,105,105,105,75])
retained=[]
for name in ('glm5','gemini_pro'):
    r=next(r for r in llm_review['passes'] if r['name']==name)
    retained.append(r['groups']['combined']['retain_scoped_patched_for_review']['triage_projection']['abstained']['count'])
flash=next(r for r in llm_review['passes'] if 'flash-lite' in str(r['model']))
p(f'Qwen review raises recall but substantially raises false alerts; seven vulnerable-labelled cases are dismissed per pass after excluding Next.js. GLM/Flash-Lite dismiss two each; Pro dismisses one. PATCHED applies to the reviewed advisory only. Retaining scoped dismissals leaves {retained[0]} GLM, {flash["groups"]["combined"]["retain_scoped_patched_for_review"]["triage_projection"]["abstained"]["count"]} Flash-Lite and {retained[1]} Pro cases unresolved.')
p('Aligned decisive accuracy remains GLM 39/40, Flash-Lite 38/40 and Pro 38/38 (now two aligned abstentions). Conditional denominators do not measure overall review accuracy. DeepSeek remains incomplete at 46/119 historical reviews. Reused 12-case pilots are development evidence.','SmallX')
h('Clone-detection comparison: optional supporting result')
table(['100 positive clone-intent candidates','Any reference linkage','Correct-origin linkage'],[
('ProvTrail hash + region retrieval','100/100','99/100'),
('jscpd near-miss pooled scan','85/100','85/100'),
('jscpd near-miss known source-pair scan','89/100','Known source pair provided')],[263,122,122])
p('This measures positive-only source-link sensitivity, not vulnerability classification, precision or false-positive rate. Type 3/4 labels describe generation intent and do not establish semantic-only clone categories. jscpd was faster in the single local timing observation; do not use this as a controlled throughput comparison.','SmallX')
source('eval/comparison_raw/hash-rule-summary-v1/llm-review/summary.json; original reviews preserved under eval/frozen/. Clone sensitivity: docs/jscpd-clone-pilot.md.')

page(8,'Claims, limits and evidence map','Suggested report structure and wording')
h('Findings section: claims supported by these runs')
for text in [
 '1. <b>Known-origin code reuse:</b> corrected replay gives automatic correct-origin recall of 100% for release-source targets and 86.05% for transformed candidates; combined patched false-alert rate is 5.34%, with 9.83% abstention.',
 '2. <b>Complementary tool coverage:</b> the tested dependency scanners recognize all declared vulnerable-version controls, while ProvTrail recognizes the corresponding exact/renamed implementations without source-package declarations.',
 '3. <b>Component contribution:</b> hashing and contrastive verification improve detection/attribution or reduce review burden. Containment can be disabled without observed aggregate detection loss in these workloads.',
 '4. <b>Parameter tradeoffs:</b> K5/B10 preserves shortlisted evaluation quality; R64 exchanges attribution quality for lower GPU time. S0.80 does not provide an unqualified evaluation improvement.',
 '5. <b>Review remains a cost:</b> report manual queues and conflicting advisory boundaries alongside recall. LLM confirmation trades recall, false alerts and false dismissals.']:
    p(text)
h('Limits to state explicitly')
p('Expected origins remain in the reference index; the cohorts have been inspected during development. The 30/70 grouped split is retrospective. Tier 1 advisory/source validity differs from stricter executable security-boundary validation. The older cumulative v43 pool is not the final refreshed active 600+600 cohort. Transformation admissions rely on recorded preservation evidence; blanket Type 3/4 or full semantic-equivalence claims are unsupported.')
p('Patched labels apply to selected fixes, not global absence of vulnerabilities. The ten-advisory tool study is small, correlated and limited to JS/TS npm fixtures with bounded context. SAST outcomes depend on rule/model/context coverage. SCA empty-inventory results are expected coverage boundaries. ProvTrail depends on reference coverage and does not guarantee exploitability.')
h('Evidence locations to cite in the report')
table(['Evidence group','Location under the repository'],[
('Inputs / split / model / index','eval/frozen/experiment-active-v2/manifest.json'),
('Corrected quality / review projections','eval/comparison_raw/hash-rule-summary-v1/'),
('Final operating point / components','eval/frozen/active-component-ablation-gpu-v1/combined/'),
('CPU sweep and selected evaluation','eval/frozen/active-tuning-v2/ and active-evaluation-shortlist-v2/'),
('GPU parameter validation','eval/frozen/active-shortlist-gpu-v1/combined/'),
('Containment designed test','eval/frozen/containment-targeted-100-gpu-v1/combined/'),
('Current SAST / metadata / SCA','eval/comparison_raw/sast-ten-v1/, sast-ten-dependencies-v1/, sca-copy-v1/'),
('Active cohort admission/provenance','eval/active/README.md; eval/tier2/VALIDATION.md')],[139,368],small=True)
p('Corrected figures are derived quality results, not a fresh end-to-end run. Timings, costs and repeated-decision checks belong to the original code. A fresh revised baseline needs a new compatible freeze. Original reports are preserved; the recomputed summary and input hashes identify this revision.','SmallX')

# The full CPU tuning grid belongs in an appendix rather than in the main claims.
values=[s for s in tuning['summaries'] if s['tier']=='tier2']
assert len(values)==38
for part in range(2):
    page(9+part,f'CPU tuning grid ({part+1}/2)','All 38 settings | Tier 2 tuning: 91 vulnerable + 87 patched | Single-pass CPU times')
    p('Corrected Tier 1 tuning quality is identical across all settings: 90/90 correct-origin detections, 6/91 patched alerts and 0/181 reviews. Tier 2 rows below are unchanged by the hash rule. Each row is independent, including joint K/budget and edit/margin combinations.')
    rows=[]
    for i,s in enumerate(values[part*19:(part+1)*19],part*19+1):
        c=s['configuration'];v=c['verifier']
        rows.append([i,c['retrieval_top_k'],c['max_verification_candidates'],c['max_candidate_regions'],c['max_verification_regions_per_pair'],f"{v['minimum_edit_side_score']:.2f}",f"{v['minimum_edit_margin']:.2f}",f"{v['minimum_structure_score']:.2f}",f"{v['minimum_token_score']:.2f}",s['correct_origin_automatic']['count'],s['patched_false_positive']['count'],s['abstained']['count'],f"{s['runtime_seconds']:.0f}"])
    table(['#','K','B','R','V','E','M','S','T','Origin /91','FP /87','Review /178','CPU sec'],rows,[20,22,24,30,22,35,35,35,35,56,45,62,66],small=True)
    p('K = retrieved origin limit; B = verification candidate budget; R = candidate-region cap; V = verification regions per pair; E = minimum edit-side score; M = edit margin; S/T = structure/token thresholds. Retrieval threshold is 0 throughout. Row 1 is the baseline K10/B10/R96/V3, E0.90/M0.10/S0.70/T0.70.','SmallX')
    p('These are tuning outcomes, not evaluation accuracy. CPU times exclude setup and are single-pass observations sensitive to system load and warmup. The GPU shortlist on page 3 supplies the stronger repeated timing comparison.','SmallX')
    source('eval/comparison_raw/hash-rule-summary-v1/active-tuning-v2/summary.json. Quality recomputed from saved rows; CPU times remain historical.')

def footer(canvas,doc):
    canvas.saveState();w,h=A4
    canvas.setStrokeColor(colors.HexColor('#c8d5dd'));canvas.line(44,39,w-44,39)
    canvas.setFont('Helvetica',8);canvas.setFillColor(colors.HexColor('#405365'))
    canvas.drawString(44,26,'ProvTrail | Findings and ablation | 30 Sep 2026')
    canvas.drawRightString(w-44,26,str(doc.page));canvas.restoreState()
doc=SimpleDocTemplate(str(OUT),pagesize=A4,rightMargin=44,leftMargin=44,topMargin=40,bottomMargin=52,title='ProvTrail: Findings and Ablation',author='ProvTrail evaluation')
doc.build(story,onFirstPage=footer,onLaterPages=footer)
reader=PdfReader(OUT)
assert len(reader.pages)==10, f'Unexpected pagination: {len(reader.pages)}'
for i,pageobj in enumerate(reader.pages):
    text=pageobj.extract_text()
    assert len(text)>400
    assert 'ProvTrail | Findings and ablation' in text
(ROOT/'tmp/pdfs/source-hashes.json').write_text(json.dumps(sources,indent=2),encoding='utf-8')
print(f'Created {OUT} ({len(reader.pages)} pages)')
