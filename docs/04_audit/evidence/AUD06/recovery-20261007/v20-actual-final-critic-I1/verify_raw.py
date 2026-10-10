import os,json,hashlib,re,collections
P='/tmp/aud06-finalcritic-I1-db55luic';R=P+'/owncopy';C=json.load(open('/tmp/aud06-v20-final-critic-sealed-contract.json'));I=C['currentRawInputs'];records=[]
def sha(p):return hashlib.sha256(open(p,'rb').read()).hexdigest()
def load(k):return json.load(open(R+'/'+I[k]))
def verify_entries(entries,base,label):
 bad=[];rows=[]
 for e in entries:
  f=base+'/'+e['path'];h=sha(f) if os.path.isfile(f) else None;s=os.path.getsize(f) if h else None
  ok=h==e['sha256'] and ('size' not in e or s==e['size']);row={'path':e['path'],'sha256':h,'size':s,'passed':ok};rows.append(row)
  if not ok:bad.append(row)
 records.append({'label':label,'entries':rows});return {'count':len(rows),'mismatches':bad}
out={};snap=R+'/'+I['immutableSnapshot'];out['snapshot158']=verify_entries(load('snapshotManifest')['files'],snap,'immutableSnapshot')
out['manifest78']=verify_entries(load('manifest')['artifacts'],snap,'currentManifest')
out['proof422']=verify_entries(load('runtimeInstallation')['entries'],R,'runtimeInstalled422')
stack=R+'/'+I['syntheticRuntime'];ss=json.load(open(stack+'/source-manifest.json'));out['runtime370']=verify_entries(ss,R,'syntheticRuntimeSource370')
cmds=[json.loads(l) for l in open(stack+'/commands.jsonl') if l.strip()];cmdfail=[]
for q in cmds:
 for stream in ['stdout','stderr']:
  f=stack+'/'+os.path.basename(q[stream+'File']);h=sha(f)
  if h!=q[stream+'Sha256']:cmdfail.append(q['id']+':'+stream)
out['runtimeCommands']={'count':len(cmds),'outputHashFailures':cmdfail,'nonzero':[{'id':q['id'],'name':q['name'],'exitCode':q['exitCode']} for q in cmds if q['exitCode']!=0]}
sumfail=[];sumcount=0
for l in open(stack+'/SHA256SUMS'):
 h,path=l.rstrip().split(maxsplit=1);path=path.lstrip('*');f=stack+'/'+path
 sumcount+=1
 if not os.path.exists(f) or sha(f)!=h:sumfail.append(path)
out['runtimeSHA256SUMS']={'count':sumcount,'mismatches':sumfail}
v=load('currentResult');ids=[];logrows=[];snapshotGates=[]
for g in v['gates']:
 gid=g['id'];ids.append(gid);row={k:g.get(k) for k in ['id','command','status','exitCode','durationMs']};f=snap+'/certification/phase11/logs/'+gid+'.log'
 if os.path.isfile(f):
  raw=open(f).read();headers={k:re.search(r'^# '+k+r'=(.*)$',raw,re.M).group(1) for k in ['certificationId','candidateId','commit','treeHash','gate']};e=re.search(r'^# exitCode=(\d+) durationMs=(\d+)$',raw,re.M)
  row.update(path=os.path.relpath(f,R),sha256=sha(f),size=os.path.getsize(f),header=headers,actualExit=int(e[1]) if e else None,actualDurationMs=int(e[2]) if e else None)
  row['bindingValid']=headers['certificationId']==v['certificationId'] and headers['candidateId']==C['sealedCandidate']['candidateId'] and headers['commit']==C['commit'] and headers['treeHash']==C['sealedCandidate']['behaviorTreeHash'] and headers['gate']==gid and row['actualExit']==g['exitCode'] and row['actualDurationMs']==g['durationMs'];logrows.append(row)
 else:row['internal']=True
 snapshotGates.append(row)
out['gate35']={'total':len(ids),'unique':len(set(ids)),'passed':sum(g['status']=='PASS' for g in v['gates']),'commandLogs':len(logrows),'badBindings':[g['id'] for g in logrows if not g['bindingValid']],'internal':[g['id'] for g in snapshotGates if g.get('internal')]}
for k in ['unitJSON','postgresJSON']:
 q=load(k);out[k]={a:q.get(a) for a in ['numTotalTests','numPassedTests','numPendingTests','numFailedTests','numTotalTestSuites','numFailedTestSuites','success','startTime']}
u=load('unitJSON');d=load('postgresJSON');selected=json.load(open(R+'/package.json'))['scripts']['test:postgres']
def tests(q):
 for f in q['testResults']:
  for a in f['assertionResults']:
   name=f['name'];mark='/repo/';rel=name.split(mark,1)[1] if mark in name else os.path.relpath(name,R)
   yield (rel,a['fullName']),a['status']
ux=list(tests(u));dx=list(tests(d));sk=[key for key,status in ux if status in ['pending','skipped','todo']];dm=collections.defaultdict(list)
for key,status in dx:dm[key].append(status)
recs=[]
for key in sk:recs.append({'file':key[0],'fullName':key[1],'dedicatedStatuses':dm[key],'passed':dm[key]==['passed']})
out['independentExactSkips']={'count':len(sk),'unique':len(set(sk)),'matchedPassedExactlyOnce':sum(r['passed'] for r in recs),'missingOrAmbiguous':[r for r in recs if not r['passed']],'dedicatedFailures':sum(s=='failed' for k,s in dx),'dedicatedSkipped':sum(s in ['pending','skipped','todo'] for k,s in dx),'declaredReceiptCounts':load('exactSkipReconciliation')['counts'],'selectionCommand':selected}
out['coverageTotals']=load('coverageSummary')['total']
first=R+'/'+I['preservedFirstActualSnapshot'];w=json.load(open(first+'/certification/phase11/phase11-result.json'));out['firstCycle']={k:w.get(k) for k in ['certificationId','timestamp','decision','certification']};out['firstCycle']['failedGates']=[{k:g.get(k) for k in ['id','status','exitCode','command']} for g in w['gates'] if g['status']!='PASS']
# Opaque original bindings are matched using BEFORE record bytes only.
before=json.load(open(P+'/before.json'));out['opaqueBindings']={k:[x['path'] for x in before['entries'] if x.get('sha256')==h] for k,h in C['opaqueBindings'].items()}
# Existing integration machine input only binding/identity/fingerprint mechanical facts; no verdict/checks/summary.
f=R+'/docs/04_audit/evidence/AUD19/AUD19-08-critic-report.json';m=json.load(open(f));out['priorMachineMechanicalOnly']={'path':os.path.relpath(f,R),'sha256':sha(f),'size':os.path.getsize(f),'criticIdentity':m['critic']['identity'],'freshContext':m['critic']['freshContext'],'binding':m['binding'],'fingerprint':m['fingerprint'],'independence':m['critic']['independence']}
for name,value in [('raw-verification.json',out),('raw-integrity-indices.json',records),('gate-log-index.json',snapshotGates),('exact-skip-index.json',recs)]:open(P+'/'+name,'w').write(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
# Print compact controls only, no result narrative/generated scoring/prior conclusions.
for k,val in out.items():
 if k=='independentExactSkips':val={a:b for a,b in val.items() if a!='missingOrAmbiguous'};val['badCount']=sum(not r['passed'] for r in recs)
 print(k,json.dumps(val,ensure_ascii=False))
