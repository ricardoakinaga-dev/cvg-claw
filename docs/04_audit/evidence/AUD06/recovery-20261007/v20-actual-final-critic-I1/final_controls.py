import sys,os,json,hashlib,stat,subprocess,time,re,collections
P='/tmp/aud06-finalcritic-I1-db55luic';sys.path.insert(0,P);from guard_copy import meta
R=P+'/owncopy';T='/tmp/cvg-aud06-certification-aottnvx0/repo';C=json.load(open('/tmp/aud06-v20-final-critic-sealed-contract.json'));I=C['currentRawInputs'];GI=[]
def walk(src,dst,rel):
 m=meta(src);s=os.lstat(dst)
 if (m['dev'],m['ino'])==(s.st_dev,s.st_ino):raise RuntimeError('git inode shared')
 row={'path':'.git/'+rel,'targetMetadata':m,'ownInode':s.st_ino,'ownDev':s.st_dev,'inodeIndependent':True}
 if stat.S_ISDIR(m['mode']):
  fd=os.open(src,os.O_RDONLY|os.O_DIRECTORY|os.O_NOATIME);names=sorted(e.name for e in os.scandir(fd));os.close(fd)
  if meta(src)!=m:raise RuntimeError('git metadata changed')
  GI.append(row)
  for n in names:walk(src+'/'+n,dst+'/'+n,rel+'/'+n if rel else n)
 elif stat.S_ISREG(m['mode']):
  fd=os.open(src,os.O_RDONLY|os.O_NOATIME|os.O_NOFOLLOW)
  if meta(src)!=m:raise RuntimeError('git pre changed')
  h=hashlib.sha256()
  while True:
   b=os.read(fd,1048576)
   if not b:break
   h.update(b)
  os.close(fd)
  if meta(src)!=m:raise RuntimeError('git post changed')
  with open(dst,'rb') as f:own=hashlib.file_digest(f,'sha256').hexdigest()
  if h.hexdigest()!=own or s.st_nlink!=1:raise RuntimeError('git bytes/links mismatch')
  row.update(sha256=own,size=s.st_size,nlink=s.st_nlink);GI.append(row)
 elif stat.S_ISLNK(m['mode']):
  l=os.readlink(src)
  if meta(src)!=m or l!=os.readlink(dst):raise RuntimeError('git link mismatch')
  if os.path.realpath(dst).startswith(T+'/'):raise RuntimeError('git target link')
  row['link']=l;GI.append(row)
 else:raise RuntimeError('special git entry')
walk(T+'/.git',R+'/.git','');open(P+'/git-physical-independence-index.json','w').write(json.dumps(GI,indent=2)+'\n');print('Git physical guarded entries',len(GI),'regular',sum('sha256'in a for a in GI),'all bytes/inodes/links independent')
# Static/manual observations saved as direct evidence, never execute fixtures.
O={};st=R+'/'+I['syntheticRuntime'];snap=R+'/'+I['immutableSnapshot'];unit=json.load(open(R+'/'+I['unitJSON']));pg=json.load(open(R+'/'+I['postgresJSON']))
O['relevantTestFacts']=[]
want=['aud06-n3-policy.test.ts','aud06-n3-executor.test.ts','retention-renewal.test.ts','retention-postgres.test.ts','certify-controlled.test.js','architecture.test.js','aud06-state-routing.test.js','request-context.test.ts','request-query.test.ts','client.test.ts','phase11-bypass-audit.test.js','bypass-sql-audit.test.js','aud06-stack.test.js']
for scope,q in [('unit',unit),('postgres',pg)]:
 for f in q['testResults']:
  if any(f['name'].endswith('/'+a) for a in want):O['relevantTestFacts'].append({'scope':scope,'file':f['name'].split('/repo/')[-1],'statuses':dict(collections.Counter(a['status'] for a in f['assertionResults']))})
O['lineCounts']={f:open(R+'/'+f).read().count('\n') for f in ['apps/api/src/server.ts','apps/api/src/server/request-context.ts','apps/api/src/server/request-query.ts','apps/web/src/api/client.ts','apps/web/src/api/contracts.ts']}
O['runtimeBurst']=dict(collections.Counter(str((x['status'],x['upstream'])) for x in json.load(open(st+'/shared-quota-burst.json'))))
rest=json.load(open(st+'/restore-integrity.json'));O['restore']={'completeOriginalRestoredEqual':rest['original']==rest['restored'],'sourceUnchanged':rest['sourceUnchanged'],'originalSha256':rest['original']['sha256']}
q=json.load(open(st+'/summary.json'));O['runtime']={k:q[k] for k in ['runId','status','startedAt','endedAt','exitCode','cleanupErrors','sourceDriftSinceSnapshot','teardown','production','realPilot','realRpoRtoQualified','humanSignoff']};O['runtimeChecks']={k:q['checks'][k] for k in ['migration','startup','containerIsolation','sharedQuota','restore']}
raw=open(snap+'/certification/phase11/logs/bypass_audit.log').read();v=json.loads(raw[raw.find('\n{')+1:]);O['bypass']={k:v[k] for k in ['status','scannedFiles','findings','forwardingQueries']}
O['currentExternal']={k:v for k,v in json.load(open(R+'/'+I['currentResult']))['externalGates'].items() if k!='notes'}
O['teardownActual']=json.load(open(R+'/'+I['teardown']));O['actualCycleTimes']={k:v for k,v in json.load(open(R+'/'+I['actualExitTimes'])).items() if k!='scope'}
O['coverageFirstDedicated'] = json.load(open(R+'/'+I['coverageSummary']))['total'];O['coverageVerifyObserved']={'statements':92.83,'branches':90,'functions':91.31,'lines':93.3,'reason':'Separate emitted coverage profile in verify.log; no substitution of percentages.'}
O['rawTerminal']={}
for f in ['e2e','security','coverage','verify']:
 lines=open(snap+'/certification/phase11/logs/'+f+'.log').read().splitlines();O['rawTerminal'][f]=[re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',l) for l in lines if re.search(r'found 0 vulnerabilities|75 passed|All files |Test Files |\sTests ',l)]
O['runtimeInstallRaw']=[l.strip() for l in open(st+'/015-build-runtime.stderr.log') if 'npm ci --ignore-scripts' in l or 'added 324 packages' in l]
renew='docs/04_audit/evidence/CLAW-W1/CLAW-W1-07-tombstone-policy-renewal-decision-20261005.json';q=json.load(open(R+'/'+renew));O['retentionApproval']={k:q[k] for k in ['status','decidedAt','validUntil','policyVersion','environmentAndEffectScope','policyRulesChanged','releaseEligible','postTombstoneHorizonDays']}
# Candidate snapshots and tolerances compared opaquely to exact HEAD in previous index; selected product config only.
O['visualBaselines']=[f['path'] for f in C['candidateFiles'] if 'spec.ts-snapshots/' in f['path']];O['visualToleranceLines']=[{'line':j,'text':l.strip()} for j,l in enumerate(open(R+'/tests/e2e/visual-shell.spec.ts'),1) if re.search(r'maxDiff|threshold|toHaveScreenshot',l)]
O['boundedStaticSourceObservations']=['PolicyEngine checks immutable N3 catalog before grants/documents; GovernedAgentRuntime DENY before model/approval/executor/outbox; fresh/approved/disguised tests inspect spies.','Wrapper uses private creation cidfiles/immutable IDs, own sessions, original EXIT status, bounded startup/cleanup, retained wait/container status distinction.','Retention uses transaction timestamp before mutation; inclusive validity boundary, UNCERTAIN excluded; early-warning sentinel is CI maintenance at 30 days, not a new runtime authority.','buildServer injects request-context, installs auth/raw body/metrics/security hooks; client types extracted to contracts with request/envelope public behavior retained.','Public scanner uses actual own-root git inventory of API/worker/agent-core; AST host calls separate from SQL lexer; opaque unresolved SQL refused except exact disclosed bootstrap pure forwarder; quota exact unqualified target/grammar, host member-origin domain bounded.','Q01/Q07 semantic input exclusively verified normative projection; no historical text or prior critic verdicts used.']
open(P+'/direct-observations.json','w').write(json.dumps(O,ensure_ascii=False,indent=2)+'\n');print('direct observations saved; baselines',len(O['visualBaselines']),'counts',O['lineCounts'])
# Owncopy candidate still identical after all own review controls; actual helper invocation only computes hashes.
z=subprocess.run(['/home/ricardo/.nvm/versions/node/v22.23.2/bin/node','--input-type=module','-e',"import {candidateFingerprint} from './scripts/lib/critic-evidence.mjs';console.log(candidateFingerprint(process.cwd()))"],cwd=R,capture_output=True,text=True);assert z.returncode==0
fp=z.stdout.strip();before=json.load(open(P+'/candidate-reconstruction.json'))['fingerprintBefore'];assert fp==before
open(P+'/fingerprint-final.json','w').write(json.dumps({'algorithm':'sha256-candidate-v1','before':before,'after':fp,'equal':True,'owncopyOnly':True},indent=2)+'\n')
open(P+'/job-closure-before-after.json','w').write(json.dumps({'at_ns':time.time_ns(),'guardCopySession14798Exit':0,'gitCatFileBatchExit':0,'projectionExit':0,'nodeVersionExit':0,'candidateHelperExit':0,'gitAndRawControlsExit':0,'candidateFinalFingerprintExit':z.returncode,'openOwnBackgroundJobs':0,'descendantsAgents':0,'targetTests':0,'networkDBDockerInstalls':0,'fixtureExecution':0,'expensiveGateReruns':0,'corpusAttempts':0,'canonicalJobsClosed':'User dispatch attestation; actual completed receipt exit0 and resource absence logs independently inspected; no live Docker calls'},indent=2)+'\n');print('All own spawned jobs synchronously ended; no own open background job; AFTER may run now')
