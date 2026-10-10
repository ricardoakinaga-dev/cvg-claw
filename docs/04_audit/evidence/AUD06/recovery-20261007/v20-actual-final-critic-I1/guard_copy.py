import os,sys,json,stat,hashlib,ctypes,time
ROOT='/tmp/cvg-aud06-certification-aottnvx0/repo'; OUT='/tmp/aud06-finalcritic-I1-db55luic'
libc=ctypes.CDLL(None,use_errno=True)
class TS(ctypes.Structure): _fields_=[('sec',ctypes.c_int64),('nsec',ctypes.c_uint32),('reserved',ctypes.c_int32)]
class SX(ctypes.Structure): _fields_=[('mask',ctypes.c_uint32),('blksize',ctypes.c_uint32),('attributes',ctypes.c_uint64),('nlink',ctypes.c_uint32),('uid',ctypes.c_uint32),('gid',ctypes.c_uint32),('mode',ctypes.c_uint16),('spare0',ctypes.c_uint16),('ino',ctypes.c_uint64),('size',ctypes.c_uint64),('blocks',ctypes.c_uint64),('attributes_mask',ctypes.c_uint64),('atime',TS),('btime',TS),('ctime',TS),('mtime',TS),('rdev_major',ctypes.c_uint32),('rdev_minor',ctypes.c_uint32),('dev_major',ctypes.c_uint32),('dev_minor',ctypes.c_uint32),('mnt_id',ctypes.c_uint64),('dio_mem_align',ctypes.c_uint32),('dio_offset_align',ctypes.c_uint32),('spare3',ctypes.c_uint64*12)]
def meta(p):
 s=os.lstat(p);x=SX();rc=libc.statx(-100,os.fsencode(p),0x100,0xfff,ctypes.byref(x))
 if rc:raise OSError(ctypes.get_errno(),p)
 return dict(mode=s.st_mode,ino=s.st_ino,dev=s.st_dev,nlink=s.st_nlink,uid=s.st_uid,gid=s.st_gid,size=s.st_size,blocks=s.st_blocks,blksize=s.st_blksize,rdev=s.st_rdev,atime_ns=s.st_atime_ns,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns,btime_ns=x.btime.sec*10**9+x.btime.nsec if x.mask&0x800 else None,statx_mask=x.mask,attributes=x.attributes,attributes_mask=x.attributes_mask,mnt_id=x.mnt_id)
def atom(p,o):
 t=p+'.tmp';open(t,'x').write(json.dumps(o,ensure_ascii=False,sort_keys=True,indent=2)+'\n');os.replace(t,p)
def scan(copy=False,git=False):
 rows=[];bytecount=0;start=time.time_ns()
 def walk(p,rel):
  nonlocal bytecount
  m=meta(p);r={'path':rel,'metadata':m}
  if stat.S_ISDIR(m['mode']):
   if copy:os.mkdir(OUT+'/owncopy/'+rel,0o700) if rel else None
   fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOATIME|os.O_NOFOLLOW)
   try:names=sorted(e.name for e in os.scandir(fd))
   finally:os.close(fd)
   if meta(p)!=m:raise RuntimeError('directory changed '+rel)
   rows.append(r)
   for n in names:
    if not rel and n=='.git' and not git:continue
    walk(p+'/'+n,rel+'/'+n if rel else n)
  elif stat.S_ISREG(m['mode']):
   fd=os.open(p,os.O_RDONLY|os.O_NOATIME|os.O_NOFOLLOW);h=hashlib.sha256()
   if meta(p)!=m:raise RuntimeError('pre-read changed '+rel)
   try:
    of=open(OUT+'/owncopy/'+rel,'xb') if copy else None
    while True:
     b=os.read(fd,1024*1024)
     if not b:break
     h.update(b);bytecount+=len(b)
     if of:of.write(b)
    if of:of.close();os.chmod(OUT+'/owncopy/'+rel,stat.S_IMODE(m['mode']))
   finally:os.close(fd)
   if meta(p)!=m:raise RuntimeError('post-read changed '+rel)
   r['sha256']=h.hexdigest();rows.append(r)
  elif stat.S_ISLNK(m['mode']):
   link=os.readlink(p)
   if meta(p)!=m:raise RuntimeError('readlink changed '+rel)
   r['link']=link;rows.append(r)
   if copy:os.symlink(link,OUT+'/owncopy/'+rel)
  else:raise RuntimeError('unsupported object '+rel)
 walk(ROOT,'')
 return {'root':ROOT,'excluded':['root .git'] if not git else [],'start_ns':start,'end_ns':time.time_ns(),'entries':rows,'count':len(rows),'bytesHashed':bytecount}
if __name__=='__main__':
 mode=sys.argv[1]
 if mode=='before':
  os.mkdir(OUT+'/owncopy',0o700)
  b=scan(copy=True);atom(OUT+'/before.json',b)
  # .git excluded from sentinel but copied with exact same guarded opaque mechanism
  old=ROOT;ROOT=old+'/.git';os.mkdir(OUT+'/git-copy',0o700)
  # separate destination via temporary owncopy root substitution is forbidden; opaque recursive helper
  def cg(src,dst):
   m=meta(src)
   if stat.S_ISDIR(m['mode']):
    os.mkdir(dst,0o700);fd=os.open(src,os.O_RDONLY|os.O_DIRECTORY|os.O_NOATIME);names=sorted(e.name for e in os.scandir(fd));os.close(fd)
    if meta(src)!=m:raise RuntimeError('git dir changed')
    for n in names:cg(src+'/'+n,dst+'/'+n)
   elif stat.S_ISREG(m['mode']):
    fd=os.open(src,os.O_RDONLY|os.O_NOATIME|os.O_NOFOLLOW)
    if meta(src)!=m:raise RuntimeError('git pre changed')
    with open(dst,'xb') as f:
     while True:
      q=os.read(fd,1048576)
      if not q:break
      f.write(q)
    os.close(fd)
    if meta(src)!=m:raise RuntimeError('git post changed')
   elif stat.S_ISLNK(m['mode']):
    q=os.readlink(src)
    if meta(src)!=m:raise RuntimeError('git link changed')
    os.symlink(q,dst)
   else:raise RuntimeError('git special')
  cg(ROOT,OUT+'/owncopy/.git');ROOT=old
  # independent byte and inode/link check without target reads
  checks=[]
  for r in b['entries']:
   p=OUT+'/owncopy/'+r['path'];s=os.lstat(p)
   if (s.st_dev,s.st_ino)==(r['metadata']['dev'],r['metadata']['ino']):raise RuntimeError('shared inode')
   if 'sha256'in r:
    with open(p,'rb') as f:h=hashlib.file_digest(f,'sha256').hexdigest()
    if h!=r['sha256'] or s.st_nlink!=1:raise RuntimeError('copy mismatch/hardlink')
   elif 'link'in r:
    if os.readlink(p)!=r['link']:raise RuntimeError('link mismatch')
    resolved=os.path.realpath(p)
    if resolved.startswith(old+'/'):raise RuntimeError('link reaches TARGET')
   checks.append(r['path'])
  atom(OUT+'/copy-verification.json',{'verifiedEntries':len(checks),'bytes':b['bytesHashed'],'inodeIndependent':True,'regularNlink1':True,'targetReachableLinks':False,'guardFailures':0,'rootGit':'opaque independent physical copy; no alternates semantics yet','time_ns':time.time_ns()})
  print('BEFORE/copy verified',len(checks),b['bytesHashed'])
 elif mode=='after':
  a=scan();atom(OUT+'/after.json',a);b=json.load(open(OUT+'/before.json'));diff=[(x,y) for x,y in zip(b['entries'],a['entries']) if x!=y]
  if len(a['entries'])!=len(b['entries']):diff.append('entry count')
  atom(OUT+'/sentinel-comparison.json',{'identical':not diff,'beforeCount':b['count'],'afterCount':a['count'],'changed':diff,'allAvailableTimes':['atime','mtime','ctime','statx birthtime'],'noTimestampRestoration':True,'targetReadsPermanentlyEnded_ns':time.time_ns()});print('AFTER identical',not diff,'entries',a['count'])
