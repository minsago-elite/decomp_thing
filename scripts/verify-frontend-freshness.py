#!/usr/bin/env python3
"""Trusted-build stage-only freshness diagnostic. Importing this file starts no work.

A reviewed input manifest and an already provisioned, repository-owned tool/cache
context are prerequisites. This is not descendant containment or packaging proof.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import struct
import subprocess
import time
import zipfile

TASKS = ('verifyFrontendToolchain', 'frontendInstall', 'frontendBuild',
         'generateFrontendAssetManifest', 'verifyFrontendAssets', 'stageFrontend')
KEYS = ('frontend/package-lock.json', 'frontend/package.json', 'frontend/.npmrc',
        '.node-version', 'scripts/install-frontend-node.sh', 'scripts/frontend-node-sha256.txt')
FIXED = ('build.gradle.kts', 'settings.gradle.kts', 'gradle.properties', 'gradlew',
         'gradle/wrapper/gradle-wrapper.jar', 'gradle/wrapper/gradle-wrapper.properties',
         'ghidra-bridge/build.gradle.kts', '.node-version', *KEYS[4:],
         'scripts/generate-web-api.mjs', 'scripts/web-asset-manifest.mjs',
         'contracts/web/v1/contract.schema.json')
SOURCE = (8192, 16*1024**2, 128*1024**2, 32)
OUTPUT = (8192, 16*1024**2, 64*1024**2, 16)

class Refusal(RuntimeError):
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def closed_json(data):
    def pairs(rows):
        result = {}
        for k, v in rows:
            if k in result: raise Refusal('duplicate JSON key')
            result[k] = v
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refusal('nonfinite JSON')))


class Ledger:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.start = clock()
        self.end = self.start + 420
        self.log_bytes = self.evidence_bytes = 0

    def check(self, cleanup=False):
        remaining = self.end - self.clock() - (0 if cleanup else 15)
        if remaining <= 0: raise Refusal('original absolute work end reached')
        return remaining

    def output(self, size, command_bytes):
        self.check()
        self.log_bytes += size
        if command_bytes > 2*1024**2 or self.log_bytes > 8*1024**2:
            raise Refusal('command/combined output limit')

    def evidence(self, size):
        self.check(cleanup=True)
        self.evidence_bytes += size
        if self.evidence_bytes > 16*1024**2: raise Refusal('retained evidence limit')


class UiBudget:
    """Separate existing asset/private-manifest caps;65MiB is only their sum."""
    def __init__(self):
        self.asset_bytes=0; self.asset_count=0; self.manifest_seen=False

    def admit(self, name, size):
        if type(name) is not str or type(size) is not int or size<0:
            raise Refusal('invalid UI member size')
        if name=='asset-manifest.json':
            if self.manifest_seen or size>1024**2: raise Refusal('private manifest bound')
            self.manifest_seen=True
        else:
            self.asset_bytes+=size; self.asset_count+=1
            if size>16*1024**2 or self.asset_bytes>64*1024**2 or self.asset_count>2048:
                raise Refusal('nonmanifest asset bound')


def check_ui_partition(rows):
    budget=UiBudget()
    for name,row in rows.items(): budget.admit(name,row['bytes'])
    return rows


class Files:
    """Bounded ordinary filesystem operations, not protection from hostile mounts."""
    def __init__(self, repository, ledger):
        self.repository = Path(repository).resolve(strict=True)
        self.ledger = ledger

    def path(self, path):
        p = Path(path)
        if not p.is_absolute(): p = self.repository / p
        if '..' in p.parts or not p.is_relative_to(self.repository): raise Refusal('outside repository')
        for parent in (p, *p.parents):
            if parent == self.repository: break
            if parent.is_symlink(): raise Refusal('symbolic path forbidden')
        return p

    def read(self, path, maximum=16*1024**2):
        p = self.path(path); self.ledger.check()
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or not 0 <= first.st_size <= maximum:
                raise Refusal('regular file size admission')
            chunks=[]; total=0
            while True:
                self.ledger.check(); data=os.read(fd, min(65536, maximum-total+1))
                if not data: break
                total += len(data)
                if total > maximum: raise Refusal('growing file')
                chunks.append(data)
            last=os.fstat(fd); named=p.stat(follow_symlinks=False)
            fields=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')
            if any(getattr(first,k)!=getattr(last,k) or getattr(first,k)!=getattr(named,k) for k in fields) or total!=first.st_size:
                raise Refusal('file changed during observation')
            self.ledger.check(); return b''.join(chunks)
        finally: os.close(fd)

    def write(self, path, data, evidence=False):
        self.ledger.check(cleanup=evidence)
        if evidence: self.ledger.evidence(len(data))
        p=self.path(path); p.parent.mkdir(parents=True, exist_ok=True)
        with p.open('wb') as stream:
            for i in range(0,len(data),65536):
                self.ledger.check(cleanup=evidence); stream.write(data[i:i+65536])
        self.ledger.check(cleanup=evidence)

    def inventory(self, root, limits=OUTPUT, budget=None, *, partitioned_ui=False, dist_assets=False):
        root=self.path(root); budget={'entries':0,'bytes':0} if budget is None else budget; rows={}
        if partitioned_ui and dist_assets: raise Refusal('distinct UI/dist inventory policies required')
        ui=UiBudget() if partitioned_ui else None
        regular_files=0
        def walk(directory, depth):
            nonlocal regular_files
            if depth > limits[3]: raise Refusal('inventory depth')
            with os.scandir(directory) as items:
                while True:
                    self.ledger.check()
                    # Includes the advance needed to observe EOF.
                    if budget['entries'] >= limits[0]: raise Refusal('inventory entry limit')
                    try: item=next(items)
                    except StopIteration: break
                    budget['entries'] += 1
                    p=Path(item.path); relative=p.relative_to(root).as_posix()
                    if len(relative.encode())>512: raise Refusal('inventory path bound')
                    metadata=item.stat(follow_symlinks=False); self.ledger.check()
                    if stat.S_ISDIR(metadata.st_mode): walk(p,depth+1)
                    elif stat.S_ISREG(metadata.st_mode):
                        regular_files+=1
                        if dist_assets and regular_files>2048: raise Refusal('dist asset file bound')
                        if metadata.st_size > limits[1] or metadata.st_size < 0: raise Refusal('inventory file bound')
                        budget['bytes'] += metadata.st_size
                        if budget['bytes'] > limits[2]: raise Refusal('inventory aggregate bound')
                        if ui is not None: ui.admit(relative,metadata.st_size)
                        read_limit=metadata.st_size if ui is not None else limits[1]
                        data=self.read(p,read_limit); rows[relative]={'bytes':len(data),'sha256':sha(data)}
                    else: raise Refusal('inventory special file')
        walk(root,0); return dict(sorted(rows.items()))

    def remove(self, root):
        # Metadata-only unlinks of leaf symlinks; never follow them into targets.
        requested=Path(root); parent=self.path(requested.parent)
        count=0
        def erase(p,depth):
            nonlocal count
            self.ledger.check(); count+=1
            if count>100000 or depth>64: raise Refusal('owned cleanup traversal bound')
            try: metadata=p.lstat()
            except FileNotFoundError: return
            if stat.S_ISDIR(metadata.st_mode):
                with os.scandir(p) as items:
                    while True:
                        self.ledger.check()
                        try: item=next(items)
                        except StopIteration: break
                        erase(Path(item.path),depth+1)
                p.rmdir()
            else: p.unlink()
            self.ledger.check()
        erase(parent/requested.name,0)

    def jar_ui(self, path):
        p=self.path(path); self.ledger.check()
        fd=os.open(p,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
        try:
            first=os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or not 0<=first.st_size<=256*1024**2:
                raise Refusal('baseline JAR regular size admission')
            self.ledger.check()
            stream=os.fdopen(fd,'rb'); fd=None
            with stream:
                stream.seek(0,2); size=stream.tell()
                if size>256*1024**2: raise Refusal('baseline JAR file bound')
                stream.seek(max(0,size-65557)); tail=stream.read(65557)
                i=tail.rfind(b'PK\x05\x06')
                if i<0 or len(tail)-i<22: raise Refusal('JAR EOCD missing')
                _,disk,central_disk,n_disk,n,size_cd,offset,comment=struct.unpack('<4s4H2IH',tail[i:i+22])
                if disk or central_disk or n!=n_disk or n>=8192 or size_cd>1024**2 or offset+size_cd>size or i+22+comment!=len(tail):
                    raise Refusal('JAR central directory admission')
                stream.seek(0); rows={}; total=0; ui=UiBudget()
                with zipfile.ZipFile(stream) as archive:
                    if len(archive.infolist())!=n: raise Refusal('JAR count mismatch')
                    for info in archive.infolist():
                        self.ledger.check()
                        if not info.filename.startswith('decompengine/web/ui/'): continue
                        name=info.filename[len('decompengine/web/ui/'):]
                        if info.is_dir(): continue
                        if not name or '..' in Path(name).parts or name.startswith('/') or name in rows: raise Refusal('unsafe/duplicate UI entry')
                        if stat.S_ISLNK(info.external_attr>>16): raise Refusal('JAR UI symlink')
                        total += info.file_size
                        if len(rows)>=2049 or info.file_size>16*1024**2 or total>65*1024**2: raise Refusal('JAR UI bounds')
                        ui.admit(name,info.file_size)
                        with archive.open(info) as member:
                            h=hashlib.sha256(); observed=0
                            while True:
                                self.ledger.check(); data=member.read(65536)
                                if not data: break
                                observed+=len(data)
                                if observed>info.file_size: raise Refusal('JAR growing member')
                                h.update(data)
                        if observed!=info.file_size: raise Refusal('JAR truncated member')
                        rows[name]={'bytes':observed,'sha256':h.hexdigest()}
                last=os.fstat(stream.fileno()); named=p.stat(follow_symlinks=False)
                fields=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')
                if any(getattr(first,k)!=getattr(last,k) or getattr(first,k)!=getattr(named,k) for k in fields): raise Refusal('JAR changed during observation')
                self.ledger.check(); return rows
        finally:
            if fd is not None: os.close(fd)



class Runner:
    def __init__(self, ledger, files, evidence):
        self.ledger=ledger; self.files=files; self.evidence=evidence
        self.uncertain=False; self.sequence=0

    def __call__(self, argv, cwd, env):
        self.ledger.check(); self.sequence+=1
        child=None; captured=bytearray(); intervened=False; primary=None
        facts={'launcherCreated':False,'rootReaped':False,'exitCode':None,'operationalGroupAbsent':None,
               'terminationRequested':False,'killRequested':False,'waitUncertain':False}
        try:
            if signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL: raise Refusal('SIGCHLD ownership prerequisite')
            child=subprocess.Popen(argv,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
            facts['launcherCreated']=True
            with selectors.DefaultSelector() as selector:
                os.set_blocking(child.stdout.fileno(),False); selector.register(child.stdout,selectors.EVENT_READ)
                while selector.get_map():
                    for key,_ in selector.select(min(.1,self.ledger.check())):
                        self.ledger.check(); chunk=os.read(key.fileobj.fileno(),65536)
                        if not chunk: selector.unregister(key.fileobj); continue
                        self.ledger.output(len(chunk),len(captured)+len(chunk)); captured.extend(chunk)
                code=child.wait(timeout=self.ledger.check()); facts.update(rootReaped=True,exitCode=code)
                self.ledger.check()
            try: os.killpg(child.pid,0)
            except ProcessLookupError: facts['operationalGroupAbsent']=True
            else:
                facts['operationalGroupAbsent']=False
                raise Refusal('operational group leftovers; absence unverified')
            return {'code':code,'output':bytes(captured),'intervened':False,'reaped':True}
        except BaseException as error:
            primary=error; intervened=True; self.uncertain=True
            # No poll(): retain the unreaped leader until signaling is over.
            if child is not None:
                try:
                    # WNOWAIT observes ownership without releasing/reusing PID.
                    self.ledger.check(cleanup=True)
                    state=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                    self.ledger.check(cleanup=True)
                    if state is None:
                        self.ledger.check(cleanup=True)
                        os.killpg(child.pid,signal.SIGTERM); facts['terminationRequested']=True
                        try:
                            code=child.wait(timeout=min(2,self.ledger.check(cleanup=True))); facts.update(rootReaped=True,exitCode=code)
                        except subprocess.TimeoutExpired:
                            self.ledger.check(cleanup=True)
                            state=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                            self.ledger.check(cleanup=True)
                            if state is None:
                                self.ledger.check(cleanup=True)
                                os.killpg(child.pid,signal.SIGKILL); facts['killRequested']=True
                            code=child.wait(timeout=self.ledger.check(cleanup=True)); facts.update(rootReaped=True,exitCode=code)
                    else:
                        code=child.wait(timeout=self.ledger.check(cleanup=True)); facts.update(rootReaped=True,exitCode=code)
                except BaseException: facts['waitUncertain']=not facts['rootReaped']
            raise
        finally:
            try:
                if child is not None and child.stdout is not None: child.stdout.close()
                # Retained bytes are bounded; uncertain cleanup never grants continuation.
                self.files.write(self.evidence/('command-%02d.log'%self.sequence),bytes(captured),evidence=True)
                self.files.write(self.evidence/('command-%02d.json'%self.sequence),canonical({**facts,'argv':argv,'cwd':str(cwd),'environmentKeys':sorted(env),'npmOffline':env.get('NPM_CONFIG_OFFLINE'),
                           'intervened':intervened,'cleanupUncertain':self.uncertain,'descendantAbsenceProven':False}),evidence=True)
            except BaseException:
                self.uncertain=True
                if primary is None: raise


def outcomes(output, names, negative=False):
    rows={}
    for line in output.decode('utf8',errors='strict').splitlines():
        if not line.startswith('> Task '): continue
        fields=line.split()
        if len(fields)<3: raise Refusal('malformed task outcome')
        name=fields[2]
        if not name.startswith(':') or name[1:] not in names or name in rows: raise Refusal('unexpected/duplicate task outcome')
        label='EXECUTED' if len(fields)==3 else ' '.join(fields[3:])
        if label not in ('EXECUTED','UP-TO-DATE','FAILED'): raise Refusal('uncredited task outcome')
        rows[name]=label
    if set(rows)!={':'+name for name in names}: raise Refusal('missing task outcomes')
    if negative and rows[':frontendBuild']!='FAILED': raise Refusal('drift build did not fail')
    return rows


def require_outcomes(result, mode):
    if result.get('intervened') is not False or result.get('reaped') is not True: raise Refusal('uncertain command')
    negative=mode=='drift'; names=TASKS[:3] if negative else TASKS
    rows=outcomes(result['output'],names,negative)
    wanted={':'+name:'EXECUTED' for name in names}
    if mode in ('unchanged','fresh','drift'): wanted[':frontendInstall']='UP-TO-DATE'
    if mode=='unchanged':
        for name in TASKS[2:]:
            if name!='verifyFrontendAssets': wanted[':'+name]='UP-TO-DATE'
    if negative:
        wanted[':frontendBuild']='FAILED'
        if result['code']!=1 or b'Generated contract drift:' not in result['output']: raise Refusal('wrong negative failure')
    elif result['code']!=0: raise Refusal('build failed')
    if rows!=wanted: raise Refusal('actual task outcomes differ: '+json.dumps(rows,sort_keys=True))
    return rows


def init_guard(names):
    paths=','.join("':%s'"%name for name in names)
    return ("gradle.taskGraph.whenReady { graph ->\n"+
            "  if (graph.allTasks.collect { it.path } != ["+paths+"]) throw new GradleException('freshness task graph differs')\n}\n").encode()


def baseline_paths(source, work, requested, files):
    source=files.path(source); work=files.path(work)
    required={source/'build/frontend/dist',source/'build/frontend/asset-manifest.json',
              source/'build/generated/frontend-resources/decompengine/web/ui'}
    optional_ui=source/'build/resources/main/decompengine/web/ui'
    if type(requested) is not list or not 3<=len(requested)<=8: raise Refusal('required checkout baselines missing')
    selected=[]
    for name in requested:
        if type(name) is not str: raise Refusal('baseline path must be explicit absolute string')
        p=files.path(name)
        if str(p)!=name or p==work or p.is_relative_to(work) or work.is_relative_to(p): raise Refusal('baseline path/overlap')
        if p not in required and p!=optional_ui and not (p.parent==source/'build/libs' and p.suffix=='.jar'):
            raise Refusal('unrelated baseline selector')
        if p in selected: raise Refusal('duplicate baseline selector')
        selected.append(p)
    if not required.issubset(selected): raise Refusal('required checkout baselines omitted')
    return selected


class Freshness:
    def __init__(self, source, work, manifest, ledger, files, runner):
        self.source=files.path(source); self.work=files.path(work)
        self.fixture=self.work/'fixture'; self.evidence=self.work/'evidence'
        self.manifest=manifest; self.ledger=ledger; self.fs=files; self.runner=runner
        self.active=None
        self.phases={name:{'status':'NOT_RUN'} for name in ('cold','unchanged','warm','drift','fresh')}

    def enter(self, mode):
        if self.active!=mode:
            self.active=mode; self.phases[mode]={'status':'STARTED'}

    def failure(self, error):
        if self.active is not None: self.phases[self.active]['status']='FAILED_OR_UNKNOWN'
        return {'status':'FAILED_OR_UNKNOWN','reason':type(error).__name__+':'+str(error)[:500],
                'phases':self.phases,'fixtureRetained':True,'fullIssue651Accepted':False}

    def baseline(self):
        rows={}
        for p in baseline_paths(self.source,self.work,self.manifest['packagedBaseline'],self.fs):
            if p==self.source/'build/frontend/asset-manifest.json':
                data=self.fs.read(p,1024**2)
                if not data: raise Refusal('missing checkout private manifest')
                rows[str(p)]={'bytes':len(data),'sha256':sha(data)}
            else:
                is_dist=p==self.source/'build/frontend/dist'
                limits=OUTPUT if is_dist else (8192,16*1024**2,65*1024**2,16)
                value=self.fs.jar_ui(p) if p.suffix=='.jar' else self.fs.inventory(p,limits,partitioned_ui=not is_dist,dist_assets=is_dist)
                if not is_dist: check_ui_partition(value)
                if len(value)>(2048 if is_dist else 2049): raise Refusal('baseline asset count')
                required={'index.html','.vite/manifest.json'} if is_dist else {'index.html','asset-manifest.json'}
                if not required.issubset(value): raise Refusal('incomplete checkout/packaged UI baseline')
                rows[str(p)]=value
        return rows

    def snapshot(self):
        f=self.fixture
        dist=self.fs.inventory(f/'build/frontend/dist',dist_assets=True)
        if len(dist)>2048: raise Refusal('asset file count')
        manifest_bytes=self.fs.read(f/'build/frontend/asset-manifest.json',1024**2)
        inventory=closed_json(manifest_bytes)
        if set(inventory)!={'schemaVersion','applicationVersion','entryScript','entryStyles','files','buildId'} or inventory['schemaVersion']!=1: raise Refusal('closed private asset manifest required')
        payload={k:v for k,v in inventory.items() if k!='buildId'}
        if sha((json.dumps(payload,ensure_ascii=False,separators=(',',':'))+'\n').encode())!=inventory['buildId']: raise Refusal('asset buildId disagrees')
        records={r['path']:{'bytes':r['sizeBytes'],'sha256':r['sha256']} for r in inventory['files']}
        if len(records)!=len(inventory['files']) or records!=dist: raise Refusal('private manifest/dist mismatch')
        staged=self.fs.inventory(f/'build/generated/frontend-resources/decompengine/web/ui',(8192,16*1024**2,65*1024**2,16),partitioned_ui=True)
        if staged!={**dist,'asset-manifest.json':{'bytes':len(manifest_bytes),'sha256':sha(manifest_bytes)}}:
            raise Refusal('staged bytes differ')
        reports={n:self.fs.read(f/('build/frontend/'+n),1024**2) for n in ('bundle-report.json','bundle-composition.json')}
        return {'dist':dist,'manifest':{'bytes':len(manifest_bytes),'sha256':sha(manifest_bytes)},'reports':{n:{'bytes':len(data),'sha256':sha(data)} for n,data in reports.items()},'buildId':inventory['buildId'],'staged':staged,'vite':closed_json(self.fs.read(f/'build/frontend/dist/.vite/manifest.json',1024**2))}

    def command(self, mode):
        names=TASKS[:3] if mode=='drift' else TASKS
        guard=self.work/'graph.gradle'; self.fs.write(guard,init_guard(names))
        m=self.manifest
        env={'PATH':str(Path(m['nodeHome'])/'bin')+':/usr/bin:/bin','HOME':str(self.work/'home'),
             'JAVA_HOME':m['javaHome'],'GRADLE_USER_HOME':m['gradleHome'],
             'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TMPDIR':str(self.work/'tmp'),
             'NPM_CONFIG_CACHE':str(self.work/'npm-download-cache'),
             'NPM_CONFIG_USERCONFIG':str(self.work/'empty-npmrc'),
             'NPM_CONFIG_GLOBALCONFIG':str(self.work/'empty-global-npmrc'),
             'NPM_CONFIG_OFFLINE':'false' if mode=='cold' else 'true'}
        argv=[m['gradle'],'--offline','--no-daemon','--no-build-cache','--console=plain',
              '--project-cache-dir',str(self.fixture/'.gradle'),'-I',str(guard),
              '-PfrontendNodeHome='+m['nodeHome'],'frontendBuild' if mode=='drift' else 'stageFrontend']
        return argv,env

    def build(self, mode):
        self.enter(mode)
        argv,env=self.command(mode); result=self.runner(argv,self.fixture,env)
        self.ledger.check(); actual=require_outcomes(result,mode)
        self.phases[mode]={'status':'BUILD_COMPLETED','taskOutcomes':actual,'elapsedSeconds':self.ledger.clock()-self.ledger.start}
        self.fs.write(self.evidence/(mode+'-outcomes.json'),canonical(self.phases[mode]),evidence=True)

    def drift(self):
        self.enter('drift')
        targets=('frontend/src/api/generated.ts','frontend/src/api/generated-schema.ts','contracts/web/v1/contract.schema.json')
        for i,name in enumerate(targets):
            path=self.fixture/name; original=self.fs.read(path)
            if i<2: changed=original+b'\n// authored freshness drift\n'
            else:
                value=closed_json(original); value['definitions']['freshnessDriftProbe']={'type':'string','enum':['authored']}; changed=canonical(value)
            self.fs.write(path,changed)
            argv,env=self.command('drift')
            checked=self.runner([str(Path(self.manifest['nodeHome'])/'bin/node'),str(self.fixture/'scripts/generate-web-api.mjs'),'--check'],self.fixture,env)
            self.ledger.check()
            if checked['code']!=1 or b'Generated contract drift:' not in checked['output'] or checked['intervened'] or not checked['reaped']:
                raise Refusal('missing intended API drift refusal')
            if self.fs.read(path)!=changed: raise Refusal('check silently rewrote drift')
            if i==0: self.build('drift')
            self.fs.write(path,original)
        self.phases['drift']['status']='PASSED'

    def run(self):
        baseline=self.baseline()
        self.build('cold'); cold=self.snapshot(); self.phases['cold']['status']='PASSED'; self.fs.write(self.evidence/'cold.json',canonical(cold),evidence=True)
        self.build('unchanged')
        if self.snapshot()!=cold: raise Refusal('unchanged bytes differ')
        self.phases['unchanged']['status']='PASSED'
        self.enter('warm')
        for name in ('frontend/node_modules','build','.gradle'): self.fs.remove(self.fixture/name)
        self.build('warm'); warm=self.snapshot()
        if warm!=cold: raise Refusal('offline warm bytes differ')
        self.phases['warm']['status']='PASSED'
        self.drift()
        self.enter('fresh')
        old=self.fixture/'frontend/src/app/mark.svg'; data=self.fs.read(old)
        self.fs.write(old.with_name('freshness-mark.svg'),data.replace(b'<svg',b'<svg data-freshness="changed"',1))
        if b'<svg' not in data: raise Refusal('expected SVG anchor absent')
        self.fs.remove(old)
        app=self.fixture/'frontend/src/app/App.tsx'; original=self.fs.read(app)
        if original.count(b"'./mark.svg'")!=1: raise Refusal('asset import anchor differs')
        self.fs.write(app,original.replace(b"'./mark.svg'",b"'./freshness-mark.svg'"))
        for part in ('build/frontend/dist','build/generated/frontend-resources/decompengine/web/ui'):
            self.fs.write(self.fixture/part/'assets/freshness-obsolete.svg',b'<svg/>')
        self.build('fresh'); fresh=self.snapshot()
        old_assets={n for n in warm['dist'] if n.endswith('.svg') and n.startswith('assets/mark-')}
        new_assets={n for n in fresh['dist'] if n.endswith('.svg') and n.startswith('assets/freshness-mark-')}
        if not old_assets or len(new_assets)!=1 or fresh['buildId']==warm['buildId'] or old_assets.intersection(fresh['dist']): raise Refusal('fresh asset not invalidated')
        new_asset=next(iter(new_assets))
        if not any(new_asset in row.get('assets',[]) for row in fresh['vite'].values()): raise Refusal('new asset not referenced by Vite chunk')
        if 'assets/freshness-obsolete.svg' in fresh['dist'] or 'assets/freshness-obsolete.svg' in fresh['staged']: raise Refusal('obsolete asset retained')
        if {warm['dist'][n]['sha256'] for n in old_assets}.intersection(fresh['dist'][n]['sha256'] for n in new_assets): raise Refusal('fresh asset bytes unchanged')
        for n in ('frontend/src/api/generated.ts','frontend/src/api/generated-schema.ts'):
            if self.fs.read(self.fixture/n)!=self.fs.read(self.source/n): raise Refusal('generated API changed')
        if self.baseline()!=baseline: raise Refusal('packaged baseline changed')
        self.phases['fresh']['status']='PASSED'
        self.fs.write(self.evidence/'fresh.json',canonical(fresh),evidence=True)
        self.ledger.check()
        return {'status':'PASSED_STAGE_ONLY','phases':self.phases,'packagedBaseline':baseline,
                'fullIssue651Accepted':False,'descendantAbsenceProven':False,'coldGradleQualified':False}


def prepare(source, work, manifest, files):
    source=files.path(source); work=files.path(work)
    if work.exists() or source==work or source.is_relative_to(work) or work.is_relative_to(source/'frontend'):
        raise Refusal('fresh disjoint owned work path required')
    if set(manifest)!={'sources','tools','gradle','gradleHome','nodeHome','javaHome','packagedBaseline','os','arch','cacheRestoreMetadata'}:
        raise Refusal('closed reviewed provisioning manifest required')
    if not manifest['tools'] or not manifest['sources'] or len(manifest['packagedBaseline'])>8 or not manifest['packagedBaseline']:
        raise Refusal('nonempty bounded provisioning/baseline required')
    selected=set(FIXED)
    frontend={}; budget={'entries':len(FIXED)+16,'bytes':0}
    for directory in ('src','tests','dev','public','scripts'):
        p=files.path(source/'frontend'/directory)
        if p.exists(): frontend.update({directory+'/'+n:r for n,r in files.inventory(p,SOURCE,budget).items()})
    with os.scandir(source/'frontend') as entries:
        while True:
            files.ledger.check()
            if budget['entries']>=8192: raise Refusal('source entry bound')
            try: item=next(entries)
            except StopIteration: break
            budget['entries']+=1
            name=item.name
            declared=(name in ('package.json','package-lock.json','.npmrc','index.html') or
                      'config.' in name)
            if declared:
                if not item.is_file(follow_symlinks=False): raise Refusal('frontend config must be regular')
                frontend[name]={}
    for name in frontend:
        first=name.split('/')[0]
        if first in ('src','tests','dev','public','scripts') or '/' not in name:
            selected.add('frontend/'+name)
    if set(manifest['sources'])!=selected or len(selected)>8192: raise Refusal('exact source manifest differs')
    total=0
    for name in sorted(selected):
        data=files.read(source/name,min(16*1024**2,128*1024**2-total)); total+=len(data)
        row=manifest['sources'][name]
        if type(row) is not dict or set(row)!={'sha256','bytes','mode'} or type(row['bytes']) is not int or type(row['mode']) is not int or not 0<=row['mode']<=0o777: raise Refusal('exact source pin types required')
        if total>128*1024**2 or set(row)!={'sha256','bytes','mode'} or row['sha256']!=sha(data) or row['bytes']!=len(data) or row['mode']!=stat.S_IMODE((source/name).stat().st_mode): raise Refusal('source pin disagreement')
    if len(manifest['tools'])>256: raise Refusal('tool input count')
    tool_bytes=0
    for name,row in manifest['tools'].items():
        p=files.path(name); data=files.read(p,min(128*1024**2,512*1024**2-tool_bytes)); tool_bytes+=len(data)
        if tool_bytes>512*1024**2: raise Refusal('tool input aggregate')
        if type(row) is not dict or type(row.get('bytes')) is not int or row!={'sha256':sha(data),'bytes':len(data)}: raise Refusal('provisioned tool pin disagreement')
    for value in ('gradleHome','nodeHome','javaHome'):
        if not files.path(manifest[value]).is_dir(): raise Refusal('provisioned context missing')
    for name in (manifest['gradle'],str(Path(manifest['nodeHome'])/'bin/node'),str(Path(manifest['javaHome'])/'bin/java')):
        if name not in manifest['tools']: raise Refusal('required executable lacks reviewed pin')
    if not files.path(manifest['gradle']).is_relative_to(files.path(manifest['gradleHome'])): raise Refusal('Gradle distribution must already be provisioned in same cache')
    baseline_paths(source,work,manifest['packagedBaseline'],files)
    work.mkdir(parents=True)
    for name in ('fixture','evidence','home','tmp','npm-download-cache'): (work/name).mkdir()
    files.write(work/'empty-npmrc',b''); files.write(work/'empty-global-npmrc',b'')
    for name in sorted(selected):
        data=files.read(source/name)
        if sha(data)!=manifest['sources'][name]['sha256']: raise Refusal('source changed during copy')
        files.write(work/'fixture'/name,data); (work/'fixture'/name).chmod(manifest['sources'][name]['mode'])
    fingerprint={n:manifest['sources'][n]['sha256'] for n in KEYS}
    fingerprint.update(os=manifest['os'],arch=manifest['arch'])
    files.write(work/'evidence/inputs.json',canonical({'manifest':manifest,'npmCacheInputSha256':sha(canonical(fingerprint))}),evidence=True)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository',required=True); parser.add_argument('--source',required=True)
    parser.add_argument('--work',required=True); parser.add_argument('--provisioned-manifest',required=True)
    args=parser.parse_args(argv); ledger=Ledger(); files=Files(args.repository,ledger)
    work=files.path(args.work); diagnostic=None; was_absent=not work.exists()
    previous_term=signal.getsignal(signal.SIGTERM)
    def cancelled(_number,_frame): raise Refusal('ordinary cancellation requested')
    signal.signal(signal.SIGTERM,cancelled)
    try:
        manifest=closed_json(files.read(args.provisioned_manifest,4*1024**2))
        prepare(args.source,work,manifest,files)
        runner=Runner(ledger,files,work/'evidence')
        diagnostic=Freshness(args.source,work,manifest,ledger,files,runner)
        result=diagnostic.run(); code=0
    except BaseException as error:
        result=(diagnostic.failure(error) if diagnostic is not None else
                {'status':'FAILED_OR_UNKNOWN','reason':type(error).__name__+':'+str(error)[:500],
                 'phases':{},'fixtureRetained':True,'fullIssue651Accepted':False})
        code=1
    try:
        if was_absent and work.is_dir(): files.write(work/'evidence/result.json',canonical(result),evidence=True)
    except BaseException:
        # Missing late evidence stays unknown; never mask an existing primary failure.
        if code==0: raise
    finally:
        signal.signal(signal.SIGTERM,previous_term)
    return code


if __name__=='__main__':
    raise SystemExit(main())
