#!/usr/bin/env python3
"""Trusted-build stage-only freshness diagnostic. Importing this file starts no work.

A reviewed input manifest and an already provisioned, repository-owned tool/cache
context are prerequisites. This is not descendant containment or packaging proof.
"""
from __future__ import annotations
import argparse
import errno
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
SOURCE_OUTPUTS = ('build', '.gradle', 'frontend/node_modules')
NPM_LINK = '../lib/node_modules/npm/bin/npm-cli.js'
GROUP_ENTRIES = 256  # All entries/advances, including the EOF observation.
GROUP_STAT_BYTES = 4096
GROUP_SCAN_BYTES = 1024**2

class Refusal(RuntimeError):
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_view(rows):
    """Private expected input state, derived from admitted pins and explicit owned edits only."""
    if type(rows) is not dict or not 0<len(rows)<=SOURCE[0]: raise Refusal('source input count')
    copied={}; total=0
    for name,row in rows.items():
        if type(name) is not str or not name or len(name.encode())>512 or Path(name).is_absolute() or '..' in Path(name).parts or Path(name).as_posix()!=name:
            raise Refusal('source input path')
        if type(row) is not dict or set(row)!={'bytes','sha256','mode'}: raise Refusal('source input pin fields')
        if type(row['bytes']) is not int or not 0<=row['bytes']<=SOURCE[1] or type(row['mode']) is not int or not 0<=row['mode']<=0o777:
            raise Refusal('source input size or mode')
        if type(row['sha256']) is not str or len(row['sha256'])!=64 or any(c not in '0123456789abcdef' for c in row['sha256']):
            raise Refusal('source input digest')
        total+=row['bytes']
        if total>SOURCE[2]: raise Refusal('source input aggregate')
        copied[name]=dict(row)
    return copied


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

    def npm_launcher(self, path):
        # Sole fixed leaf exception: never relax generic path/read admission.
        p=Path(path); p=self.path(p.parent)/p.name; self.ledger.check()
        first=p.lstat(); self.ledger.check()
        expected=NPM_LINK.encode('ascii')
        if p.name!='npm' or not stat.S_ISLNK(first.st_mode) or first.st_size!=len(expected):
            raise Refusal('fixed npm launcher link required')
        self.ledger.check(); target=os.readlink(p); self.ledger.check()
        last=p.lstat(); self.ledger.check()
        fields=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')
        if target!=NPM_LINK or any(getattr(first,k)!=getattr(last,k) for k in fields):
            raise Refusal('npm launcher link changed or unsupported')
        return expected

    def write(self, path, data, evidence=False):
        self.ledger.check(cleanup=evidence)
        if evidence: self.ledger.evidence(len(data))
        p=self.path(path); p.parent.mkdir(parents=True, exist_ok=True)
        with p.open('wb') as stream:
            for i in range(0,len(data),65536):
                self.ledger.check(cleanup=evidence); stream.write(data[i:i+65536])
        self.ledger.check(cleanup=evidence)

    def write_input(self, path, data, mode):
        self.write(path,data)
        self.path(path).chmod(mode)
        self.ledger.check()

    def inventory(self, root, limits=OUTPUT, budget=None, *, partitioned_ui=False, dist_assets=False, input_sources=None):
        root=self.path(root); budget={'entries':0,'bytes':0} if budget is None else budget; rows={}
        if partitioned_ui and dist_assets: raise Refusal('distinct UI/dist inventory policies required')
        if input_sources is not None and (partitioned_ui or dist_assets): raise Refusal('distinct source inventory policy required')
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
                    if stat.S_ISDIR(metadata.st_mode):
                        if input_sources is None or relative not in SOURCE_OUTPUTS: walk(p,depth+1)
                    elif stat.S_ISREG(metadata.st_mode):
                        if input_sources is not None:
                            if relative not in input_sources: raise Refusal('unexpected copied input')
                            pin=input_sources[relative]
                            if metadata.st_size!=pin['bytes'] or stat.S_IMODE(metadata.st_mode)!=pin['mode']:
                                raise Refusal('copied input metadata changed')
                        regular_files+=1
                        if dist_assets and regular_files>2048: raise Refusal('dist asset file bound')
                        if metadata.st_size > limits[1] or metadata.st_size < 0: raise Refusal('inventory file bound')
                        budget['bytes'] += metadata.st_size
                        if budget['bytes'] > limits[2]: raise Refusal('inventory aggregate bound')
                        if ui is not None: ui.admit(relative,metadata.st_size)
                        read_limit=metadata.st_size if ui is not None or input_sources is not None else limits[1]
                        data=self.read(p,read_limit); rows[relative]={'bytes':len(data),'sha256':sha(data)}
                        if input_sources is not None:
                            named=p.stat(follow_symlinks=False); self.ledger.check()
                            fields=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns')
                            if any(getattr(metadata,k)!=getattr(named,k) for k in fields): raise Refusal('copied input changed during inventory')
                            rows[relative]['mode']=stat.S_IMODE(metadata.st_mode)
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
                        if info.orig_filename!=info.filename: raise Refusal('JAR UI name changed during parsing')
                        name=info.filename[len('decompengine/web/ui/'):]
                        directory=info.is_dir()
                        relative=name[:-1] if directory else name
                        if (not name and not directory) or '\\' in name or (relative and any(part in ('','..','.') for part in relative.split('/'))):
                            raise Refusal('unsafe UI entry')
                        kind=stat.S_IFMT(info.external_attr>>16)
                        if kind==stat.S_IFLNK: raise Refusal('JAR UI symlink')
                        if kind not in (0,stat.S_IFDIR if directory else stat.S_IFREG): raise Refusal('JAR UI entry type')
                        if directory:
                            if info.file_size!=0: raise Refusal('JAR UI directory payload')
                            continue
                        if name in rows: raise Refusal('duplicate UI entry')
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



def npm_inputs(manifest, files):
    """Fixed launcher-text/entry-byte pins, not a transitive npm closure."""
    home=Path(manifest['nodeHome'])
    names=(str(home/'bin/npm'),str(home/'lib/node_modules/npm/bin/npm-cli.js'))
    tools=manifest.get('tools',{})
    if any(name not in tools for name in names): raise Refusal('required npm input lacks reviewed pin')
    observed={}
    for i,name in enumerate(names):
        data=files.npm_launcher(name) if i==0 else files.read(name,128*1024**2)
        row=tools[name]
        if type(row) is not dict or type(row.get('bytes')) is not int or row!={'sha256':sha(data),'bytes':len(data)}:
            raise Refusal('npm reviewed input disagreement')
        observed[name]={**row,'kind':'fixed-symlink-text' if i==0 else 'regular-entry-bytes'}
    return observed


class Runner:
    def __init__(self, ledger, files, evidence):
        self.ledger=ledger; self.files=files; self.evidence=evidence
        self.uncertain=False; self.sequence=0

    def group_members(self, pid, cleanup=False):
        """Bounded racy observation, never child ownership or containment proof."""
        count=total=0; members=[]; leader=False
        self.ledger.check(cleanup=cleanup)
        with os.scandir('/proc') as entries:
            while True:
                self.ledger.check(cleanup=cleanup)
                if count>=GROUP_ENTRIES: raise Refusal('group observation entry bound')
                count+=1
                try: entry=next(entries)
                except StopIteration: break
                name=entry.name
                if not name.isascii() or not name.isdecimal(): continue
                if len(name)>10 or int(name)<=0: raise Refusal('invalid proc identity')
                path='/proc/'+name+'/stat'; self.ledger.check(cleanup=cleanup)
                try: fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
                except OSError as error:
                    if error.errno!=errno.ENOENT: raise
                    continue  # This enumerated PID vanished; retain the entry/work bounds.
                try:
                    self.ledger.check(cleanup=cleanup); first=os.fstat(fd); self.ledger.check(cleanup=cleanup)
                    if not stat.S_ISREG(first.st_mode) or not 0<=first.st_size<=GROUP_STAT_BYTES:
                        raise Refusal('proc stat regular size admission')
                    data=bytearray()
                    while True:
                        self.ledger.check(cleanup=cleanup)
                        left=min(GROUP_STAT_BYTES-len(data),GROUP_SCAN_BYTES-total)
                        if left<=0: raise Refusal('group observation byte bound')
                        part=os.read(fd,left); self.ledger.check(cleanup=cleanup)
                        if not part: break
                        if len(part)>left: raise Refusal('proc read exceeded request')
                        total+=len(part); data.extend(part)
                    self.ledger.check(cleanup=cleanup); last=os.fstat(fd)
                    self.ledger.check(cleanup=cleanup)
                    try: named=os.stat(path,follow_symlinks=False)
                    except OSError as error:
                        if error.errno!=errno.ENOENT: raise
                        continue  # The owned descriptor still closes in finally below.
                    self.ledger.check(cleanup=cleanup)
                    fields=('st_dev','st_ino','st_mode','st_size')
                    if any(getattr(first,k)!=getattr(last,k) or getattr(first,k)!=getattr(named,k) for k in fields):
                        raise Refusal('proc stat identity changed')
                finally: os.close(fd)
                raw=bytes(data); close=raw.rfind(b')'); prefix=(name+' (').encode('ascii')
                if not raw.startswith(prefix) or close<len(prefix): raise Refusal('malformed proc stat')
                fields=raw[close+1:].split()
                if len(fields)<20 or fields[0] not in (b'R',b'S',b'D',b'Z',b'T',b't',b'X',b'x',b'K',b'W',b'P',b'I'):
                    raise Refusal('malformed proc stat fields')
                if any(not fields[i].isdigit() for i in (1,2,3,19)):
                    raise Refusal('malformed proc stat coordinates')
                group,session=int(fields[2]),int(fields[3])
                if group==pid:
                    if session!=pid: raise Refusal('owned group session mismatch')
                    if int(name)==pid: leader=True
                    else: members.append(int(name))
                self.ledger.check(cleanup=cleanup)
        if not leader: raise Refusal('held leader absent from group observation')
        self.ledger.check(cleanup=cleanup)
        return tuple(members)

    def __call__(self, argv, cwd, env):
        self.ledger.check(); self.sequence+=1
        child=None; held=False; captured=bytearray(); intervened=False; primary=None
        facts={'launcherCreated':False,'rootReaped':False,'exitCode':None,'operationalGroupAbsent':None,
               'terminationRequested':False,'killRequested':False,'waitUncertain':False,'groupObservation':'NOT_RUN'}
        def observe(cleanup=False):
            nonlocal held
            if not held: raise Refusal('child wait ownership unavailable')
            self.ledger.check(cleanup=cleanup)
            try: state=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
            except BaseException:
                held=False; facts['waitUncertain']=True; raise
            self.ledger.check(cleanup=cleanup)
            if state is not None and (state.si_pid!=child.pid or state.si_code not in (os.CLD_EXITED,os.CLD_KILLED,os.CLD_DUMPED)):
                held=False; facts['waitUncertain']=True
                raise Refusal('unrecognized child wait observation')
            return state
        def await_exit(cleanup=False):
            while observe(cleanup) is None:
                time.sleep(min(.01,self.ledger.check(cleanup=cleanup)))
        def reap(cleanup=False):
            nonlocal held
            timeout=self.ledger.check(cleanup=cleanup)
            if not held: raise Refusal('child already released')
            held=False  # Revoke BEFORE any final wait, including ambiguous failures.
            try: code=child.wait(timeout=timeout)
            except BaseException:
                facts['waitUncertain']=True; raise
            facts.update(rootReaped=True,exitCode=code)
            self.ledger.check(cleanup=cleanup)
            return code
        def membership(cleanup=False):
            observe(cleanup)
            try: members=self.group_members(child.pid,cleanup)
            except BaseException:
                facts['groupObservation']='UNKNOWN'; raise
            observe(cleanup)
            facts['groupObservation']='SURVIVORS' if members else 'LEADER_ONLY_SNAPSHOT'
            return members
        def send(number):
            # Only an unreaped actual child authorizes its original session group.
            observe(True); self.ledger.check(cleanup=True)
            os.killpg(child.pid,number)
            facts['terminationRequested' if number==signal.SIGTERM else 'killRequested']=True
            self.ledger.check(cleanup=True)
        def final_absence(cleanup=False):
            self.ledger.check(cleanup=cleanup)
            try: os.killpg(child.pid,0)
            except ProcessLookupError: facts['operationalGroupAbsent']=True
            else:
                facts['operationalGroupAbsent']=False
                raise Refusal('operational group leftovers; absence unverified')
            self.ledger.check(cleanup=cleanup)
        try:
            if signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL: raise Refusal('SIGCHLD ownership prerequisite')
            child=subprocess.Popen(argv,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
            held=True; facts['launcherCreated']=True
            with selectors.DefaultSelector() as selector:
                os.set_blocking(child.stdout.fileno(),False); selector.register(child.stdout,selectors.EVENT_READ)
                while selector.get_map():
                    for key,_ in selector.select(min(.1,self.ledger.check())):
                        self.ledger.check(); chunk=os.read(key.fileobj.fileno(),65536)
                        if not chunk: selector.unregister(key.fileobj); continue
                        self.ledger.output(len(chunk),len(captured)+len(chunk)); captured.extend(chunk)
            await_exit()
            if membership(): raise Refusal('observed operational group survivors')
            code=reap(); final_absence()
            return {'code':code,'output':bytes(captured),'intervened':False,'reaped':True}
        except BaseException as error:
            primary=error; intervened=True; self.uncertain=True
            if child is not None and held:
                try:
                    send(signal.SIGTERM)
                    grace=min(self.ledger.end,self.ledger.clock()+2)
                    while True:
                        state=observe(True)
                        try: members=membership(True)
                        except (OSError,Refusal): members=None
                        if state is not None and members==(): break
                        self.ledger.check(cleanup=True)
                        left=grace-self.ledger.clock()
                        if left<=0 or members is None: break
                        time.sleep(min(.01,left,self.ledger.check(cleanup=True)))
                    if state is None or members!=(): send(signal.SIGKILL)
                    await_exit(True); reap(True); final_absence(True)
                except BaseException: facts['waitUncertain']=not facts['rootReaped']
            raise
        finally:
            try:
                if child is not None and child.stdout is not None: child.stdout.close()
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
    if mode in ('unchanged','fresh','stale','drift'): wanted[':frontendInstall']='UP-TO-DATE'
    if mode=='unchanged':
        for name in TASKS[2:]:
            if name!='verifyFrontendAssets': wanted[':'+name]='UP-TO-DATE'
    if negative:
        wanted[':frontendBuild']='FAILED'
        if result['code']!=1 or b'Generated contract drift:' not in result['output']: raise Refusal('wrong negative failure')
    elif result['code']!=0: raise Refusal('build failed')
    if mode=='stale':
        allowed={name:{value} for name,value in wanted.items()}
        allowed[':generateFrontendAssetManifest']={'EXECUTED','UP-TO-DATE'}
        if any(rows[name] not in allowed[name] for name in rows): raise Refusal('actual stale task outcomes differ: '+json.dumps(rows,sort_keys=True))
    elif rows!=wanted: raise Refusal('actual task outcomes differ: '+json.dumps(rows,sort_keys=True))
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
        self._inputs=source_view(manifest.get('sources'))
        self.phases={name:{'status':'NOT_RUN'} for name in ('cold','unchanged','warm','fresh','stale','drift')}

    def require_inputs(self):
        observed=self.fs.inventory(self.fixture,SOURCE,input_sources=self._inputs)
        if observed!=self._inputs: raise Refusal('copied source changed')

    def read_input(self, name):
        pin=self._inputs[name]; data=self.fs.read(self.fixture/name,pin['bytes'])
        if len(data)!=pin['bytes'] or sha(data)!=pin['sha256']: raise Refusal('copied source changed before edit')
        return data

    def replace_input(self, name, data):
        self.read_input(name)
        mode=self._inputs[name]['mode']
        view=source_view({**self._inputs,name:{'bytes':len(data),'sha256':sha(data),'mode':mode}})
        self.fs.write_input(self.fixture/name,data,mode)
        self._inputs=view

    def rename_input(self, old, name, data):
        self.read_input(old)
        if name in self._inputs: raise Refusal('fresh input already admitted')
        mode=self._inputs[old]['mode']; view={k:v for k,v in self._inputs.items() if k!=old}
        view=source_view({**view,name:{'bytes':len(data),'sha256':sha(data),'mode':mode}})
        self.fs.write_input(self.fixture/name,data,mode)
        self.fs.remove(self.fixture/old)
        self._inputs=view

    def run_checked(self, argv, env):
        self.require_inputs()
        result=self.runner(argv,self.fixture,env)
        if result.get('intervened') is not False or result.get('reaped') is not True: raise Refusal('uncertain command')
        self.require_inputs()
        return result

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
        pins=npm_inputs(self.manifest,self.fs)
        argv,env=self.command(mode); result=self.run_checked(argv,env)
        if npm_inputs(self.manifest,self.fs)!=pins: raise Refusal('npm inputs changed across command')
        self.ledger.check(); actual=require_outcomes(result,mode)
        self.phases[mode]={'status':'BUILD_COMPLETED','taskOutcomes':actual,'npmInputPins':pins,'copiedInputSha256':sha(canonical(self._inputs)),'elapsedSeconds':self.ledger.clock()-self.ledger.start}
        self.fs.write(self.evidence/(mode+'-outcomes.json'),canonical(self.phases[mode]),evidence=True)

    def drift(self):
        self.enter('drift')
        targets=('frontend/src/api/generated.ts','frontend/src/api/generated-schema.ts','contracts/web/v1/contract.schema.json')
        checks=[]
        for i,name in enumerate(targets):
            self.require_inputs()
            original=self.read_input(name)
            if i<2: changed=original+b'\n// authored freshness drift\n'
            else:
                value=closed_json(original); value['definitions']['freshnessDriftProbe']={'type':'string','enum':['authored']}; changed=canonical(value)
            self.replace_input(name,changed)
            argv,env=self.command('drift')
            checked=self.run_checked([str(Path(self.manifest['nodeHome'])/'bin/node'),str(self.fixture/'scripts/generate-web-api.mjs'),'--check'],env)
            self.ledger.check()
            if checked['code']!=1 or b'Generated contract drift:' not in checked['output'] or checked['intervened'] or not checked['reaped']:
                raise Refusal('missing intended API drift refusal')
            if self.read_input(name)!=changed: raise Refusal('check silently rewrote drift')
            checks.append({'path':name,'copiedInputSha256':sha(canonical(self._inputs))})
            if i==0: self.build('drift')
            self.replace_input(name,original)
        self.require_inputs()
        self.phases['drift'].update(status='PASSED',apiSourceChecks=checks,restoredCopiedInputSha256=sha(canonical(self._inputs)))

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
        self.enter('fresh')
        self.require_inputs()
        data=self.read_input('frontend/src/app/mark.svg')
        if b'<svg' not in data: raise Refusal('expected SVG anchor absent')
        self.rename_input('frontend/src/app/mark.svg','frontend/src/app/freshness-mark.svg',data.replace(b'<svg',b'<svg data-freshness="changed"',1))
        original=self.read_input('frontend/src/app/App.tsx')
        if original.count(b"'./mark.svg'")!=1: raise Refusal('asset import anchor differs')
        self.replace_input('frontend/src/app/App.tsx',original.replace(b"'./mark.svg'",b"'./freshness-mark.svg'"))
        self.build('fresh'); fresh=self.snapshot()
        old_assets={n for n in warm['dist'] if n.endswith('.svg') and n.startswith('assets/mark-')}
        new_assets={n for n in fresh['dist'] if n.endswith('.svg') and n.startswith('assets/freshness-mark-')}
        if not old_assets or len(new_assets)!=1 or fresh['buildId']==warm['buildId'] or old_assets.intersection(fresh['dist']): raise Refusal('fresh asset not invalidated')
        new_asset=next(iter(new_assets))
        if not any(new_asset in row.get('assets',[]) for row in fresh['vite'].values()): raise Refusal('new asset not referenced by Vite chunk')
        if {warm['dist'][n]['sha256'] for n in old_assets}.intersection(fresh['dist'][n]['sha256'] for n in new_assets): raise Refusal('fresh asset bytes unchanged')
        self.phases['fresh']['status']='PASSED'
        self.fs.write(self.evidence/'fresh.json',canonical(fresh),evidence=True)
        self.enter('stale')
        for part in ('build/frontend/dist','build/generated/frontend-resources/decompengine/web/ui'):
            self.fs.write(self.fixture/part/'assets/freshness-obsolete.svg',b'<svg/>')
        self.build('stale'); stale=self.snapshot()
        if 'assets/freshness-obsolete.svg' in stale['dist'] or 'assets/freshness-obsolete.svg' in stale['staged'] or stale!=fresh:
            raise Refusal('obsolete asset retained or accepted fresh closure changed')
        self.phases['stale']['status']='PASSED'
        self.fs.write(self.evidence/'stale.json',canonical(stale),evidence=True)
        self.drift()
        self.require_inputs()
        for n in ('frontend/src/api/generated.ts','frontend/src/api/generated-schema.ts'):
            if self.fs.read(self.fixture/n)!=self.fs.read(self.source/n): raise Refusal('generated API changed')
        if self.baseline()!=baseline: raise Refusal('packaged baseline changed')
        npm_inputs(self.manifest,self.fs)
        self.ledger.check()
        return {'status':'PASSED_STAGE_ONLY','phases':self.phases,'packagedBaseline':baseline,'copiedInputSha256':sha(canonical(self._inputs)),
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
    npm_pins=npm_inputs(manifest,files)
    tool_bytes=0
    for name,row in manifest['tools'].items():
        if name==str(Path(manifest['nodeHome'])/'bin/npm'):
            data=files.npm_launcher(name)
        else:
            p=files.path(name); data=files.read(p,min(128*1024**2,512*1024**2-tool_bytes))
        tool_bytes+=len(data)
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
    files.write(work/'evidence/inputs.json',canonical({'manifest':manifest,'npmInputPins':npm_pins,'npmCacheInputSha256':sha(canonical(fingerprint))}),evidence=True)


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
