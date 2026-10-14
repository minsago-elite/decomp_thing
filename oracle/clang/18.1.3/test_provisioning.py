import base64
import contextlib
import errno
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/oracle"))
import provision_clang_18_1_3 as provision


def signed_package_rows_for_fixture(record):
    rows = {}
    for section in ("packages", "downloadedPackages"):
        for package in record[section]:
            key = (package["name"], package["version"], package["architecture"])
            rows[key] = {
                "Package": package["name"], "Version": package["version"],
                "Architecture": package["architecture"], "Filename": package["file"],
                "Size": str(package["bytes"]), "SHA256": package["sha256"],
                "_suite": package["suite"], "_component": package["component"],
            }
    return list(rows.values())


def finite_schema_corpus():
    conditional = {"type": "object", "required": ["kind", "target"], "properties": {
        "kind": {"enum": ["regular-file", "symlink"]}, "target": {"type": ["string", "null"]}},
        "allOf": [{"if": {"properties": {"kind": {"const": "regular-file"}}},
                   "then": {"properties": {"target": {"type": "null"}}},
                   "else": {"properties": {"target": {"type": "string", "minLength": 1}}}}]}
    return [
        ("const numeric equality", {"const": 1}, 1.0, True),
        ("const boolean distinction", {"const": 1}, True, False),
        ("enum numeric equality", {"enum": [1]}, 1.0, True),
        ("enum boolean distinction", {"enum": [1]}, True, False),
        ("integral float", {"type": "integer"}, 1.0, True),
        ("fractional float", {"type": "integer"}, 1.5, False),
        ("integer boolean distinction", {"type": "integer"}, True, False),
        ("unique numeric equality", {"uniqueItems": True}, [1, 1.0], False),
        ("unique boolean distinction", {"uniqueItems": True}, [1, True], True),
        ("object key order equality", {"uniqueItems": True}, [{"a": 1, "b": 2}, {"b": 2.0, "a": 1.0}], False),
        ("regular conditional valid", conditional, {"kind": "regular-file", "target": None}, True),
        ("regular conditional invalid", conditional, {"kind": "regular-file", "target": "link"}, False),
        ("symlink conditional valid", conditional, {"kind": "symlink", "target": "link"}, True),
        ("symlink conditional invalid", conditional, {"kind": "symlink", "target": None}, False),
        ("required object", conditional, {"kind": "regular-file"}, False),
        ("type conditional", conditional, [], False),
        ("additional properties", {"additionalProperties": False}, {"unknown": 1}, False),
        ("additional properties schema", {"additionalProperties": {"type": "integer"}}, {"any": 1.0}, True),
        ("array min", {"minItems": 2}, [1], False),
        ("array max", {"maxItems": 1}, [1, 2], False),
        ("string length", {"minLength": 2, "maxLength": 3}, "x", False),
        ("reviewed digest pattern", {"pattern": "^[0-9a-f]{64}$"}, "f" * 64, True),
        ("invalid digest pattern", {"pattern": "^[0-9a-f]{64}$"}, "F" * 64, False),
        ("minimum", {"minimum": 1}, 0.5, False),
        ("reference siblings", {"$defs": {"n": {"type": "number"}}, "$ref": "#/$defs/n", "minimum": 2}, 1, False),
        ("boolean true schema", {"items": True}, [1, False], True),
        ("boolean false schema", {"items": False}, [1], False),
    ]


class DownloadResponseFixture(io.BytesIO):
    def __init__(self, payload, announced=None):
        super().__init__(payload)
        self.headers = {"Content-Encoding": "identity"}
        if announced is not None:
            self.headers["Content-Length"] = str(announced)
        self.read_sizes = []

    def read(self, size=-1):
        self.read_sizes.append(size)
        return super().read(size)

    def geturl(self):
        return "https://snapshot.ubuntu.com/object"


def authored_deb_payload(package, entries, conffiles=b"", compression=""):
    """Inert local ar/USTAR bytes; metadata authentication is authored, not a signature claim."""
    def tar(rows):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for info, data in rows:
                archive.addfile(info, io.BytesIO(data) if info.isfile() else None)
        return output.getvalue()
    control = (f"Package: {package['name']}\nVersion: {package['version']}\nArchitecture: {package['architecture']}\n").encode()
    control_rows = []
    for name, data in (("control", control), ("conffiles", conffiles)):
        if name == "conffiles" and not data:
            continue
        info = tarfile.TarInfo(name);info.size=len(data);info.mode=0o644
        control_rows.append((info, data))
    members = [("debian-binary", b"2.0\n"), ("control.tar" + compression, tar(control_rows)),
               ("data.tar" + compression, tar(entries))]
    output = bytearray(b"!<arch>\n")
    for name, data in members:
        if name != "debian-binary":
            if compression == ".gz":data=gzip.compress(data, mtime=0)
            elif compression == ".xz":data=provision.lzma.compress(data)
        header=(f"{name+'/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n").encode()
        assert len(header)==60
        output.extend(header);output.extend(data)
        if len(data)%2:output.extend(b"\n")
    return bytes(output)


@contextlib.contextmanager
def authored_retained_root_binding(path):
    """Real inert descriptors; root-owned deployment admission is separately tested/mocked."""
    parent_fd=provision.open_directory_without_links(path.parent)
    root_fd=os.open(path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
    parent,root=os.fstat(parent_fd),os.fstat(root_fd)
    binding=provision.PinnedRootfsDirectory(path,path.parent,parent_fd,root_fd,(parent.st_dev,parent.st_ino),(root.st_dev,root.st_ino))
    try:yield binding
    finally:binding.close()


class PackagingLifetimeTests(unittest.TestCase):
    def setUp(self):
        parent=ROOT/"build/clang-packaging-lifetime-correction-001/test-tmp";parent.mkdir(parents=True,exist_ok=True)
        temporary=tempfile.TemporaryDirectory(dir=parent);self.addCleanup(temporary.cleanup)
        self.base=Path(temporary.name)

    def authority_metadata(self, metadata, identity):
        from types import SimpleNamespace
        if (metadata.st_dev,metadata.st_ino)!=identity:return metadata
        values={name:getattr(metadata,name) for name in dir(metadata) if name.startswith("st_")};values["st_uid"]=0
        return SimpleNamespace(**values)

    def test_actual_retained_pin_requires_root_authority_and_closes_on_failure(self):
        root=self.base/"rootfs";root.mkdir();opened=[];actual_open=os.open
        def track(*args,**kwargs):
            descriptor=actual_open(*args,**kwargs);opened.append(descriptor);return descriptor
        with mock.patch.object(provision.os,"open",side_effect=track):
            with self.assertRaisesRegex(provision.ProvisionError,"root-owned"):
                with provision.pin_retained_rootfs_directory(root):self.fail("caller-owned tree admitted")
        for descriptor in set(opened):
            with self.assertRaises(OSError):os.fstat(descriptor)

    def test_actual_pin_with_authored_root_owner_metadata_holds_fd_and_detects_replacement(self):
        root=self.base/"rootfs";root.mkdir();(root/"canary").write_bytes(b"original inode")
        metadata=root.stat();identity=(metadata.st_dev,metadata.st_ino)
        actual_fstat=os.fstat;actual_stat=os.stat
        def fstat(fd):return self.authority_metadata(actual_fstat(fd),identity)
        def stat(path,*args,**kwargs):return self.authority_metadata(actual_stat(path,*args,**kwargs),identity)
        held=[]
        with mock.patch.object(provision.os,"fstat",side_effect=fstat),mock.patch.object(provision.os,"stat",side_effect=stat):
            with self.assertRaisesRegex(provision.ProvisionError,"pathname binding"):
                with provision.pin_retained_rootfs_directory(root) as binding:
                    held.extend((binding.root_fd,binding.parent_fd))
                    self.assertEqual((binding.descriptor_path/"canary").read_bytes(),b"original inode")
                    root.rename(self.base/"original-rootfs");root.mkdir();(root/"canary").write_bytes(b"replacement canary")
                    self.assertEqual((binding.descriptor_path/"canary").read_bytes(),b"original inode")
                    binding.require_path_binding()
        for descriptor in held:
            with self.assertRaises(OSError):os.fstat(descriptor)
        self.assertEqual((root/"canary").read_bytes(),b"replacement canary")

    def test_root_pin_refuses_symlink_ancestor_without_consuming_it(self):
        real=self.base/"real";real.mkdir();(real/"rootfs").mkdir();alias=self.base/"alias";alias.symlink_to(real,target_is_directory=True)
        with self.assertRaises(provision.ProvisionError):
            with provision.pin_retained_rootfs_directory(alias/"rootfs"):self.fail("symlink ancestor admitted")

    def test_actual_packaging_consumer_receives_descriptor_and_rejects_late_root_swap(self):
        root=self.base/"rootfs";root.mkdir();(root/"canary").write_bytes(b"held")
        args=provision.argparse.Namespace(oci_archive=self.base/"inert-image")
        seen=[]
        with authored_retained_root_binding(root) as binding:
            def verify(path,*args,**kwargs):
                self.assertEqual(path,binding.descriptor_path);self.assertIs(kwargs["binding"],binding);seen.append("verify")
            def installed(path,contract):
                self.assertEqual(path,binding.descriptor_path);self.assertEqual((path/"canary").read_bytes(),b"held");seen.append("installed")
                root.rename(self.base/"retained");root.mkdir();return set()
            with mock.patch.object(provision,"verify_retained_rootfs_and_image",side_effect=verify),mock.patch.object(provision,"package_metadata_map",return_value={}),mock.patch.object(provision,"installed_package_keys",side_effect=installed),mock.patch.object(provision,"verify_recorded_driver_identities",side_effect=AssertionError("must not execute driver after swap")) as driver:
                with self.assertRaisesRegex(provision.ProvisionError,"pathname binding"):
                    provision._package_provenance_pinned(args,{}, {}, {},None,None,None,None,[],{},[],binding)
                driver.assert_not_called()
        self.assertEqual(seen,["verify","installed"])

    def test_private_archive_tar_roundtrip_and_exact_fd_identity_publication(self):
        destination=self.base/"provenance.tar";held=[]
        with provision.PinnedProvenanceArchive(destination,65536) as output:
            held.extend((output.stream.fileno(),output.parent_fd))
            with tarfile.open(fileobj=output,mode="w") as archive:
                info=tarfile.TarInfo("authored.txt");info.size=3;archive.addfile(info,io.BytesIO(b"abc"))
            self.assertFalse(destination.exists())
            identity=os.fstat(output.stream.fileno());result=output.publish()
            self.assertEqual((destination.stat().st_dev,destination.stat().st_ino),(identity.st_dev,identity.st_ino))
            self.assertEqual(result,{"bytes":destination.stat().st_size,"sha256":provision.sha256_file(destination)})
            with self.assertRaises(provision.ProvisionError):output.write(b"late mutation")
        with tarfile.open(destination) as archive:self.assertEqual(archive.extractfile("authored.txt").read(),b"abc")
        for descriptor in held:
            with self.assertRaises(OSError):os.fstat(descriptor)

    def test_archive_boundary_and_preexisting_canary_never_unlinked(self):
        destination=self.base/"provenance.tar"
        with provision.PinnedProvenanceArchive(destination,3) as output:
            output.write(b"abc");self.assertEqual(output.publish()["bytes"],3)
        destination.unlink();destination.write_bytes(b"canary")
        with provision.PinnedProvenanceArchive(destination,3) as output:
            output.write(b"abc")
            with self.assertRaises(provision.ProvisionError):output.publish()
        self.assertEqual(destination.read_bytes(),b"canary")
        destination.unlink()
        with provision.PinnedProvenanceArchive(destination,3) as output:
            with self.assertRaisesRegex(provision.ProvisionError,"byte budget"):output.write(b"abcd")
            self.assertEqual(output.tell(),0)
        self.assertFalse(destination.exists())

    def test_same_inode_mutation_after_publication_digest_is_refused(self):
        destination=self.base/"provenance.tar";actual_fsync=os.fsync
        with provision.PinnedProvenanceArchive(destination,16) as output:
            output.write(b"abc")
            def fsync(fd):
                actual_fsync(fd)
                if fd==output.parent_fd and destination.exists():
                    destination.chmod(0o600);destination.write_bytes(b"bad");destination.chmod(0o400)
            with mock.patch.object(provision.os,"fsync",side_effect=fsync):
                with self.assertRaisesRegex(provision.ProvisionError,"changed before completion"):output.publish()
        self.assertEqual(destination.read_bytes(),b"bad") # unaccepted name is never blindly deleted

    def test_archive_fdopen_failure_and_close_failure_release_parent_descriptors(self):
        destination=self.base/"provenance.tar";opened=[];actual_open=os.open
        def track(*args,**kwargs):
            fd=actual_open(*args,**kwargs);opened.append(fd);return fd
        with mock.patch.object(provision.os,"open",side_effect=track),mock.patch.object(provision.os,"fdopen",side_effect=OSError("authored fdopen failure")):
            with self.assertRaises(OSError):provision.PinnedProvenanceArchive(destination,16)
        for fd in set(opened):
            with self.assertRaises(OSError):os.fstat(fd)
        output=provision.PinnedProvenanceArchive(destination,16);parent_fd=output.parent_fd;stream=output.stream
        actual_close=stream.close
        def failed_close():
            actual_close();raise OSError("authored close failure")
        with mock.patch.object(stream,"close",side_effect=failed_close):
            with self.assertRaises(OSError):output.close()
        with self.assertRaises(OSError):os.fstat(parent_fd)
        self.assertFalse(destination.exists())

    def test_output_parent_replacement_and_post_link_swap_preserve_canaries(self):
        parent=self.base/"output";parent.mkdir();destination=parent/"provenance.tar"
        with provision.PinnedProvenanceArchive(destination,16) as output:
            output.write(b"authored")
            parent.rename(self.base/"retained-parent");parent.mkdir();destination.write_bytes(b"new-parent canary")
            with self.assertRaisesRegex(provision.ProvisionError,"parent binding"):output.publish()
        self.assertEqual(destination.read_bytes(),b"new-parent canary")
        destination.unlink();actual_link=os.link
        def link(*args,**kwargs):
            actual_link(*args,**kwargs);destination.rename(parent/"unaccepted-original");destination.write_bytes(b"post-link canary")
        with provision.PinnedProvenanceArchive(destination,16) as output:
            output.write(b"authored")
            with mock.patch.object(provision.os,"link",side_effect=link):
                with self.assertRaisesRegex(provision.ProvisionError,"destination binding"):output.publish()
        self.assertEqual(destination.read_bytes(),b"post-link canary")
        self.assertEqual((parent/"unaccepted-original").read_bytes(),b"authored")


class AuthenticatedDebPayloadTests(unittest.TestCase):
    def setUp(self):
        self.contract=provision.read_contract()
        parent=ROOT/"build/clang-signed-package-payload-correction-002/test-tmp"
        parent.mkdir(parents=True,exist_ok=True)
        temporary=tempfile.TemporaryDirectory(dir=parent);self.addCleanup(temporary.cleanup)
        self.base=Path(temporary.name);self.root=self.base/"rootfs";self.root.mkdir()
        self.payloads=self.base/"payloads";self.payloads.mkdir()
        self.package={"name":"authored-clang", "version":"1:18.1.3-1", "architecture":"amd64"}

    def entry(self, name, data=b"", kind=tarfile.REGTYPE, target="", mode=0o644):
        info=tarfile.TarInfo(name);info.type=kind;info.linkname=target;info.mode=mode
        info.uid=os.getuid();info.gid=os.getgid();info.size=len(data) if info.isfile() else 0
        return info,data

    def package_bytes(self, entries, **kwargs):
        data=authored_deb_payload(self.package,entries,**kwargs)
        row={**self.package,"bytes":len(data),"sha256":provision.sha256(data)}
        (self.payloads/(row["sha256"]+".deb")).write_bytes(data)
        return row,data

    def fixture(self, compression="", *, include_root=True):
        (self.root/"usr/bin").mkdir(parents=True)
        (self.root/"usr/lib/llvm-18/include").mkdir(parents=True)
        (self.root/"etc").mkdir()
        files={"usr/bin/clang-18":b"authored inert compiler", "usr/lib/llvm-18/include/LangOptions.h":b"authored inert header", "usr/lib/library.so":b"authored inert library", "etc/clang.conf":b"authored conffile"}
        for name,data in files.items():
            (self.root/name).write_bytes(data);(self.root/name).chmod(0o755 if name.endswith("clang-18") else 0o644)
        (self.root/"usr/bin/clang++-18").symlink_to("clang-18")
        os.link(self.root/"usr/bin/clang-18",self.root/"usr/bin/clang-alias")
        entries=([self.entry(".",kind=tarfile.DIRTYPE,mode=0o755)] if include_root else [])
        entries += [self.entry(name,data,mode=0o755 if name.endswith("clang-18") else 0o644) for name,data in files.items()]
        entries += [self.entry("usr/bin/clang++-18",kind=tarfile.SYMTYPE,target="clang-18",mode=0o777),self.entry("usr/bin/clang-alias",kind=tarfile.LNKTYPE,target="usr/bin/clang-18",mode=0o755)]
        return self.package_bytes(entries,conffiles=b"/etc/clang.conf\n",compression=compression)

    def test_authentic_payloads_and_all_supported_compressions_pass(self):
        for compression in ("", ".gz", ".xz"):
            with self.subTest(compression=compression):
                # Fresh authored tree per compression, no installation or extraction.
                if (self.root/"usr").exists():shutil.rmtree(self.root/"usr");shutil.rmtree(self.root/"etc")
                row,_=self.fixture(compression)
                result=provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)
                self.assertEqual(len(result["files"]),13)
                self.assertTrue(next(x for x in result["files"] if x["path"]=="/etc/clang.conf")["entry"]["conffile"])

    def test_implicit_parents_have_recorded_signed_root_derivation_and_exact_metadata(self):
        row,_=self.fixture()
        manifest=provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)
        parents=[record for record in manifest["files"] if "derivation" in record]
        self.assertEqual({record["path"] for record in parents},{"/usr","/usr/bin","/usr/lib","/usr/lib/llvm-18","/usr/lib/llvm-18/include","/etc"})
        for record in parents:
            self.assertEqual(record["entry"],{"kind":"directory","mode":0o755,"uid":os.getuid(),"gid":os.getgid()})
            self.assertEqual(record["derivation"],{"rule":"implicit-parent-from-authenticated-root-v1","sourcePath":"/","extendedMetadata":"none"})
        parent=self.root/"usr";parent.chmod(0o777)
        with self.assertRaisesRegex(provision.ProvisionError,"mode/owner"):
            provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)
        parent.chmod(0o755)
        original_stat=provision.os.stat
        def changed_owner(path,*args,**kwargs):
            metadata=original_stat(path,*args,**kwargs)
            if path=="usr" and "dir_fd" in kwargs and kwargs.get("follow_symlinks") is False:
                from types import SimpleNamespace
                values={name:getattr(metadata,name) for name in dir(metadata) if name.startswith("st_")}
                values["st_uid"]+=1
                return SimpleNamespace(**values)
            return metadata
        with mock.patch.object(provision.os,"stat",side_effect=changed_owner):
            with self.assertRaisesRegex(provision.ProvisionError,"mode/owner"):
                provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)
        original_xattrs=provision.os.listxattr
        def parent_acl(path,*args,**kwargs):
            return ["system.posix_acl_access"] if str(path).endswith("/usr") else original_xattrs(path,*args,**kwargs)
        with mock.patch.object(provision.os,"listxattr",side_effect=parent_acl):
            with self.assertRaisesRegex(provision.ProvisionError,"extended metadata"):
                provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)

    def test_missing_parent_authority_and_explicit_parent_conflicts_refuse(self):
        row,_=self.fixture(include_root=False)
        with self.assertRaisesRegex(provision.ProvisionError,"lacks authenticated root-directory"):
            provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)
        # Existing explicit directory metadata remains authoritative and cannot be
        # overwritten by a default derivation or a conflicting second package.
        entries=[self.entry("usr",kind=tarfile.DIRTYPE,mode=0o700),self.entry("usr/owned",b"authored")]
        row,_=self.package_bytes(entries)
        root=self.base/"explicit-root";root.mkdir();(root/"usr").mkdir(mode=0o700);(root/"usr/owned").write_bytes(b"authored")
        manifest=provision.verify_installed_package_payloads(root,self.payloads,[row],self.contract)
        directory=next(record for record in manifest["files"] if record["path"]=="/usr")
        self.assertNotIn("derivation",directory);self.assertEqual(directory["entry"]["mode"],0o700)
        second={**self.package,"name":"authored-other"}
        data=authored_deb_payload(second,[self.entry("usr",kind=tarfile.DIRTYPE,mode=0o755)])
        second.update(bytes=len(data),sha256=provision.sha256(data));(self.payloads/(second["sha256"]+".deb")).write_bytes(data)
        with self.assertRaisesRegex(provision.ProvisionError,"conflicting.*ownership"):
            provision.verify_installed_package_payloads(root,self.payloads,[row,second],self.contract)

    def test_rehashed_installed_compiler_header_library_conffile_and_link_mutations_refuse(self):
        row,_=self.fixture()
        for name in ("usr/bin/clang-18","usr/lib/llvm-18/include/LangOptions.h","usr/lib/library.so","etc/clang.conf"):
            path=self.root/name;saved=path.read_bytes();path.write_bytes(b"self-consistently rehashed malicious bytes")
            caller_record={"sha256":provision.sha256_file(path)} # does not supply authority to verifier
            self.assertIsNotNone(caller_record)
            with self.assertRaisesRegex(provision.ProvisionError,"differs from authenticated payload"):
                provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)
            path.write_bytes(saved)
        link=self.root/"usr/bin/clang++-18";link.unlink();link.symlink_to("not-clang")
        with self.assertRaises(provision.ProvisionError):provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)

    def test_mode_owner_hardlink_and_parent_aliases_refuse(self):
        row,_=self.fixture()
        with mock.patch.object(provision.os,"listxattr",return_value=["security.capability"]):
            with self.assertRaisesRegex(provision.ProvisionError,"extended metadata"):
                provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)
        header=self.root/"usr/lib/llvm-18/include/LangOptions.h";header.chmod(0o600)
        with self.assertRaisesRegex(provision.ProvisionError,"mode/owner"):provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)
        header.chmod(0o644)
        owner_root=self.base/"owner-root";owner_root.mkdir();(owner_root/"owned").write_bytes(b"authored")
        info,data=self.entry("owned",b"authored");info.uid+=1
        owner_row,_=self.package_bytes([(info,data)])
        with self.assertRaisesRegex(provision.ProvisionError,"mode/owner"):provision.verify_installed_package_payloads(owner_root,self.payloads,[owner_row],self.contract)
        alias=self.root/"usr/bin/clang-alias";alias.unlink();alias.write_bytes((self.root/"usr/bin/clang-18").read_bytes());alias.chmod(0o755)
        with self.assertRaisesRegex(provision.ProvisionError,"hardlink"):provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)
        alias.unlink();os.link(self.root/"usr/bin/clang-18",alias)
        original=self.root/"usr/lib";original.rename(self.root/"usr/retained-lib");original.symlink_to("retained-lib")
        with self.assertRaises(provision.ProvisionError):provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)

    def test_missing_changed_unbound_and_bootstrap_payloads_refuse(self):
        row,data=self.fixture();source=self.payloads/(row["sha256"]+".deb")
        source.write_bytes(data+b"changed")
        with self.assertRaises(provision.ProvisionError):provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)
        source.write_bytes(data)
        bootstrap={**row,"name":"authored-bootstrap","sha256":"a"*64}
        with self.assertRaises(provision.ProvisionError):provision.verify_installed_package_payloads(self.root,self.payloads,[row,bootstrap],self.contract)
        source.unlink()
        with self.assertRaises(provision.ProvisionError):provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)

    def test_unsafe_duplicate_special_and_escaping_or_forward_link_members_refuse(self):
        cases=[[self.entry("/absolute")],[self.entry("../escape")],[self.entry("duplicate"),self.entry("duplicate")],
               [self.entry("device",kind=tarfile.CHRTYPE)], [self.entry("pax",b"override",kind=tarfile.XHDTYPE)],
               [self.entry("link",kind=tarfile.SYMTYPE,target="../../escape")],
               [self.entry("link",kind=tarfile.LNKTYPE,target="later"),self.entry("later")]]
        for entries in cases:
            row,data=self.package_bytes(entries)
            with self.subTest(entries=entries),self.assertRaises(provision.ProvisionError):
                provision.authenticated_deb_manifest(data,row,provision.DebPayloadBudget(self.contract))

    def test_budgets_conflicts_conffile_declarations_and_trailing_streams_refuse(self):
        row,data=self.fixture(".gz")
        budget=provision.DebPayloadBudget(self.contract);budget.decoded=16
        with self.assertRaisesRegex(provision.ProvisionError,"decoded-byte"):provision.authenticated_deb_manifest(data,row,budget)
        budget=provision.DebPayloadBudget(self.contract);budget.entries=0
        with self.assertRaisesRegex(provision.ProvisionError,"entry budget"):provision.authenticated_deb_manifest(data,row,budget)
        with self.assertRaisesRegex(provision.ProvisionError,"trailing"):
            provision._deb_decode("data.tar.gz",gzip.compress(b"x")+gzip.compress(b"y"),provision.DebPayloadBudget(self.contract))
        row2={**row,"name":"conflicting-package"}
        row2,data2=self.package_bytes([self.entry("usr/bin/clang-18",b"different")])
        row2["name"]="conflicting-package" # control identity must also be authenticated
        data2=authored_deb_payload(row2,[self.entry("usr/bin/clang-18",b"different")]);row2.update(bytes=len(data2),sha256=provision.sha256(data2));(self.payloads/(row2["sha256"]+".deb")).write_bytes(data2)
        with self.assertRaisesRegex(provision.ProvisionError,"conflicting.*ownership"):
            provision.verify_installed_package_payloads(self.root,self.payloads,[row,row2],self.contract)
        bad,packed=self.package_bytes([self.entry("etc/a",b"x")],conffiles=b"/etc/missing\n")
        with self.assertRaisesRegex(provision.ProvisionError,"conffile"):
            provision.authenticated_deb_manifest(packed,bad,provision.DebPayloadBudget(self.contract))

    def test_existing_offline_packaging_fixture_constructs_real_authored_payload_closure(self):
        self.fixture()
        record={"packages":[dict(self.package),{**self.package,"name":"authored-empty-metapackage"}],"downloadedPackages":[dict(self.package)]}
        destination=self.base/"fixture-payloads"
        RecipeAndCandidateBindingTests.authenticated_payloads_for_packaging_fixture(self,self.root,record,destination)
        self.assertEqual(record["downloadedPackages"][0],record["packages"][0])
        manifest=provision.verify_installed_package_payloads(self.root,destination,record["packages"],self.contract)
        self.assertEqual(len(manifest["payloads"]),2)
        self.assertEqual(next(row for row in manifest["files"] if row["path"]=="/usr/bin/clang-18")["entry"]["kind"],"file")

    def test_generated_or_omitted_package_files_cannot_hide_behind_installed_database(self):
        row,_=self.fixture();extra=self.root/"etc/ld.so.preload";extra.write_bytes(b"unapproved runtime injection")
        with self.assertRaisesRegex(provision.ProvisionError,"unapproved generated or omitted-package"):
            provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)
        extra.unlink()
        partial,_=self.package_bytes([self.entry(".",kind=tarfile.DIRTYPE,mode=0o755),self.entry("etc/clang.conf",b"authored conffile")])
        with self.assertRaisesRegex(provision.ProvisionError,"unapproved generated or omitted-package"):
            provision.verify_installed_package_payloads(self.root,self.payloads,[partial],self.contract)

    def test_retention_is_complete_and_cumulative_budget_precedes_payload_io(self):
        row,data=self.fixture();cache=self.root/"var/cache/apt/archives";cache.mkdir(parents=True)
        (cache/"authored.deb").write_bytes(data);destination=self.base/"retained"
        provision.retain_signed_package_payloads(self.root,destination,[row],self.contract)
        self.assertEqual((destination/(row["sha256"]+".deb")).read_bytes(),data)
        shutil.rmtree(destination);(cache/"authored.deb").unlink()
        with self.assertRaises(provision.ProvisionError):provision.retain_signed_package_payloads(self.root,destination,[row],self.contract)
        contract=json.loads(json.dumps(self.contract));contract["profile"]["bounds"]["maxAcquisitionBytes"]=row["bytes"]-1
        with mock.patch.object(provision,"read_regular_evidence",side_effect=AssertionError("over-budget payload read")):
            with self.assertRaisesRegex(provision.ProvisionError,"before read"):
                provision.retain_signed_package_payloads(self.root,self.base/"over-budget",[row],contract)

    def test_changed_identity_is_rejected_before_reading_replacement_descriptor(self):
        row,_=self.fixture();source=self.root/"usr/lib/llvm-18/include/LangOptions.h"
        original_open=os.open;original_read=os.read;replacement={}
        def opened(path,flags,*args,**kwargs):
            if path=="LangOptions.h" and "dir_fd" in kwargs and not replacement:
                source.rename(source.with_name("retained-original-header"));source.write_bytes(b"authored inert header")
                descriptor=original_open(path,flags,*args,**kwargs);replacement["fd"]=descriptor;return descriptor
            return original_open(path,flags,*args,**kwargs)
        def read(descriptor,size):
            if descriptor==replacement.get("fd"):raise AssertionError("replacement descriptor consumed before identity refusal")
            return original_read(descriptor,size)
        with mock.patch.object(provision.os,"open",side_effect=opened),mock.patch.object(provision.os,"read",side_effect=read):
            with self.assertRaisesRegex(provision.ProvisionError,"identity changed before read"):
                provision.verify_installed_package_payloads(self.root,self.payloads,[row],self.contract)

    def test_actual_packaging_gate_refuses_missing_signed_payload_before_native_replay(self):
        row,_=self.fixture()
        acquisition=self.base/"acquisition";acquisition.mkdir();(acquisition/"downloads").mkdir()
        for name in ("acquisition-candidate.json","patch-audit.json"):(acquisition/name).write_bytes(b"{}")
        image=self.base/"image.tar";image.write_bytes(b"inert image placeholder")
        record={"reproducibility":{"cleanBuilds":2,"matchingRootfsSha256":True,"matchingImageDigest":True},"packages":[row],"downloadedPackages":[]}
        args=provision.argparse.Namespace(contract=provision.CONTRACT_PATH,record=self.base/"record.json",acquisition=acquisition,rootfs=self.root,oci_archive=image,probe_report=self.base/"probe.json",loader_report=self.base/"loader.json",negative_report=self.base/"negative.json",negative_compiler=self.base/"negative",keyring=self.base/"keyring",output=self.base/"must-not-exist.tar")
        key=(row["name"],row["version"],row["architecture"])
        # Authored upstream signed metadata/image gates only; actual new payload gate is not mocked out.
        with mock.patch.object(provision,"pin_retained_rootfs_directory",side_effect=authored_retained_root_binding),mock.patch.object(provision,"read_provenance_report",return_value=record),mock.patch.object(provision,"validate_build_record"),mock.patch.object(provision,"preflight_provenance_output",return_value=args.output),mock.patch.object(provision,"validate_locked_comparator_manifest",return_value=(None,self.base/"manifest",None,None)),mock.patch.object(provision,"load_candidate",return_value=({},[])),mock.patch.object(provision,"verify_retained_rootfs_and_image"),mock.patch.object(provision,"package_metadata_map",return_value={key:row}),mock.patch.object(provision,"installed_package_keys",return_value={key}),mock.patch.object(provision,"verify_installed_package_payloads",wraps=provision.verify_installed_package_payloads) as gate,mock.patch.object(provision,"verify_recorded_driver_identities",side_effect=AssertionError("must not replay native tools")) as native:
            with self.assertRaisesRegex(provision.ProvisionError,"regular evidence input"):
                provision._package_provenance_unqualified(args)
            gate.assert_called_once();native.assert_not_called()
        self.assertFalse(args.output.exists())


class ProvisioningNegativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = provision.read_contract()
        (ROOT / "build").mkdir(exist_ok=True)
        cls.temp_root = Path(tempfile.mkdtemp(prefix="clang1813-offline-tests-", dir=ROOT / "build"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_root, ignore_errors=True)

    def temporary_directory(self):
        return tempfile.TemporaryDirectory(dir=self.temp_root)

    def simulate_privileged_rootfs_helper(self, command):
        self.assertEqual(command[0], "sudo")
        if command[5] == provision.ROOTFS_PARENT_RESTORE_PROGRAM:
            return mock.Mock(stdout="")
        self.assertEqual(command[5], provision.ROOTFS_DIRECTORY_CREATE_PROGRAM)
        parent_path, name = command[6:8]
        parent_fd = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.mkdir(name, dir_fd=parent_fd)
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                metadata = os.fstat(descriptor)
            finally:
                os.close(descriptor)
        finally:
            os.close(parent_fd)
        return mock.Mock(stdout=f"{metadata.st_dev}:{metadata.st_ino}\n")

    def simulate_privileged_rootfs_tar_publication(self, command, timeout=None):
        self.assertEqual(command[0], "sudo")
        self.assertEqual(command[5], provision.ROOTFS_TAR_PUBLISH_PROGRAM)
        source_parent, source_name, output_parent, destination_name = command[6:10]
        expected_bytes, expected_sha256 = int(command[10]), command[11]
        source = Path(source_parent) / source_name
        destination = Path(output_parent) / destination_name
        payload = source.read_bytes()
        if len(payload) != expected_bytes:
            raise provision.ProvisionError("verified rootfs tar pathname differs from its recorded identity")
        if provision.sha256(payload) != expected_sha256:
            raise provision.ProvisionError("verified rootfs tar bytes changed before publication")
        with destination.open("xb") as stream:
            stream.write(payload)
        destination.chmod(0o444)
        metadata = destination.stat()
        return mock.Mock(stdout=f"{metadata.st_dev}:{metadata.st_ino}\n")

    def report_fixture_publications_as_root_owned(self, original_stat):
        def fixture(path, *args, **kwargs):
            metadata = original_stat(path, *args, **kwargs)
            if stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o444:
                fields = list(metadata)
                fields[stat.ST_UID] = 0
                return os.stat_result(fields)
            return metadata
        return fixture

    def report_fixture_descriptors_as_root_owned(self, original_fstat):
        def fixture(descriptor):
            metadata = original_fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o444:
                fields = list(metadata)
                fields[stat.ST_UID] = 0
                return os.stat_result(fields)
            return metadata
        return fixture

    def valid_build_record(self):
        digest = "a" * 64
        profile = self.contract["profile"]
        packages = []
        for pin in profile["binaryRoots"]:
            packages.append({
                "name": pin["name"], "version": pin["version"], "architecture": "amd64",
                "suite": "noble", "component": "universe",
                "file": f"pool/universe/l/llvm-toolchain-18/{pin['name']}.deb",
                "bytes": 1, "sha256": digest,
            })
        packages.append({
            "name": "ca-certificates", "version": "synthetic-test-only", "architecture": "all",
            "suite": "noble", "component": "main", "file": "pool/main/c/ca-certificates/fixture.deb",
            "bytes": 1, "sha256": digest,
        })
        tool = lambda role: {
            "role": role, "path": "/usr/bin/clang-18" if role == "c-driver" else "/usr/bin/clang++-18",
            "symlinkChain": [], "resolvedPath": "/usr/lib/llvm-18/bin/clang",
            "bytes": 1, "sha256": digest,
            "mode": "0555",
            "versionOutput": "clang version 18.1.3\n",
        }
        file_manifest = provision.manifest([
            {"path": "/usr/lib/llvm-18/lib/libclang-cpp.so", "bytes": 1, "sha256": digest,
             "kind": "regular-file", "target": None},
            {"path": "/usr/lib/llvm-18/lib/libLLVM-18.so", "bytes": 2, "sha256": "b" * 64,
             "kind": "regular-file", "target": None},
            {"path": "/usr/lib/llvm-18/lib/libclang.so", "bytes": 3, "sha256": "c" * 64,
             "kind": "regular-file", "target": None},
        ])
        resources = provision.manifest([{"path": "/usr/lib/llvm-18/lib/clang/18.1.3/include/stddef.h",
                                         "bytes": 1, "sha256": digest}])
        repositories = [{
            "suite": suite,
            "inRelease": f"{profile['snapshotBase']}dists/{suite}/InRelease",
            "sha256": digest, "bytes": 1,
            "signerPrimaryFingerprint": profile["ubuntuArchivePrimaryFingerprints"][0],
        } for suite in profile["suites"]]
        probe = {
            "compilerVersion": "18.1.3", "target": "x86_64-pc-linux-gnu",
            "inventoryEvidence": self.contract["langOptions"]["inventoryEvidence"],
            "generatedFields": self.contract["langOptions"]["generatedFieldCount"],
            "familyCounts": self.contract["langOptions"]["familyCounts"],
            "generatedFieldNames": [f"Field{i}" for i in range(298)],
            "manualFields": self.contract["langOptions"]["manualFields"],
            "callingConventions": self.contract["langOptions"]["callingConventions"],
            "apiChecks": self.contract["langOptions"]["apiChecks"],
            "runtimeLangOptionsChecks": self.contract["langOptions"]["runtimeChecks"],
            "macroObservations": {"expansionCount": 1, "macroInfoChecks": 1,
                                   "nonBuiltinClassifications": 1},
            "definitionSha256": digest, "headerSha256": digest,
            "sourceSha256": provision.recipe_identity()["probeSha256"],
            "binarySha256": digest, "fixtureSha256": digest,
        }
        return {
            "schemaVersion": 1,
            "buildSystem": "ubuntu-snapshot-debootstrap-apt",
            "profile": {"id": profile["id"], "architecture": "amd64", "target": profile["target"],
                        "snapshot": profile["snapshot"], "codename": profile["codename"]},
            "acquisition": {
                "repositories": repositories, "ubuntuKeyring": {"bytes": 1, "sha256": digest},
                "candidateSha256": digest,
                "sourceIndexesSha256": digest, "binaryIndexesSha256": digest,
                "signatureFingerprints": [row["signerPrimaryFingerprint"] for row in repositories],
            },
            "source": {
                "package": "llvm-toolchain-18", "version": "1:18.1.3-1ubuntu1",
                "upstreamTag": "llvmorg-18.1.3",
                "dsc": {"bytes": 1, "sha256": digest},
                "files": [{"name": "source.dsc", "bytes": 1, "sha256": digest, "role": "dsc"}],
                "upstreamArchive": {"bytes": 1, "sha256": digest},
                "upstreamSignature": {"bytes": 1, "sha256": digest},
                "upstreamKeyring": {"bytes": 1, "sha256": digest},
            },
            "patchAudit": {"status": "compatible", "patchCount": 0,
                            "patchInventorySha256": digest, "relevantFileCount": 34,
                            "relevantFileManifestSha256": digest},
            "packages": packages, "downloadedPackages": [dict(row) for row in packages],
            "tools": [tool("c-driver"), tool("cxx-driver")],
            "runtime": file_manifest, "resources": resources,
            "resourceDirectory": "/usr/lib/llvm-18/lib/clang/18.1.3",
            "probe": probe, "environment": self.contract["environment"],
            "recipe": provision.recipe_identity(),
            "commands": provision.canonical_commands(self.contract, digest),
            "rootfs": {"bytes": 1, "sha256": digest},
            "image": {"format": "oci-image-layout-v1", "manifestSha256": digest,
                      "imageDigest": "sha256:" + digest},
            "imageArtifact": {"bytes": 1, "sha256": digest},
            "reproducibility": {"cleanBuilds": 2, "matchingRootfsSha256": True,
                                 "matchingImageDigest": True},
        }

    def test_contract_pins_all_development_and_runtime_roots(self):
        roots = {row["name"] for row in self.contract["profile"]["binaryRoots"]}
        self.assertEqual(roots, {
            "clang-18", "llvm-18-dev", "libclang-18-dev",
            "libclang-cpp18-dev", "libclang-cpp18",
        })

    def test_contract_pins_the_exact_version_scoped_tom_stellard_release_key(self):
        upstream = self.contract["profile"]["upstream"]
        self.assertEqual(upstream["keyFile"], "oracle/clang/18.1.3/keys/tom-stellard-llvm-release.asc")
        self.assertEqual(upstream["keySha256"], "29e76f29dc1894b8f7d494ed74b3aef1509bc757888a39b50bf069240979dba9")
        self.assertEqual(upstream["primaryFingerprint"], "474E22316ABF4785A88C6E8EA2C794A986419D8A")
        key = ROOT / upstream["keyFile"]
        self.assertEqual(key.stat().st_size, 3935)
        self.assertEqual(provision.sha256_file(key), upstream["keySha256"])

    def test_detached_signature_rejects_expired_tom_key_before_accepting_validsig(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            data, signature = base / "source", base / "source.sig"
            data.write_bytes(b"small authenticated tag fixture")
            signature.write_bytes(b"detached signature fixture")
            upstream = self.contract["profile"]["upstream"]
            key = ROOT / upstream["keyFile"]
            status = (
                "[GNUPG:] KEYEXPIRED 1746208199\n"
                "[GNUPG:] EXPKEYSIG A2C794A986419D8A Tom Stellard <tstellar@redhat.com>\n"
                "[GNUPG:] VALIDSIG 474E22316ABF4785A88C6E8EA2C794A986419D8A "
                "2024-04-03 1712188131 0 4 0 1 8 00 474E22316ABF4785A88C6E8EA2C794A986419D8A\n"
            )
            with mock.patch.object(provision.subprocess, "run", return_value=mock.Mock(
                    returncode=0, stdout=status, stderr="")) as run:
                with self.assertRaisesRegex(
                        provision.ProvisionError,
                        "upstream signature has a rejected or unknown status: KEYEXPIRED"):
                    provision.verify_detached_signature(signature, data, key, upstream["primaryFingerprint"])
            self.assertEqual(run.call_args.args[0][0], "gpgv")

    def test_relevant_file_policy_rejects_absolute_substituted_and_dot_paths_before_reads(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            canaries = []
            for index in range(34):
                path = base / ("host-canary-" + str(index))
                path.write_bytes(b"host canary must not be audited")
                canaries.append(path)
            substitutions = [str(path.resolve()) for path in canaries]
            original = self.contract["relevantFiles"]
            policies = [substitutions]
            for value in ("host-canary-0", "clang/../host-canary-0", "./" + original[0],
                          original[0].replace("/include/", "//include/"), original[0] + "/",
                          original[0].replace("LangOptions.def", "Unreviewed.def")):
                policies.append([value, *original[1:]])
            for index, policy in enumerate(policies):
                contract = json.loads(provision.canonical_json(self.contract))
                contract["relevantFiles"] = policy
                selected = base / ("contract-" + str(index) + ".json")
                selected.write_bytes(provision.canonical_json(contract))
                output = base / ("audit-" + str(index) + ".json")
                with self.subTest(policy=policy[0]), mock.patch.object(provision, "inventory_patch_files") as inventory, \
                        mock.patch.object(Path, "read_bytes", side_effect=AssertionError("unexpected audited host file read")):
                    with self.assertRaisesRegex(provision.ProvisionError, "relevantFiles"):
                        provision.read_contract(selected)
                    with self.assertRaisesRegex(provision.ProvisionError, "relevantFiles"):
                        provision.audit_patches(base / "package", base / "upstream", output, contract)
                    inventory.assert_not_called()
                self.assertFalse(output.exists())
            for path in canaries:
                self.assertEqual(path.read_bytes(), b"host canary must not be audited")
            self.assertEqual(tuple(original), provision.REVIEWED_RELEVANT_FILES)

    def test_reviewed_source_fd_reads_refuse_symlink_escape_and_over_budget_input(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            root = base / "source"
            relative = self.contract["relevantFiles"][0]
            target = root / relative
            target.parent.mkdir(parents=True)
            canary = base / "host-canary"
            canary.write_bytes(b"must remain outside the source audit")
            target.symlink_to(canary)
            descriptor = os.open(root, os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC)
            try:
                with self.assertRaises(OSError):
                    provision.read_audited_source_file(descriptor, relative)
                target.unlink()
                target.write_bytes(b"four")
                with mock.patch.object(provision, "MAX_SINGLE_DOWNLOAD", 3):
                    with self.assertRaisesRegex(provision.ProvisionError, "byte budget"):
                        provision.read_audited_source_file(descriptor, relative)
                for path in ("../host-canary", str(canary.resolve()), "clang/./wrong"):
                    with self.subTest(path=path), self.assertRaisesRegex(provision.ProvisionError, "reviewed file policy"):
                        provision.read_audited_source_file(descriptor, path)
            finally:
                os.close(descriptor)
            self.assertEqual(canary.read_bytes(), b"must remain outside the source audit")

    def test_source_audit_keeps_the_retained_root_after_pathname_replacement(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            package, upstream, host = base / "package", base / "upstream", base / "host"
            for root, payload in ((package, b"reviewed original"), (upstream, b"reviewed original"),
                                  (host, b"host canary must not be read")):
                for relative in self.contract["relevantFiles"]:
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(payload)
            original_read = provision.read_audited_source_file
            replaced = False
            def replace_then_read(descriptor, relative):
                nonlocal replaced
                if not replaced:
                    package.rename(base / "retained-package")
                    package.symlink_to(host, target_is_directory=True)
                    replaced = True
                return original_read(descriptor, relative)
            output = base / "audit.json"
            with mock.patch.object(provision, "inventory_patch_files", return_value=[]), \
                    mock.patch.object(provision, "read_audited_source_file", side_effect=replace_then_read):
                audit = provision.audit_patches(package, upstream, output, self.contract)
            self.assertEqual(audit["status"], "compatible")
            self.assertEqual(audit["relevantFileCount"], 34)
            self.assertTrue(all(row["packagedSha256"] == provision.sha256(b"reviewed original")
                                for row in audit["relevantFiles"]))

    def prepare_runtime_rootfs(self, record, rootfs):
        rootfs.mkdir(parents=True, exist_ok=True)
        compiler = next(tool for tool in record["tools"] if tool["role"] == "cxx-driver")
        original_compiler_sha = compiler["sha256"]
        for row in record["runtime"]["entries"]:
            if row["kind"] != "regular-file":
                continue
            payload = (b"synthetic compiler/runtime bytes" if row["sha256"] == original_compiler_sha
                       else ("synthetic runtime bytes: " + row["path"]).encode())
            path = rootfs / row["path"].lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            if row["sha256"] == original_compiler_sha:
                compiler["bytes"] = len(payload)
                compiler["sha256"] = provision.sha256(payload)
        for row in record["runtime"]["entries"]:
            if row["kind"] != "symlink":
                continue
            path = rootfs / row["path"].lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(row["target"])
        record["runtime"] = provision.manifest([
            provision.runtime_file_entry(rootfs, row["path"]) for row in record["runtime"]["entries"]
        ])

    def probe_inventory(self, record):
        probe = record["probe"]
        return {
            "inventoryEvidence": probe["inventoryEvidence"],
            "generatedFields": probe["generatedFields"],
            "familyCounts": probe["familyCounts"],
            "manualFields": probe["manualFields"],
            "manualFieldsCount": len(probe["manualFields"]),
            "generatedFieldNames": probe["generatedFieldNames"],
            "definitionSha256": probe["definitionSha256"],
            "headerSha256": probe["headerSha256"],
        }

    def prepare_probe_rootfs(self, record, rootfs, binary=b"synthetic inert probe executable\n", mode=0o755):
        probe_path = rootfs.joinpath(*Path(provision.PROBE_BINARY_IN_ROOT).parts[1:])
        fixture_path = rootfs.joinpath(*Path(provision.PROBE_FIXTURE_IN_ROOT).parts[1:])
        source_path = rootfs.joinpath(*Path(provision.PROBE_SOURCE_IN_ROOT).parts[1:])
        header_dir = rootfs / "usr/lib/llvm-18/include/clang/Basic"
        rootfs.mkdir(parents=True, exist_ok=True)
        (rootfs / "tmp").mkdir(exist_ok=True)
        header_dir.mkdir(parents=True, exist_ok=True)
        def local_install(command, timeout=None):
            if command[:1] == ["sudo"]:
                command = command[1:]
            return subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, timeout=timeout)

        with mock.patch.object(provision, "run_checked", side_effect=local_install):
            staged_source, staged_fixture = provision.stage_probe_inputs(rootfs)
        self.assertEqual(staged_source, source_path)
        self.assertEqual(staged_fixture, fixture_path)
        probe_path.write_bytes(binary)
        probe_path.chmod(mode)
        fixture = ROOT / self.contract["negativeControl"]["fixture"]
        fixture_bytes = fixture.read_bytes()
        for name in ("LangOptions.def", "LangOptions.h"):
            shutil.copyfile(ROOT / "oracle/clang/18.1.3/fixtures" / f"llvmorg-18.1.3-{name}",
                            header_dir / name)
        record["probe"]["binarySha256"] = provision.sha256(binary)
        expected_source_sha256 = provision.recipe_identity()["probeSha256"]
        record["probe"]["sourceSha256"] = provision.verify_staged_probe_source(rootfs, expected_source_sha256)
        record["probe"]["fixtureSha256"] = provision.sha256(fixture_bytes)
        self.assertEqual(provision.sha256_file(source_path), record["probe"]["sourceSha256"])
        return probe_path, fixture_path, mode

    def local_rootfs_command(self, command, timeout=None):
        if command[:2] == ["sudo", "-n"]:
            command = command[2:]
        elif command[:1] == ["sudo"]:
            command = command[1:]
        return subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, timeout=timeout)

    def valid_loader_report(self, record, record_sha, rootfs):
        provision.verified_frontend_runtime_library_digests(rootfs, record)
        projection = provision.frontend_profile_projection_preimage(record, record_sha)
        return {
            "scope": "infrastructure-loader-smoke-only",
            "buildRecordSha256": record_sha,
            "imageDigest": record["image"]["imageDigest"],
            "resourceDirectory": "toolchain" + record["resourceDirectory"],
            "resourceFileCount": record["resources"]["entryCount"],
            "resourceTreeBytes": sum(row["bytes"] for row in record["resources"]["entries"]),
            "resourceManifestSha256": provision.frontend_resource_manifest_sha256(
                record["resourceDirectory"], record["resources"]),
            "infrastructureProfileProjectionSha256": provision.frontend_profile_projection_sha256(projection),
            "infrastructureProfileProjection": projection,
            "pathTransformSha256": provision.frontend_path_transform_sha256(record),
            "cxxDriverIdentitySha256": provision.frontend_cxx_driver_identity_sha256(record, record_sha),
            **{field: True for field in (
                "rejectedWrongImage", "rejectedWrongCxxDriverBytes", "rejectedChangedResourceIdentity",
                "rejectedChangedRuntimeLibraryIdentity", "rejectedMissingResourceDirectory")},
        }

    def prepare_loader_input_fixture(self, base, label):
        record = self.valid_build_record()
        rootfs = base / ("rootfs-" + label)
        self.prepare_runtime_rootfs(record, rootfs)
        compiler = next(tool for tool in record["tools"] if tool["role"] == "cxx-driver")
        compiler["path"] = compiler["resolvedPath"]
        compiler_path = rootfs / compiler["resolvedPath"].lstrip("/")
        compiler_path.parent.mkdir(parents=True)
        compiler_path.write_bytes(b"synthetic inert compiler bytes; never executed\n")
        compiler_path.chmod(int(compiler["mode"], 8))
        compiler["bytes"] = compiler_path.stat().st_size
        compiler["sha256"] = provision.sha256_file(compiler_path)
        resource = rootfs / record["resourceDirectory"].lstrip("/") / "include/fixture.h"
        resource.parent.mkdir(parents=True)
        resource.write_bytes(b"synthetic resource header; no compiler execution\n")
        record["resources"] = provision.resource_manifest(rootfs, record["resourceDirectory"])
        record_path = base / ("record-" + label + ".json")
        record_path.write_bytes(provision.canonical_json(record))
        output = base / ("report-" + label + ".json")
        args = provision.argparse.Namespace(contract=provision.CONTRACT_PATH, record=record_path,
                                           rootfs=rootfs, output=output)
        self.assertEqual(provision.command_write_loader_input(args), 0)
        return record, rootfs, record_path, output, output.with_suffix(".properties")

    def test_loader_input_preserves_literal_utf8_rootfs_and_report_paths(self):
        with self.temporary_directory() as temp:
            record, rootfs, _, output, properties = self.prepare_loader_input_fixture(Path(temp), "한글-é")
            encoded = properties.read_bytes()
            self.assertIn(("rootfs=" + str(rootfs.resolve()) + "\n").encode("utf-8"), encoded)
            self.assertIn(("smokeOutput=" + str(output) + "\n").encode("utf-8"), encoded)
            self.assertIn("한글-é".encode("utf-8"), encoded)
            self.assertNotIn(b"\\u", encoded)
            self.assertFalse(output.exists())
            self.assertEqual(record["resources"],
                             provision.resource_manifest(rootfs, record["resourceDirectory"]))

    def test_loader_input_java_reader_roundtrips_escaped_linux_paths(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            java_source = base / "PropertiesRoundTrip.java"
            java_source.write_text(textwrap.dedent("""
                import java.io.InputStreamReader;
                import java.nio.charset.CodingErrorAction;
                import java.nio.charset.StandardCharsets;
                import java.nio.file.Files;
                import java.nio.file.Path;
                import java.util.Base64;
                import java.util.Properties;
                class PropertiesRoundTrip {
                  public static void main(String[] args) throws Exception {
                    Properties input = new Properties();
                    try (var stream = Files.newInputStream(Path.of(args[0]));
                         var reader = new InputStreamReader(stream, StandardCharsets.UTF_8.newDecoder()
                           .onMalformedInput(CodingErrorAction.REPORT)
                           .onUnmappableCharacter(CodingErrorAction.REPORT))) {
                      input.load(reader);
                    }
                    for (String key : new String[]{"rootfs", "smokeOutput"}) {
                      System.out.println(Base64.getEncoder().encodeToString(
                        input.getProperty(key).getBytes(StandardCharsets.UTF_8)));
                    }
                  }
                }
            """), encoding="utf-8")
            labels = (r"back\bar", r"literal\u1234\t\n\r\f\end",
                      " spaces=colon:#!\t\f한글-é")
            for label in labels:
                with self.subTest(label=label):
                    _, rootfs, _, output, properties = self.prepare_loader_input_fixture(base, label)
                    result = subprocess.run([
                        "java", "-XX:-UsePerfData", "-XX:-CreateCoredumpOnCrash",
                        "-Djava.io.tmpdir=" + str(base), "-Duser.home=" + str(base),
                        "-XX:ErrorFile=" + str(base / "jvm-error-%p.log"),
                        str(java_source), str(properties),
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
                    loaded = [base64.b64decode(line).decode("utf-8") for line in result.stdout.splitlines()]
                    self.assertEqual(loaded, [str(rootfs.resolve()), str(output)])
                    self.assertFalse(output.exists())

    def test_loader_input_still_rejects_line_breaks_before_properties_write(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            _, rootfs, record_path, _, _ = self.prepare_loader_input_fixture(base, "ordinary")
            for delimiter in ("\n", "\r"):
                output = base / ("report" + delimiter + "injected=value.json")
                args = provision.argparse.Namespace(contract=provision.CONTRACT_PATH,
                    record=record_path, rootfs=rootfs, output=output)
                with self.subTest(delimiter=delimiter), mock.patch.object(provision, "atomic_write") as write:
                    with self.assertRaisesRegex(provision.ProvisionError, "contains a line break"):
                        provision.command_write_loader_input(args)
                    write.assert_not_called()
                self.assertFalse(output.with_suffix(".properties").exists())

    def test_compare_runs_rejects_canonical_and_physical_aliases_before_validation(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            first = base / "first.json"
            payload = provision.canonical_json(self.valid_build_record())
            first.write_bytes(payload)
            link = base / "symlink.json"
            link.symlink_to(first)
            hardlink = base / "hardlink.json"
            os.link(first, hardlink)
            intermediate = base / "intermediate"
            intermediate.mkdir()
            aliases = (first, link, hardlink, intermediate / "../first.json",
                       Path(os.path.relpath(first, Path.cwd())))
            for index, second in enumerate(aliases):
                output = base / ("result-" + str(index) + ".json")
                with self.subTest(second=second), mock.patch.object(provision, "validate_build_record",
                        side_effect=provision.ProvisionError("fixture reached validation")) as validate:
                    with self.assertRaisesRegex(provision.ProvisionError, "distinct.*record"):
                        provision.compare_build_runs(first, second, output, self.contract)
                    validate.assert_not_called()
                self.assertFalse(output.exists())
                self.assertEqual(first.read_bytes(), payload)

    def test_compare_runs_accepts_distinct_regular_files_with_equal_fixture_records(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            first, second, output = base / "first.json", base / "second.json", base / "result.json"
            payload = provision.canonical_json(self.valid_build_record())
            first.write_bytes(payload)
            second.write_bytes(payload)
            self.assertFalse(first.samefile(second))
            record = provision.compare_build_runs(first, second, output, self.contract)
            self.assertEqual(record["reproducibility"], {
                "cleanBuilds": 2, "matchingRootfsSha256": True, "matchingImageDigest": True,
            })
            self.assertEqual(output.read_bytes(), provision.canonical_json(record))

    def test_compare_runs_checks_opened_file_identity_after_path_replacement(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            first, second, output = base / "first.json", base / "second.json", base / "result.json"
            payload = provision.canonical_json(self.valid_build_record())
            first.write_bytes(payload)
            second.write_bytes(payload)
            original_open = os.open

            def replace_second(path, flags, *args, **kwargs):
                if Path(path) == second:
                    second.unlink()
                    os.link(first, second)
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(provision.os, "open", side_effect=replace_second), \
                    mock.patch.object(provision, "validate_build_record") as validate:
                with self.assertRaisesRegex(provision.ProvisionError, "distinct regular record files"):
                    provision.compare_build_runs(first, second, output, self.contract)
                validate.assert_not_called()
            self.assertTrue(first.samefile(second))
            self.assertFalse(output.exists())

    def test_json_parser_rejects_nested_equal_and_escaped_duplicate_members(self):
        valid = {"left": {"digest": "a"}, "right": {"digest": "b"}, "array": [{"n": 1}, {"n": 2}]}
        self.assertEqual(provision.strict_json_loads(provision.canonical_json(valid)), valid)
        payloads = (
            '{"image":{},"image":{}}',
            '{"array":[{"digest":"a","digest":"b"}]}',
            r'{"image":{},"im\u0061ge":{}}',
            r'{"nested":{"é":1,"\u00e9":2}}',
        )
        for payload in payloads:
            for data in (payload, payload.encode("utf-8")):
                with self.subTest(payload=payload, binary=isinstance(data, bytes)), \
                        self.assertRaisesRegex(provision.ProvisionError, "duplicate object member"):
                    provision.strict_json_loads(data)

    def test_record_commands_reject_duplicate_members_before_validation_or_output(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            record = self.valid_build_record()
            canonical = provision.canonical_json(record)
            variants = (b'{"image":{},' + canonical[1:],
                        canonical.replace(b'"recipe":{', b'"recipe":{"contractSha256":"untrusted",', 1))
            path, output = base / "record.json", base / "output.json"
            args = provision.argparse.Namespace(contract=provision.CONTRACT_PATH, record=path,
                                               output=output, rootfs_tar=None)
            for payload in variants:
                self.assertEqual(json.loads(payload), record)  # legacy last-wins interpretation remains valid
                path.write_bytes(payload)
                for command in (provision.command_verify_record, provision.command_write_loader_input,
                                provision.command_verify_image, provision._package_provenance_unqualified):
                    with self.subTest(command=command.__name__, payload=payload[:80]), \
                            mock.patch.object(provision, "validate_build_record",
                                side_effect=provision.ProvisionError("fixture reached validation")) as validate:
                        with self.assertRaisesRegex(provision.ProvisionError, "duplicate object member"):
                            command(args)
                        validate.assert_not_called()
                    self.assertFalse(output.exists())

    def test_provenance_report_rejects_top_level_and_nested_duplicate_members(self):
        with self.temporary_directory() as temp:
            path = Path(temp) / "report.json"
            for payload in (b'{"scope":"first","scope":"last"}',
                            b'{"scope":"fixture","payload":[{"sha256":"a","sha256":"a"}]}'):
                path.write_bytes(payload)
                with self.subTest(payload=payload), self.assertRaisesRegex(
                        provision.ProvisionError, "duplicate object member"):
                    provision.read_provenance_report(path, "fixture")
            path.write_bytes(b'{"scope":"fixture","payload":[{"sha256":"a"}]}')
            self.assertEqual(provision.read_provenance_report(path, "fixture"),
                             {"scope": "fixture", "payload": [{"sha256": "a"}]})

    def test_compare_runs_rejects_duplicate_members_in_either_distinct_input(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            first, second, output = base / "first.json", base / "second.json", base / "result.json"
            canonical = provision.canonical_json(self.valid_build_record())
            duplicated = b'{"image":{},' + canonical[1:]
            for selected in (first, second):
                first.write_bytes(duplicated if selected == first else canonical)
                second.write_bytes(duplicated if selected == second else canonical)
                with self.subTest(input=selected), mock.patch.object(provision, "validate_build_record",
                        side_effect=provision.ProvisionError("fixture reached validation")) as validate:
                    with self.assertRaisesRegex(provision.ProvisionError, "duplicate object member"):
                        provision.compare_build_runs(first, second, output, self.contract)
                    validate.assert_not_called()
                self.assertFalse(output.exists())

    def test_retained_probe_rejects_duplicate_output_before_inventory_validation(self):
        with self.temporary_directory() as temp:
            record = self.valid_build_record()
            rootfs = Path(temp) / "rootfs"
            self.prepare_probe_rootfs(record, rootfs)
            replay = {key: value for key, value in record["probe"].items()
                      if key not in ("sourceSha256", "binarySha256", "fixtureSha256")}
            output = b'{"compilerVersion":"22.1.6",' + provision.canonical_json(replay)[1:]
            self.assertEqual(json.loads(output), replay)
            with mock.patch.object(provision, "run_probe_sandboxed", return_value=output.decode("utf-8")), \
                    mock.patch.object(provision, "audit_langoptions",
                        side_effect=provision.ProvisionError("fixture reached inventory")) as audit:
                with self.assertRaisesRegex(provision.ProvisionError, "duplicate object member"):
                    provision.validate_provenance_probe_report(dict(record["probe"]), record, rootfs, self.contract)
                audit.assert_not_called()

    def test_selected_contract_rejects_duplicate_profile_before_using_pins(self):
        with self.temporary_directory() as temp:
            path = Path(temp) / "contract.json"
            canonical = provision.canonical_json(self.contract)
            payload = b'{"profile":{},' + canonical[1:]
            self.assertEqual(json.loads(payload), self.contract)
            path.write_bytes(payload)
            with self.assertRaisesRegex(provision.ProvisionError, "duplicate object member"):
                provision.read_contract(path)

    def test_workflow_actions_are_pinned_to_immutable_commit_shas(self):
        workflow = (ROOT / ".github/workflows/generic-template-toolchain.yml").read_text(encoding="utf-8")
        actions = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, flags=re.MULTILINE)
        self.assertTrue(actions)
        self.assertTrue(all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", action) for action in actions), actions)
        self.assertIn("Production snapshot metadata diagnostic", workflow)
        self.assertIn("--snapshot 20240702T000000Z", workflow)
        self.assertIn("if: ${{ github.event_name == 'workflow_dispatch' && inputs.mode == 'snapshot-metadata-diagnostic' }}", workflow)
        qualify_job = re.search(r"(?ms)^  qualify:\n(.*?)(?=^  [A-Za-z0-9_-]+:|\Z)", workflow)
        self.assertIsNotNone(qualify_job)
        qualify_text = qualify_job.group(1)
        self.assertIn("needs: offline-validation", qualify_text)
        self.assertIn("if: ${{ needs.offline-validation.result == 'success' && "
                      "needs.offline-validation.outputs.acquisition_enabled == 'true' && "
                      "(github.event_name != 'workflow_dispatch' || inputs.mode == 'full-qualification') }}",
                      qualify_text)
        trigger_text = workflow[:workflow.index("permissions:")]
        for dependency in (
                "oracle/llvm/22.1.6/release-artifacts.json",
                "oracle/llvm/22.1.6/oracle-manifest.json",
                "oracle/llvm/22.1.6/keys/douglas-yung-llvm-release.asc"):
            self.assertEqual(trigger_text.count(f"'{dependency}'"), 2)
        self.assertLess(qualify_text.index("Authenticate Ubuntu Snapshot source and patch compatibility first"),
                        qualify_text.index('bash scripts/install-frontend-node.sh'))
        self.assertEqual(qualify_text.count('-PfrontendNodeHome="$CLANG_WORK/frontend-node"'),
                         qualify_text.count('./gradlew'))
        self.assertLess(qualify_text.index('bash scripts/install-frontend-node.sh'), qualify_text.index('./gradlew'))
        self.assertIn('--rootfs "$CLANG_WORK/rootfs-run2"', qualify_text)
        self.assertLess(qualify_text.index("package-provenance"),
                        qualify_text.index('sudo rm -rf "$CLANG_WORK/rootfs-run2"'))
        self.assertIn('--oci-archive "$CLANG_WORK/run2/clang-18.1.3-noble-amd64.oci.tar"',
                      qualify_text)
        self.assertLess(qualify_text.index("package-provenance"),
                        qualify_text.index('rm "$CLANG_WORK/run2/clang-18.1.3-noble-amd64.oci.tar"'))

    def test_workflow_offline_job_gates_native_setup_without_suppressing_failures(self):
        workflow = (ROOT / ".github/workflows/generic-template-toolchain.yml").read_text(encoding="utf-8")
        offline = re.search(r"(?ms)^  offline-validation:\n(.*?)(?=^  [A-Za-z0-9_-]+:|\Z)", workflow).group(1)
        self.assertIn("acquisition_enabled: ${{ steps.acquisition_status.outputs.acquisition_enabled }}", offline)
        self.assertIn('"acquisition-status"', offline)
        self.assertIn("run: python3 -m unittest discover -s oracle/clang/18.1.3 -p 'test_*.py' -v", offline)
        self.assertNotIn("continue-on-error", workflow)
        self.assertNotIn("if:", offline)
        for costly_setup in ("setup-java", "setup-gradle", "apt-get", "./gradlew", "install-frontend-node"):
            self.assertNotIn(costly_setup, offline)
        self.assertNotIn(" || ", offline)
        self.assertNotIn("always()", offline)

    def test_workflow_status_report_accepts_prerequisite_fixtures_without_claiming_qualification(self):
        workflow = (ROOT / ".github/workflows/generic-template-toolchain.yml").read_text(encoding="utf-8")
        offline = re.search(r"(?ms)^  offline-validation:\n(.*?)(?=^  [A-Za-z0-9_-]+:|\Z)", workflow).group(1)
        source = textwrap.dedent(re.search(r"python3 - <<'PY'\n(.*?)          PY\n", offline, re.DOTALL).group(1))
        for enabled in (False, True):
            # The enabled branch is only a mocked status fixture, never acquisition permission.
            with mock.patch.object(provision, "UPSTREAM_SIGNATURE_ACCESS_ENABLED", enabled):
                status = provision.acquisition_status()
            with self.subTest(enabled=enabled), self.temporary_directory() as temp:
                output, summary = Path(temp) / "outputs", Path(temp) / "summary"
                with mock.patch.dict(provision.os.environ, {"GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary)}), \
                        mock.patch.object(provision.subprocess, "run", return_value=mock.Mock(stdout=json.dumps(status))) as run, \
                        mock.patch.object(provision.sys, "stdout", io.StringIO()):
                    exec(compile(source, "<workflow-acquisition-status>", "exec"), {})
                self.assertEqual(output.read_text(), f"acquisition_enabled={str(enabled).lower()}\n")
                self.assertIn("**INCOMPLETE**", summary.read_text())
                self.assertIn("**NOT-RUN**" if enabled else "**SKIPPED**", summary.read_text())
                self.assertIn(status["reason"], summary.read_text())
                self.assertEqual(run.call_args.args[0][-1], "acquisition-status")
                self.assertTrue(run.call_args.kwargs["check"])
        for changes in ({"acquisitionEnabled": "true"}, {"qualified": True},
                        {"acceptanceStatus": "accepted"}, {"nativeQualification": "passed"}):
            status = {**provision.acquisition_status(), **changes}
            with self.subTest(changes=changes), mock.patch.object(
                provision.subprocess, "run", return_value=mock.Mock(stdout=json.dumps(status))
            ), self.assertRaises(SystemExit):
                exec(compile(source, "<workflow-acquisition-status>", "exec"), {})

    def test_rootfs_command_uses_the_selected_contract_environment(self):
        contract = {"environment": {"LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "7",
                                     "PATH": "/custom/bin"}}
        completed = type("Result", (), {"stdout": "ok"})()
        with mock.patch.object(provision, "run_checked", return_value=completed) as run:
            self.assertEqual(provision.rootfs_run(Path("/rootfs"), ["/usr/bin/env"], contract), "ok")
        command = run.call_args.args[0]
        self.assertIn("PATH=/custom/bin", command)
        self.assertIn("SOURCE_DATE_EPOCH=7", command)

    def test_debootstrap_command_records_the_selected_keyring(self):
        keyring = Path("workspace-keys/selected archive-keyring.gpg")
        executed = provision.debootstrap_command(self.contract, "/workspace/profile-root", keyring)
        recorded = provision.debootstrap_command(self.contract, "<PROFILE_ROOT>", keyring)
        self.assertIn("--keyring=workspace-keys/selected archive-keyring.gpg", executed)
        self.assertEqual(recorded, ["<PROFILE_ROOT>" if value == "/workspace/profile-root" else value
                                    for value in executed])
        self.assertIn("--include=ca-certificates", executed)

    def test_selected_archive_keyring_is_installed_and_bound_to_https_sources(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs = base / "rootfs"
            keyring = base / "selected archive-keyring.gpg"
            payload = b"synthetic selected Ubuntu archive keyring bytes"
            keyring.write_bytes(payload)
            (rootfs / "usr/share/keyrings").mkdir(parents=True)

            def install(command, timeout=None):
                shutil.copyfile(command[-2], command[-1])
                Path(command[-1]).chmod(0o644)
                return mock.Mock(stdout="")

            with mock.patch.object(provision, "run_checked", side_effect=install) as run:
                installed = provision.install_selected_archive_keyring(rootfs, keyring, provision.sha256(payload))
            self.assertEqual(installed.read_bytes(), payload)
            self.assertEqual(installed.stat().st_mode & 0o777, 0o644)
            self.assertEqual(run.call_args.args[0], [
                "sudo", "install", "-m", "0644", str(keyring), str(installed),
            ])
            with mock.patch.object(provision, "run_checked") as run:
                with self.assertRaisesRegex(provision.ProvisionError, "selected Ubuntu archive keyring bytes"):
                    provision.install_selected_archive_keyring(rootfs, keyring, "f" * 64)
                run.assert_not_called()

        sources = provision.apt_source_list(self.contract).decode("utf-8")
        self.assertIn(f"signed-by={provision.APT_KEYRING_IN_ROOT}", sources)
        self.assertNotIn("signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg", sources)
        digest = "a" * 64
        commands = provision.canonical_commands(self.contract, digest)
        self.assertEqual(commands["installAptKeyring"], [
            "sudo", "install", "-m", "0644", f"<UBUNTU_ARCHIVE_KEYRING_SHA256:{digest}>",
            f"<PROFILE_ROOT>{provision.APT_KEYRING_IN_ROOT}",
        ])
        self.assertEqual(commands["writeAptSources"][4],
                         f"<SOURCE_LIST_SHA256:{provision.sha256(provision.apt_source_list(self.contract))}>")

    def test_selected_archive_keyring_install_precedes_first_apt_command(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            keyring = base / "selected.gpg"
            keyring.write_bytes(b"selected bytes")
            rootfs = base / "rootfs"
            events = []

            def bootstrap(command, timeout=None):
                rootfs.mkdir(parents=True, exist_ok=True)
                (rootfs / "usr/share/keyrings").mkdir(parents=True)
                (rootfs / "etc/apt").mkdir(parents=True)
                (rootfs / "etc/ssl/certs").mkdir(parents=True)
                (rootfs / "etc/ssl/certs/ca-certificates.crt").write_bytes(b"synthetic CA bundle")
                return mock.Mock(stdout="")

            def run_checked(command, timeout=None):
                if provision.ROOTFS_DIRECTORY_CREATE_PROGRAM in command:
                    return self.simulate_privileged_rootfs_helper(command)
                if provision.ROOTFS_PARENT_RESTORE_PROGRAM in command:
                    return self.simulate_privileged_rootfs_helper(command)
                if "debootstrap" in command:
                    return bootstrap(command, timeout)
                if command[1:4] == ["install", "-m", "0644"]:
                    source, destination = Path(command[-2]), Path(command[-1])
                    shutil.copyfile(source, destination)
                    destination.chmod(0o644)
                    events.append("selected-keyring" if destination.name == Path(provision.APT_KEYRING_IN_ROOT).name
                                  else "source-list")
                    return mock.Mock(stdout="")
                raise AssertionError(command)

            def rootfs_run(root, command, contract, **kwargs):
                events.append("apt-update")
                raise provision.ProvisionError("stop before package fetch")

            args = provision.argparse.Namespace(
                contract=provision.CONTRACT_PATH, workdir=base, rootfs=rootfs,
                output=base / "output", acquisition=base / "acquisition", keyring=keyring, label="fixture",
            )
            candidate = {"trustedKeyring": {"sha256": provision.sha256_file(keyring)}}
            packages = {("ca-certificates", "synthetic", "all")}
            args.acquisition.mkdir()
            with mock.patch.object(provision, "load_candidate", return_value=(candidate, [])), \
                    mock.patch.object(provision, "check_runner_bounds"), \
                    mock.patch.object(provision, "run_checked", side_effect=run_checked), \
                    mock.patch.object(provision, "installed_package_keys", return_value=packages), \
                    mock.patch.object(provision, "rootfs_run", side_effect=rootfs_run), \
                    mock.patch.object(provision.BoundedDownloader, "get") as network:
                with self.assertRaisesRegex(provision.ProvisionError, "stop before package fetch"):
                    provision._provision_rootfs_unqualified(args)
            self.assertEqual(events, ["selected-keyring", "source-list", "apt-update"])
            self.assertEqual((rootfs / Path(provision.APT_KEYRING_IN_ROOT).relative_to("/")).read_bytes(),
                             keyring.read_bytes())
            self.assertIn(f"signed-by={provision.APT_KEYRING_IN_ROOT}",
                          (rootfs / "etc/apt/sources.list").read_text(encoding="utf-8"))
            network.assert_not_called()

    def test_build_record_commands_reject_changed_omitted_inserted_and_reordered_arguments(self):
        baseline = self.valid_build_record()
        provision.validate_build_record(baseline, self.contract)
        for name, argv in baseline["commands"].items():
            mutations = {
                "changed": ["unreviewed-command", *argv[1:]],
                "omitted": argv[:-1],
                "inserted": [*argv, "--unreviewed-argument"],
                "reordered": [argv[1], argv[0], *argv[2:]],
            }
            for mutation, replacement in mutations.items():
                record = self.valid_build_record()
                record["commands"][name] = replacement
                with self.subTest(command=name, mutation=mutation), self.assertRaisesRegex(
                    provision.ProvisionError, "canonical recipe"
                ):
                    provision.validate_build_record(record, self.contract)
        for mutation in ("missing", "extra"):
            record = self.valid_build_record()
            if mutation == "missing":
                record["commands"].pop("aptCheck")
            else:
                record["commands"]["extra"] = ["unreviewed"]
            with self.subTest(mutation=mutation), self.assertRaisesRegex(provision.ProvisionError, r"canonical recipe|checked-in schema.*commands"):
                provision.validate_build_record(record, self.contract)

    def test_finite_schema_matches_json_numeric_and_conditional_corpus(self):
        for label, rule, instance, expected in finite_schema_corpus():
            with self.subTest(label=label):
                if expected:
                    provision.validate_finite_build_record_schema(instance, rule)
                else:
                    with self.assertRaisesRegex(provision.ProvisionError, "checked-in schema"):
                        provision.validate_finite_build_record_schema(instance, rule)

    def test_finite_schema_meta_validates_unselected_branches_and_reference_bounds(self):
        unsupported = [
            {"if": {"const": 1}, "then": {}, "else": {"unreviewed": True}},
            {"$defs": {"unused": {"unreviewed": True}}},
            {"$ref": "https://untrusted.invalid/schema.json"},
            {"$ref": "#/$defs/missing"},
            {"$defs": {"cycle": {"$ref": "#/$defs/cycle"}}},
            {"type": ["integer", "integer"]}, {"required": ["a", "a"]},
            {"items": []}, {"uniqueItems": 1}, {"minimum": True},
            {"pattern": "^(a+)+$"}, {"allOf": []},
            {"$schema": "http://json-schema.org/draft-07/schema#"},
        ]
        for rule in unsupported:
            with self.subTest(rule=rule), mock.patch.object(provision.BoundedDownloader, "get") as network:
                with self.assertRaisesRegex(provision.ProvisionError, "checked-in.*schema"):
                    provision.validate_finite_build_record_schema(1, rule)
                network.assert_not_called()
        nested = None
        for _ in range(provision.SCHEMA_MAX_DEPTH + 1):
            nested = [nested]
        with self.assertRaisesRegex(provision.ProvisionError, "depth/node budget"):
            provision.validate_finite_build_record_schema(nested, {})
        with mock.patch.object(provision, "SCHEMA_MAX_NODES", 8):
            with self.assertRaisesRegex(provision.ProvisionError, "depth/node budget"):
                provision.validate_finite_build_record_schema(list(range(20)), {})

    def test_selected_contract_cannot_override_fixed_schema_constants(self):
        for mutation in ("locale", "snapshot"):
            with self.subTest(mutation=mutation), self.temporary_directory() as temp:
                contract = json.loads(json.dumps(self.contract))
                record = self.valid_build_record()
                if mutation == "locale":
                    contract["environment"]["LC_ALL"] = "C.UTF-8"
                    record["environment"] = contract["environment"]
                else:
                    contract["profile"]["snapshot"] = "20240703T000000Z"
                    record["profile"]["snapshot"] = contract["profile"]["snapshot"]
                    contract["profile"]["snapshotBase"] = f"https://snapshot.ubuntu.com/ubuntu/{contract['profile']['snapshot']}/"
                    record["profile"]["snapshotBase"] = contract["profile"]["snapshotBase"]
                selected = Path(temp) / "contract.json"
                selected.write_bytes(provision.canonical_json(contract))
                record["recipe"] = provision.recipe_identity(selected)
                record["commands"] = provision.canonical_commands(contract, record["acquisition"]["ubuntuKeyring"]["sha256"])
                with self.assertRaisesRegex(provision.ProvisionError, "checked-in schema.*const mismatch"):
                    provision.validate_build_record(record, contract, selected)

    def test_full_schema_rejects_record_types_bounds_patterns_and_conditional_targets(self):
        mutations = [
            lambda r: r.pop("reproducibility"),
            lambda r: r.update(packages="not an array"),
            lambda r: r["acquisition"].update(repositories=[]),
            lambda r: r["source"]["files"][0].update(name=""),
            lambda r: r["environment"].update(SOURCE_DATE_EPOCH="-1"),
            lambda r: r["probe"]["generatedFieldNames"].__setitem__(0, "9bad"),
            lambda r: r["runtime"]["entries"][0].update(target="non-null regular file target"),
            lambda r: r["runtime"]["entries"][0].update(kind="symlink", target=None),
        ]
        for index, mutate in enumerate(mutations):
            record = json.loads(json.dumps(self.valid_build_record()))
            mutate(record)
            with self.subTest(index=index), self.assertRaisesRegex(provision.ProvisionError, "checked-in schema"):
                provision.validate_build_record(record, self.contract)

    def test_compare_runs_alone_accepts_provisional_fragments_without_reproducibility(self):
        record = self.valid_build_record()
        record.pop("reproducibility")
        with self.assertRaisesRegex(provision.ProvisionError, "required field missing"):
            provision.validate_build_record(record, self.contract)
        with self.temporary_directory() as temp:
            base = Path(temp)
            first, second = base / "first.json", base / "second.json"
            first.write_bytes(provision.canonical_json(record))
            second.write_bytes(provision.canonical_json(record))
            result = provision.compare_build_runs(first, second, base / "final.json", self.contract)
            provision.validate_build_record(result, self.contract)

    def test_network_identity_normalization_is_deterministic_and_replaces_leaf_links(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            canary = base / "resolver-canary"
            canary.write_bytes(b"outside resolver must remain untouched")
            archive_hashes = []
            for index in range(2):
                rootfs = base / str(index)
                etc = rootfs / "etc"
                etc.mkdir(parents=True)
                (etc / "machine-id").write_bytes(b"")
                (etc / "hostname").write_bytes(f"host-specific-{index}".encode())
                if index == 0:
                    (etc / "resolv.conf").write_bytes(b"nameserver 192.0.2.1\n")
                else:
                    (etc / "resolv.conf").symlink_to(canary)
                with mock.patch.object(provision, "run_checked", side_effect=self.local_rootfs_command), \
                        mock.patch.object(provision, "normalize_network_identity_files", side_effect=self.local_network_normalization_fixture):
                    provision.normalize_rootfs(rootfs, 7)
                self.assertEqual((etc / "hostname").read_bytes(), b"clang1813\n")
                self.assertEqual((etc / "resolv.conf").read_bytes(), b"")
                self.assertFalse((etc / "resolv.conf").is_symlink())
                for leaf in ("hostname", "resolv.conf"):
                    self.assertEqual(stat.S_IMODE((etc / leaf).stat().st_mode), 0o644)
                self.assertEqual(list(etc.glob(".clang1813-network-*")), [])
                archive = base / f"{index}.tar"
                subprocess.run(["tar", "--sort=name", "--format=posix", "--numeric-owner", "--mtime=@7",
                                "--pax-option=delete=atime,delete=ctime", "-cf", str(archive), "-C", str(rootfs), "."],
                               check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                archive_hashes.append(provision.sha256_file(archive))
            self.assertEqual(archive_hashes[0], archive_hashes[1])
            self.assertEqual(canary.read_bytes(), b"outside resolver must remain untouched")

    def test_network_identity_normalization_refuses_symlinked_etc_and_cleans_failed_temporaries(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs, canary = base / "rootfs", base / "canary"
            rootfs.mkdir()
            canary.mkdir()
            (canary / "hostname").write_bytes(b"host canary")
            (rootfs / "etc").symlink_to(canary, target_is_directory=True)
            with self.assertRaises(OSError):
                self.local_network_normalization_fixture(rootfs)
            self.assertEqual((canary / "hostname").read_bytes(), b"host canary")
            (rootfs / "etc").unlink()
            (rootfs / "etc").mkdir()
            with mock.patch.object(os, "replace", side_effect=OSError("injected replace failure")):
                with self.assertRaisesRegex(OSError, "replace failure"):
                    self.local_network_normalization_fixture(rootfs)
            self.assertEqual(list((rootfs / "etc").iterdir()), [])

    def test_build_record_rejects_schema_disallowed_top_level_and_nested_fields(self):
        mutations = (
            ("top-level", lambda record: record.update(acceptanceStatus="accepted"), False),
            ("profile", lambda record: record["profile"].update(unreviewed=True), True),
            ("package", lambda record: (record["packages"][0].update(unreviewed=True),
                                         record["downloadedPackages"][0].update(unreviewed=True)), False),
            ("runtime entry", lambda record: record["runtime"]["entries"][0].update(unreviewed=True), False),
            ("image", lambda record: record["image"].update(acceptanceStatus="accepted"), False),
            ("probe", lambda record: record["probe"]["macroObservations"].update(accepted=True), False),
        )
        for label, mutate, schema_only in mutations:
            record = self.valid_build_record()
            mutate(record)
            if label == "runtime entry" and not schema_only:
                record["runtime"].update(provision.manifest(record["runtime"]["entries"]))
            with self.subTest(location=label), self.assertRaisesRegex(
                provision.ProvisionError, r"checked-in schema.*unknown field",
            ):
                if schema_only:
                    provision.reject_build_record_schema_unknown_fields(record)
                else:
                    provision.validate_build_record(record, self.contract)

    def test_rootfs_archive_budget_fails_before_writing_when_walk_cannot_read_a_subtree(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs = base / "rootfs"
            rootfs.mkdir()
            archive = base / "rootfs.tar"

            with mock.patch.object(provision.os, "scandir",
                                   side_effect=PermissionError("unreadable retained rootfs subtree")):
                with self.assertRaisesRegex(provision.ProvisionError, "could not inspect retained rootfs"):
                    provision.check_rootfs_tar_budget(rootfs, 1024 * 1024)
            self.assertFalse(archive.exists())

    def test_privileged_budget_command_is_fixed_isolated_and_bound_to_the_record(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            rootfs.mkdir()
            budget = self.contract["profile"]["bounds"]["maxArtifactBytes"]
            expected = ["sudo", "-n", "/usr/bin/python3", "-I", "-B", "-c", provision.ROOTFS_TAR_BUDGET_PROGRAM,
                        "check-rootfs-tar-budget", "--rootfs", str(rootfs), "--max-bytes", str(budget)]
            self.assertEqual(provision.rootfs_tar_budget_command(rootfs, budget), expected)
            recorded = provision.canonical_commands(self.contract, "a" * 64)["rootfsTarBudget"]
            expected[9] = "<PROFILE_ROOT>"
            self.assertEqual(recorded, expected)
            for value in (0, -1, True, 1.0):
                with self.subTest(value=value), self.assertRaises(provision.ProvisionError):
                    provision.rootfs_tar_budget_command(rootfs, value)

    def test_privileged_budget_failure_and_timeout_precede_tar_and_archive_output(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            rootfs.mkdir()
            archive = Path(temp) / "rootfs.tar"
            errors = [provision.ProvisionError("could not inspect retained rootfs"),
                      subprocess.TimeoutExpired("read-only preflight", 120)]
            for error in errors:
                with self.subTest(error=type(error).__name__), \
                        mock.patch.object(provision, "run_checked", side_effect=error) as execute:
                    with self.assertRaises(type(error)):
                        provision.deterministic_rootfs_tar(rootfs, archive, 0, normalize=False, max_bytes=1024 * 1024)
                    execute.assert_called_once_with(provision.rootfs_tar_budget_command(rootfs, 1024 * 1024),
                                                    timeout=provision.ROOTFS_TAR_BUDGET_TIMEOUT_SECONDS)
                    self.assertFalse(archive.exists())

    def test_rootfs_budget_stops_scandir_incrementally_at_entry_limit(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            rootfs.mkdir()
            visited = []

            class Entry:
                def __init__(self, name):
                    self.name = name

                def stat(self, *, follow_symlinks):
                    self.assert_follow_symlinks = follow_symlinks
                    return os.stat_result((stat.S_IFREG | 0o644, 1, 0, 1, 0, 0, 1, 0, 0, 0))

            class IncrementalEntries:
                def __enter__(self):
                    return self

                def __exit__(self, *_):
                    return False

                def __iter__(self):
                    for index in range(1000000):
                        visited.append(index)
                        yield Entry(f"entry-{index}")

            with mock.patch.object(provision.os, "scandir", return_value=IncrementalEntries()):
                with self.assertRaisesRegex(provision.ProvisionError, "entry count exceeds"):
                    provision.check_rootfs_tar_budget(rootfs, 20 * 512)
            self.assertLessEqual(len(visited), 2)

    def test_empty_rootfs_tiny_budget_fails_preflight_before_traversal_and_tar_output(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            rootfs.mkdir()
            archive = Path(temp) / "rootfs.tar"
            for budget in (1, 8192, 20 * 512 - 1):
                expected = provision.rootfs_tar_budget_command(rootfs, budget)

                def inspect(command, *, timeout):
                    self.assertEqual(command, expected)
                    self.assertEqual(timeout, provision.ROOTFS_TAR_BUDGET_TIMEOUT_SECONDS)
                    return provision.command_check_rootfs_tar_budget(
                        provision.argparse.Namespace(rootfs=rootfs, max_bytes=budget))

                with self.subTest(budget=budget), mock.patch.object(provision.os, "walk") as walk, \
                        mock.patch.object(provision, "run_checked", side_effect=inspect) as execute:
                    with self.assertRaisesRegex(provision.ProvisionError, "minimum canonical tar record size"):
                        provision.deterministic_rootfs_tar(rootfs, archive, 0, normalize=False, max_bytes=budget)
                    execute.assert_called_once_with(expected, timeout=provision.ROOTFS_TAR_BUDGET_TIMEOUT_SECONDS)
                    walk.assert_not_called()
                    self.assertFalse(archive.exists())

    def test_budget_cli_is_read_only_and_rejects_relative_symlink_and_invalid_budget(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            rootfs.mkdir()
            link = Path(temp) / "rootfs-link"
            link.symlink_to(rootfs, target_is_directory=True)
            invalid = [(Path("relative/rootfs"), 1), (link, 1), (rootfs, 0), (rootfs, True)]
            for path, value in invalid:
                with self.subTest(path=path, value=value), mock.patch.object(provision, "check_rootfs_tar_budget") as inspect:
                    with self.assertRaises(provision.ProvisionError):
                        provision.command_check_rootfs_tar_budget(provision.argparse.Namespace(rootfs=path, max_bytes=value))
                    inspect.assert_not_called()
            with mock.patch.object(provision, "run_checked") as execute, \
                    mock.patch.object(provision.BoundedDownloader, "get") as network, \
                    mock.patch.object(provision, "atomic_write") as write, \
                    mock.patch.object(provision, "check_rootfs_tar_budget") as inspect:
                self.assertEqual(provision.main(["check-rootfs-tar-budget", "--rootfs", str(rootfs), "--max-bytes", "65536"]), 0)
                inspect.assert_called_once_with(rootfs, 65536)
                execute.assert_not_called()
                network.assert_not_called()
                write.assert_not_called()

    def test_rootfs_archive_preserves_numeric_package_ownership(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs = base / "rootfs"
            rootfs.mkdir()
            package_file = rootfs / "usr/bin/package-owned"
            package_file.parent.mkdir(parents=True)
            package_file.write_bytes(b"synthetic package file")
            expected_owner = package_file.stat()
            destination = base / "rootfs.tar"

            def local_tar(command, timeout=None, stdout_file=None):
                self.assertNotIn("--owner=0", command)
                self.assertNotIn("--group=0", command)
                subprocess.run(command[1:], check=True, stdout=stdout_file)
                return mock.Mock(stdout="")

            with mock.patch.object(provision, "normalize_rootfs"), \
                    mock.patch.object(provision, "run_checked", side_effect=local_tar) as run:
                provision.deterministic_rootfs_tar(rootfs, destination, 1714003200)
            command = run.call_args.args[0]
            self.assertIn("--numeric-owner", command)
            self.assertFalse(any(arg.startswith("--owner=") or arg.startswith("--group=") for arg in command))
            with tarfile.open(destination, "r:") as archive:
                member = archive.getmember("./usr/bin/package-owned")
                self.assertEqual((member.uid, member.gid), (expected_owner.st_uid, expected_owner.st_gid))

    def test_rootfs_tar_refuses_existing_file_symlink_and_fifo_without_truncation(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs = base / "rootfs"
            rootfs.mkdir()
            canary = base / "unrelated"
            canary.write_bytes(b"must remain unchanged")
            for kind in ("symlink", "regular", "fifo"):
                destination = base / (kind + ".tar")
                if kind == "symlink":
                    destination.symlink_to(canary)
                elif kind == "fifo":
                    os.mkfifo(destination)
                else:
                    destination.write_bytes(b"prior archive")
                with self.subTest(kind=kind), mock.patch.object(provision, "run_checked") as tar:
                    with self.assertRaisesRegex(provision.ProvisionError, "exclusively create"):
                        provision.deterministic_rootfs_tar(rootfs, destination, 0, normalize=False)
                    tar.assert_not_called()
                self.assertEqual(canary.read_bytes(), b"must remain unchanged")
                if kind == "regular":
                    self.assertEqual(destination.read_bytes(), b"prior archive")

    def test_rootfs_tar_uses_open_fd_when_destination_is_replaced_before_child_start(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs = base / "rootfs"
            rootfs.mkdir()
            (rootfs / "payload").write_bytes(b"inert archive member")
            destination = base / "rootfs.tar"
            canary = base / "unrelated"
            canary.write_bytes(b"must remain unchanged")
            owned = base / "owned.tar"

            def replace_and_tar(command, *, timeout, stdout_file):
                self.assertEqual(command[command.index("-cf") + 1], "-")
                self.assertNotIn(str(destination), command)
                self.assertEqual(os.fstat(stdout_file.fileno()).st_uid, os.geteuid())
                self.assertEqual(os.fstat(stdout_file.fileno()).st_mode & 0o777, 0o600)
                self.assertFalse(destination.exists())
                parent = os.open(base, os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC)
                try:
                    os.link("/proc/self/fd/" + str(stdout_file.fileno()), owned.name,
                            dst_dir_fd=parent, follow_symlinks=True)
                finally:
                    os.close(parent)
                destination.symlink_to(canary)
                return subprocess.run(command[1:], check=True, stdout=stdout_file,
                                      stderr=subprocess.PIPE, timeout=timeout)

            with mock.patch.object(provision, "run_checked", side_effect=replace_and_tar):
                with self.assertRaisesRegex(provision.ProvisionError, "exclusively publish"):
                    provision.deterministic_rootfs_tar(rootfs, destination, 0, normalize=False)
            self.assertEqual(canary.read_bytes(), b"must remain unchanged")
            self.assertTrue(destination.is_symlink())
            with tarfile.open(owned) as archive:
                self.assertEqual(archive.extractfile("./payload").read(), b"inert archive member")

    def test_rootfs_tar_failure_closes_private_inode_without_named_output(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs = base / "rootfs"
            rootfs.mkdir()
            for failure in (provision.ProvisionError("tar fixture failed"), subprocess.TimeoutExpired("tar", 600)):
                destination = base / "output.tar"
                with self.subTest(failure=type(failure).__name__), \
                        mock.patch.object(provision, "run_checked", side_effect=failure):
                    with self.assertRaises(type(failure)):
                        provision.deterministic_rootfs_tar(rootfs, destination, 0, normalize=False)
                self.assertFalse(destination.exists())
                self.assertEqual(sorted(path.name for path in base.iterdir()), ["rootfs"])

    def test_rootfs_tar_unsupported_tmpfile_fails_before_privileged_tar(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs = base / "rootfs"
            rootfs.mkdir()
            original_open = provision.os.open
            def unsupported(path, flags, *positional, **keywords):
                if flags & os.O_TMPFILE == os.O_TMPFILE:
                    raise OSError(errno.EOPNOTSUPP, "fixture filesystem lacks anonymous inode support")
                return original_open(path, flags, *positional, **keywords)
            with mock.patch.object(provision.os, "open", side_effect=unsupported), \
                    mock.patch.object(provision, "run_checked") as tar:
                with self.assertRaisesRegex(provision.ProvisionError, "private rootfs archive inode"):
                    provision.deterministic_rootfs_tar(rootfs, base / "output.tar", 0, normalize=False)
                tar.assert_not_called()
            self.assertFalse((base / "output.tar").exists())

    def test_gpgv_consumes_captured_bytes_and_kernel_sealed_keyring(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            data, key = base / "InRelease", base / "keyring.gpg"
            original = b"immutable InRelease fixture"
            key_bytes = b"immutable keyring fixture"
            data.write_bytes(original)
            key.write_bytes(key_bytes)
            fingerprint = "A" * 40

            def consume(command, **kwargs):
                data.write_bytes(b"pathname replacement")
                key.write_bytes(b"pathname replacement")
                self.assertEqual(kwargs["input"], original)
                self.assertEqual(command[-1], "-")
                key_fd = kwargs["pass_fds"][0]
                self.assertEqual(os.pread(key_fd, len(key_bytes), 0), key_bytes)
                with self.assertRaises(OSError) as refused:
                    os.pwrite(key_fd, b"x", 0)
                self.assertEqual(refused.exception.errno, errno.EPERM)
                return mock.Mock(returncode=0, stdout=("[GNUPG:] VALIDSIG " + fingerprint +
                    " 20261014 1 0 4 0 1 8 00\n").encode(), stderr=b"")

            with mock.patch.object(provision.subprocess, "run", side_effect=consume):
                self.assertEqual(provision.verify_gpgv(data, key, {fingerprint},
                    data_payload=original, key_payload=key_bytes), fingerprint)

    def test_detached_signature_consumes_sealed_data_and_original_signature(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            data, signature, key = base / "source", base / "signature", base / "key"
            payload, signed, key_bytes = b"original source bytes", b"original signature bytes", b"original key bytes"
            for path, value in ((data, payload), (signature, signed), (key, key_bytes)):
                path.write_bytes(value)
            fingerprint = "B" * 40

            def consume(command, **kwargs):
                for path in (data, signature, key):
                    path.write_bytes(b"replacement")
                self.assertEqual(kwargs["input"], signed)
                data_fd, key_fd = kwargs["pass_fds"]
                self.assertEqual(os.pread(data_fd, len(payload), 0), payload)
                self.assertEqual(os.pread(key_fd, len(key_bytes), 0), key_bytes)
                for descriptor in (data_fd, key_fd):
                    with self.assertRaises(OSError):
                        os.pwrite(descriptor, b"x", 0)
                return mock.Mock(returncode=0, stdout=("[GNUPG:] VALIDSIG " + fingerprint +
                    " 20261014 1 0 4 0 1 8 00\n").encode(), stderr=b"")

            with mock.patch.object(provision.subprocess, "run", side_effect=consume):
                self.assertEqual(provision.verify_detached_signature(signature, data, key, fingerprint,
                    data_payload=payload, signature_payload=signed, key_payload=key_bytes), fingerprint)

    def test_checked_index_parser_uses_original_compressed_bytes_after_path_replacement(self):
        with self.temporary_directory() as temp:
            for suffix, encode in (("gz", gzip.compress), ("xz", provision.lzma.compress)):
                path = Path(temp) / ("index." + suffix)
                original = encode(b"Package: original\nVersion: 1\n\n")
                path.write_bytes(original)
                checked = provision.read_regular_evidence(path)
                path.write_bytes(encode(b"Package: replacement\nVersion: 2\n\n"))
                with self.subTest(suffix=suffix):
                    self.assertEqual(list(provision.iter_compressed_index(path, payload=checked)),
                                     [{"Package": "original", "Version": "1"}])

    def test_package_closure_extraction_consumes_the_checked_index_bytes(self):
        with self.temporary_directory() as temp:
            root = Path(temp)
            path = root / "downloads/index.gz"
            path.parent.mkdir()
            original_row = b"Package: example\nVersion: 1\nArchitecture: amd64\nFilename: pool/example.deb\nSize: 7\nSHA256: " + b"a" * 64 + b"\n\n"
            original = gzip.compress(original_row)
            path.write_bytes(original)
            candidate = {"indexes": [{"path": "downloads/index.gz", "kind": "binary-amd64",
                "suite": "noble", "component": "main", "bytes": len(original),
                "sha256": provision.sha256(original)}]}
            parser = provision.iter_compressed_index

            def replace_before_parser(index, payload=None):
                path.write_bytes(gzip.compress(original_row.replace(b"a" * 64, b"f" * 64)))
                return parser(index, payload=payload)

            with mock.patch.object(provision, "iter_compressed_index", side_effect=replace_before_parser):
                observed = provision.package_metadata_for_keys(root, candidate, {("example", "1", "amd64")})
            self.assertEqual(observed[("example", "1", "amd64")]["sha256"], "a" * 64)

    def test_evidence_descriptor_checks_reject_fifo_symlink_and_length_changes(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            ordinary = base / "ordinary"
            ordinary.write_bytes(b"payload")
            fifo, link = base / "fifo", base / "link"
            os.mkfifo(fifo)
            link.symlink_to(ordinary)
            for path in (fifo, link):
                with self.subTest(path=path), self.assertRaises(provision.ProvisionError):
                    provision.verify_regular_evidence_identity(path, 7, provision.sha256(b"payload"))
            for value in (b"payloa", b"payload-extra", b"changed"):
                ordinary.write_bytes(value)
                with self.subTest(value=value), self.assertRaisesRegex(provision.ProvisionError, "bytes changed"):
                    provision.verify_regular_evidence_identity(ordinary, 7, provision.sha256(b"payload"))

    def test_build_record_commands_bind_keyring_environment_and_package_pins(self):
        record = self.valid_build_record()
        commands = record["commands"]
        digest = record["acquisition"]["ubuntuKeyring"]["sha256"]
        self.assertIn(f"--keyring=<UBUNTU_ARCHIVE_KEYRING_SHA256:{digest}>", commands["debootstrap"])
        self.assertIn(f"<UBUNTU_ARCHIVE_KEYRING_SHA256:{digest}>", commands["installAptKeyring"])
        self.assertIn("-fno-exceptions", commands["probeCompile"])
        self.assertIn("-fno-rtti", commands["probeCompile"])
        mutations = {
            "debootstrap": (f"--keyring=<UBUNTU_ARCHIVE_KEYRING_SHA256:{digest}>", "--keyring=/unbound/keyring"),
            "aptInstall": ("clang-18=1:18.1.3-1ubuntu1", "clang-18=1:22.1.6-unreviewed"),
            "aptUpdate": (f"PATH={self.contract['environment']['PATH']}", "PATH=/unreviewed/bin"),
            "rootfsTar": (f"--mtime=@{self.contract['environment']['SOURCE_DATE_EPOCH']}", "--mtime=@0"),
            "probeCompile": ("-fno-rtti", "-fplugin=/unreviewed/plugin.so"),
        }
        for name, (old, new) in mutations.items():
            record = self.valid_build_record()
            self.assertIn(old, record["commands"][name])
            record["commands"][name] = [new if arg == old else arg for arg in record["commands"][name]]
            with self.subTest(command=name), self.assertRaisesRegex(provision.ProvisionError, r"canonical recipe|checked-in schema.*commands"):
                provision.validate_build_record(record, self.contract)
        for digest in (None, 123, int("1" * 64)):
            record = self.valid_build_record()
            record["acquisition"]["ubuntuKeyring"]["sha256"] = digest
            with self.subTest(digest=digest), self.assertRaisesRegex(provision.ProvisionError, r"keyring|checked-in schema.*ubuntuKeyring"):
                provision.validate_build_record(record, self.contract)

    def test_selected_environment_changes_canonical_chroot_and_archive_commands(self):
        contract = json.loads(json.dumps(self.contract))
        contract["environment"]["PATH"] = "/custom/bin"
        contract["environment"]["SOURCE_DATE_EPOCH"] = "7"
        commands = provision.canonical_commands(contract, "b" * 64)
        for name in ("aptUpdate", "aptDownloadOnly", "aptInstall", "aptCheck", "clangCVersion",
                     "clangCxxVersion", "clangResourceDirectory", "llvmConfigLibdir", "llvmConfigCxxflags",
                     "probeCompile", "probeRun"):
            self.assertIn("PATH=/custom/bin", commands[name], name)
            self.assertIn("SOURCE_DATE_EPOCH=7", commands[name], name)
        self.assertIn("SOURCE_DATE_EPOCH=7", commands["debootstrap"])
        for name in ("rootfsTar", "ociArchive"):
            self.assertIn("--mtime=@7", commands[name])

    def test_bootstrap_ca_check_requires_package_and_nonempty_contained_bundle(self):
        packages = {("ca-certificates", "synthetic-test-only", "all")}
        with self.temporary_directory() as temp:
            rootfs = Path(temp)
            bundle = rootfs / "etc/ssl/certs/ca-certificates.crt"
            bundle.parent.mkdir(parents=True)
            for payload in (None, b""):
                if payload is not None:
                    bundle.write_bytes(payload)
                with self.subTest(payload=payload), self.assertRaisesRegex(provision.ProvisionError, "CA bundle"):
                    provision.require_bootstrap_ca_certificates(rootfs, packages)
            bundle.write_bytes(b"synthetic nonempty bundle; no TLS performed\n")
            with self.assertRaisesRegex(provision.ProvisionError, "package closure"):
                provision.require_bootstrap_ca_certificates(rootfs, set())
            provision.require_bootstrap_ca_certificates(rootfs, packages)
            bundle.unlink()
            bundle.symlink_to(Path(temp).parent)
            with self.assertRaisesRegex(provision.ProvisionError, "escapes"):
                provision.require_bootstrap_ca_certificates(rootfs, packages)

    def test_provisioning_checks_bootstrap_ca_before_any_apt_command(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            args = provision.argparse.Namespace(
                contract=provision.CONTRACT_PATH, workdir=base, rootfs=base / "rootfs",
                output=base / "output", acquisition=base / "acquisition", keyring=base / "keyring")
            args.acquisition.mkdir()
            bootstrap_commands = []
            def bootstrap(command, timeout=None):
                if provision.ROOTFS_DIRECTORY_CREATE_PROGRAM in command:
                    return self.simulate_privileged_rootfs_helper(command)
                if provision.ROOTFS_PARENT_RESTORE_PROGRAM in command:
                    return self.simulate_privileged_rootfs_helper(command)
                bootstrap_commands.append(command)
                return mock.Mock(stdout="")
            with mock.patch.object(provision, "load_candidate", return_value=({}, [])), \
                    mock.patch.object(provision, "check_runner_bounds"), \
                    mock.patch.object(provision, "run_checked", side_effect=bootstrap), \
                    mock.patch.object(provision, "installed_package_keys", return_value=set()), \
                    mock.patch.object(provision, "rootfs_run") as apt, \
                    mock.patch.object(provision.BoundedDownloader, "get") as network:
                with self.assertRaisesRegex(provision.ProvisionError, "package closure"):
                    provision._provision_rootfs_unqualified(args)
                self.assertEqual(len(bootstrap_commands), 1)
                self.assertIn("--include=ca-certificates", bootstrap_commands[0])
                apt.assert_not_called()
                network.assert_not_called()
            self.assertFalse(args.output.exists())

    def test_build_record_requires_bootstrap_ca_package_in_authenticated_closure(self):
        record = self.valid_build_record()
        record["packages"] = [row for row in record["packages"] if row["name"] != "ca-certificates"]
        with self.assertRaisesRegex(provision.ProvisionError, "bootstrap ca-certificates"):
            provision.validate_build_record(record, self.contract)

    def test_downloaded_package_key_parses_labeled_dpkg_deb_fields(self):
        result = mock.Mock(stdout="Package: clang-18\nVersion: 1:18.1.3-1ubuntu1\nArchitecture: amd64\n")
        with mock.patch.object(provision, "run_checked", return_value=result):
            self.assertEqual(provision.downloaded_package_key(Path("fixture.deb")),
                             ("clang-18", "1:18.1.3-1ubuntu1", "amd64"))
        for output in ("clang-18\n1:18.1.3-1ubuntu1\namd64\n",
                       "Package: clang-18\nVersion: 1:18.1.3-1ubuntu1\n",
                       "Package: clang-18\nPackage: substituted\nVersion: 1:18.1.3-1ubuntu1\nArchitecture: amd64\n"):
            with self.subTest(output=output), mock.patch.object(provision, "run_checked", return_value=mock.Mock(stdout=output)):
                with self.assertRaises(provision.ProvisionError):
                    provision.downloaded_package_key(Path("fixture.deb"))

    def test_build_record_rejects_missing_or_malformed_acquisition_digests(self):
        for field in ("candidateSha256", "sourceIndexesSha256", "binaryIndexesSha256"):
            for value in (None, "", "wrong", "F" * 64, int("1" * 64)):
                record = self.valid_build_record()
                if value is None:
                    record["acquisition"].pop(field)
                else:
                    record["acquisition"][field] = value
                with self.subTest(field=field, value=value), self.assertRaisesRegex(
                    provision.ProvisionError, r"checked-in schema.*acquisition",
                ):
                    provision.validate_build_record(record, self.contract)

    def test_driver_symlink_resolved_path_is_canonical_but_chain_is_preserved(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            target = rootfs / "usr/lib/llvm-18/bin/clang++"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"clang++ bytes")
            logical = rootfs / "usr/bin/clang++-18"
            logical.parent.mkdir(parents=True)
            logical.symlink_to("../lib/llvm-18/bin/clang++")
            row = provision.driver_record(rootfs, "/usr/bin/clang++-18", "cxx-driver", "clang version 18.1.3\n")
            self.assertEqual(row["resolvedPath"], "/usr/lib/llvm-18/bin/clang++")
            self.assertEqual(row["symlinkChain"], ["/usr/bin/clang++-18 -> ../lib/llvm-18/bin/clang++"])

    def test_runtime_manifest_binds_resolved_library_bytes_and_symlink_rows(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            library_dir = rootfs / "usr/lib/llvm-18/lib"
            library_dir.mkdir(parents=True)
            for name, content in (("libclang-cpp.so.18.1", b"clang library"), ("libLLVM-18.so.1", b"llvm library")):
                (library_dir / name).write_bytes(content)
            (library_dir / "libclang-cpp.so").symlink_to("libclang-cpp.so.18.1")
            (library_dir / "libLLVM-18.so").symlink_to("libLLVM-18.so.1")
            with mock.patch.object(provision, "run_probe_sandboxed", return_value="") as ldd:
                rows = provision.runtime_dependencies(rootfs, [], self.contract)
            self.assertEqual([call.args[1] for call in ldd.call_args_list], [
                ["/usr/bin/ldd", "/usr/lib/llvm-18/lib/libclang-cpp.so"],
                ["/usr/bin/ldd", "/usr/lib/llvm-18/lib/libLLVM-18.so"],
            ])
            by_path = {row["path"]: row for row in rows}
            self.assertEqual(by_path["/usr/lib/llvm-18/lib/libclang-cpp.so.18.1"]["sha256"],
                             provision.sha256(b"clang library"))
            self.assertEqual(by_path["/usr/lib/llvm-18/lib/libclang-cpp.so"]["sha256"],
                             provision.sha256(b"symlink\0libclang-cpp.so.18.1"))
            self.assertEqual(by_path["/usr/lib/llvm-18/lib/libclang-cpp.so"]["kind"], "symlink")
            self.assertEqual(by_path["/usr/lib/llvm-18/lib/libclang-cpp.so"]["target"], "libclang-cpp.so.18.1")
            self.assertEqual(by_path["/usr/lib/llvm-18/lib/libclang-cpp.so.18.1"]["kind"], "regular-file")
            self.assertIsNone(by_path["/usr/lib/llvm-18/lib/libclang-cpp.so.18.1"]["target"])
            record = {
                "tools": [{"role": "cxx-driver", "sha256": provision.sha256(b"clang library")}],
                "runtime": provision.manifest(rows),
            }
            self.assertEqual(provision.verified_frontend_runtime_library_digests(rootfs, record), [{
                "path": "toolchain/usr/lib/llvm-18/lib/libLLVM-18.so.1",
                "sha256": provision.sha256(b"llvm library"),
            }])

    def test_loader_projection_rejects_rehashed_runtime_omissions_extra_duplicate_and_order_changes(self):
        record = self.valid_build_record()
        target = "libclang-cpp.so.18.1"
        record["runtime"] = provision.manifest([
            {"path": "/usr/lib/llvm-18/lib/libLLVM-18.so.1", "bytes": 2, "sha256": "b" * 64,
             "kind": "regular-file", "target": None},
            {"path": "/usr/lib/llvm-18/lib/libclang-cpp.so.18.1", "bytes": 3, "sha256": "c" * 64,
             "kind": "regular-file", "target": None},
            {"path": "/usr/lib/llvm-18/lib/libclang-cpp.so", "bytes": len(target),
             "sha256": provision.sha256(b"symlink\0" + target.encode()), "kind": "symlink", "target": target},
        ])
        rootfs = Path(self.temp_root) / "rehashed-runtime-rootfs"
        shutil.rmtree(rootfs, ignore_errors=True)
        self.prepare_runtime_rootfs(record, rootfs)
        record_sha = provision.sha256(provision.canonical_json(record))
        report = self.valid_loader_report(record, record_sha, rootfs)
        expected_rows = [
            {"path": "toolchain/usr/lib/llvm-18/lib/libLLVM-18.so.1",
             "sha256": provision.sha256(b"synthetic runtime bytes: /usr/lib/llvm-18/lib/libLLVM-18.so.1")},
            {"path": "toolchain/usr/lib/llvm-18/lib/libclang-cpp.so.18.1",
             "sha256": provision.sha256(b"synthetic runtime bytes: /usr/lib/llvm-18/lib/libclang-cpp.so.18.1")},
        ]
        self.assertEqual(report["infrastructureProfileProjection"]["runtimeLibraryDigests"], expected_rows)
        provision.validate_provenance_loader_report(report, record, record_sha, rootfs)
        symlink = next(row for row in record["runtime"]["entries"] if row["kind"] == "symlink")
        mutations = {
            "omitted": expected_rows[:1],
            "extra": [*expected_rows, {"path": "toolchain/usr/lib/llvm-18/lib/unrecorded.so", "sha256": "d" * 64}],
            "duplicate": [*expected_rows, expected_rows[-1]],
            "reordered": list(reversed(expected_rows)),
            "symlink-added": [*expected_rows, {"path": "toolchain" + symlink["path"], "sha256": symlink["sha256"]}],
            "wrong-bytes": [expected_rows[0], {**expected_rows[1], "sha256": "d" * 64}],
        }
        for label, rows in mutations.items():
            changed = json.loads(json.dumps(report))
            projection = changed["infrastructureProfileProjection"]
            projection["runtimeLibraryDigests"] = rows
            changed["infrastructureProfileProjectionSha256"] = provision.frontend_profile_projection_sha256(projection)
            with self.subTest(label=label), self.assertRaisesRegex(provision.ProvisionError, "projection differs"):
                provision.validate_provenance_loader_report(changed, record, record_sha, rootfs)

    def test_runtime_manifest_rejects_missing_classification_and_inconsistent_symlink_bytes(self):
        target = "library.so.1"
        baseline = provision.manifest([
            {"path": "/usr/lib/library.so.1", "bytes": 2, "sha256": "b" * 64,
             "kind": "regular-file", "target": None},
            {"path": "/usr/lib/library.so", "bytes": len(target),
             "sha256": provision.sha256(b"symlink\0" + target.encode()), "kind": "symlink", "target": target},
        ])
        provision.validated_runtime_entries(baseline)
        mutations = {
            "missing-kind": lambda rows: rows[0].pop("kind"),
            "missing-target": lambda rows: rows[0].pop("target"),
            "unknown-kind": lambda rows: rows[0].update(kind="unknown"),
            "regular-target": lambda rows: rows[1].update(target=target),
            "symlink-null-target": lambda rows: rows[0].update(target=None),
            "changed-target": lambda rows: rows[0].update(target="different.so"),
            "changed-size": lambda rows: rows[0].update(bytes=1),
            "changed-sha": lambda rows: rows[0].update(sha256="d" * 64),
            "nul-target": lambda rows: rows[0].update(target="bad\0target"),
            "surrogate-target": lambda rows: rows[0].update(target="\ud800"),
            "oversize-target": lambda rows: rows[0].update(target="x" * 4097),
            "duplicate": lambda rows: rows.append(dict(rows[-1])),
            "reordered": lambda rows: rows.reverse(),
            "unknown-field": lambda rows: rows[0].update(accepted=True),
        }
        for label, mutate in mutations.items():
            changed = json.loads(json.dumps(baseline))
            mutate(changed["entries"])
            with self.subTest(label=label), self.assertRaises(provision.ProvisionError):
                provision.validated_runtime_entries(changed)

    def test_recorded_runtime_rechecks_kind_targets_and_bytes_in_rootfs(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            directory = rootfs / "usr/lib"
            directory.mkdir(parents=True)
            library = directory / "library.so.1"
            library.write_bytes(b"library bytes")
            link = directory / "library.so"
            link.symlink_to("/usr/lib/library.so.1")
            rows = [provision.runtime_file_entry(rootfs, "/usr/lib/library.so.1"),
                    provision.runtime_file_entry(rootfs, "/usr/lib/library.so")]
            record = {"runtime": provision.manifest(rows)}
            provision.verify_recorded_runtime_manifest(rootfs, record)

            link.unlink()
            link.write_bytes(b"library bytes")
            with self.assertRaisesRegex(provision.ProvisionError, "classification or bytes changed"):
                provision.verify_recorded_runtime_manifest(rootfs, record)
            link.unlink()
            link.symlink_to("library.so.1")
            with self.assertRaisesRegex(provision.ProvisionError, "classification or bytes changed"):
                provision.verify_recorded_runtime_manifest(rootfs, record)
            link.unlink()
            link.symlink_to("/usr/lib/library.so.1")
            library.write_bytes(b"changed library bytes")
            with self.assertRaisesRegex(provision.ProvisionError, "classification or bytes changed"):
                provision.verify_recorded_runtime_manifest(rootfs, record)
            library.write_bytes(b"library bytes")
            duplicate = directory / "identical.so.1"
            duplicate.write_bytes(b"library bytes")
            library.unlink()
            library.symlink_to("identical.so.1")
            with self.assertRaisesRegex(provision.ProvisionError, "classification or bytes changed"):
                provision.verify_recorded_runtime_manifest(rootfs, record)

    def test_runtime_classification_preserves_resources_manifest_wire(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            file = rootfs / "usr/lib/library.so.1"
            file.parent.mkdir(parents=True)
            file.write_bytes(b"library bytes")
            self.assertEqual(set(provision.file_entry(rootfs, "/usr/lib/library.so.1")), {"path", "bytes", "sha256"})
            self.assertEqual(set(provision.runtime_file_entry(rootfs, "/usr/lib/library.so.1")),
                             {"path", "bytes", "sha256", "kind", "target"})

    def test_runtime_dependencies_retain_directory_aliases_without_projecting_them_as_libraries(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            llvm_lib = rootfs / "usr/lib/llvm-18/lib"
            llvm_lib.mkdir(parents=True)
            (llvm_lib / "libclang-cpp.so").write_bytes(b"clang library")
            (llvm_lib / "libLLVM-18.so").write_bytes(b"llvm library")
            libc = rootfs / "usr/lib/x86_64-linux-gnu/libc.so.6"
            libc.parent.mkdir(parents=True)
            libc.write_bytes(b"libc library")
            (rootfs / "lib").symlink_to("usr/lib")
            with mock.patch.object(provision, "run_probe_sandboxed", return_value="libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x1234)"):
                rows = provision.runtime_dependencies(rootfs, ["/usr/bin/clang-18"], self.contract)
            by_path = {row["path"]: row for row in rows}
            self.assertEqual(by_path["/lib"], {
                "path": "/lib", "bytes": len("usr/lib"), "sha256": provision.sha256(b"symlink\0usr/lib"),
                "kind": "symlink", "target": "usr/lib",
            })
            self.assertEqual(by_path["/usr/lib/x86_64-linux-gnu/libc.so.6"]["kind"], "regular-file")
            record = self.valid_build_record()
            record["runtime"] = provision.manifest(rows)
            provision.verify_recorded_runtime_manifest(rootfs, record)
            self.assertEqual(len(provision.frontend_runtime_library_digests(record)), 3)
            self.assertNotIn("toolchain/lib", [row["path"] for row in provision.frontend_runtime_library_digests(record)])
            # Driver resolution still requires a regular file, even though runtime alias metadata permits directories.
            with self.assertRaisesRegex(provision.ProvisionError, "non-regular file"):
                provision.symlink_chain(rootfs, "/lib")

    def test_runtime_manifest_headers_and_projection_paths_match_schema_and_a_loader_bounds(self):
        entry = {"path": "/usr/lib/library.so.1", "bytes": 2, "sha256": "b" * 64,
                 "kind": "regular-file", "target": None}
        baseline = provision.manifest([entry])
        for field, value in (("entryCount", True), ("entryCount", 1.0), ("entryCount", 0),
                             ("bytes", float(baseline["bytes"])), ("bytes", False), ("bytes", 0)):
            changed = dict(baseline, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(provision.ProvisionError):
                provision.validated_runtime_entries(changed)
        exact_path = "/" + ("a" * 255 + "/") * 15 + "b" * 246
        self.assertEqual(len(("toolchain" + exact_path).encode()), 4096)
        provision.validated_runtime_entries(provision.manifest([{**entry, "path": exact_path}]))
        for path in (exact_path + "b", "/usr/lib/back\\slash.so", "/usr/lib/../library.so", "/usr//lib/library.so"):
            changed = provision.manifest([{**entry, "path": path}])
            with self.subTest(path=path), self.assertRaises(provision.ProvisionError):
                provision.validated_runtime_entries(changed)

    def test_driver_and_runtime_symlinks_retain_every_hop_and_enforce_limit(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            library_dir = rootfs / "usr/lib/llvm-18/lib"
            library_dir.mkdir(parents=True)
            target = library_dir / "library-bytes"
            target.write_bytes(b"library")
            for name in ("libclang-cpp.so", "libLLVM-18.so"):
                (library_dir / name).symlink_to("intermediate")
            (library_dir / "intermediate").symlink_to("library-bytes")
            chain, resolved = provision.symlink_chain(rootfs, "/usr/lib/llvm-18/lib/libclang-cpp.so")
            self.assertEqual(resolved, target)
            self.assertEqual(chain, [
                "/usr/lib/llvm-18/lib/libclang-cpp.so -> intermediate",
                "/usr/lib/llvm-18/lib/intermediate -> library-bytes",
            ])
            with mock.patch.object(provision, "run_probe_sandboxed", return_value=""):
                rows = provision.runtime_dependencies(rootfs, [], self.contract)
            self.assertEqual({row["path"] for row in rows}, {
                "/usr/lib/llvm-18/lib/libclang-cpp.so", "/usr/lib/llvm-18/lib/libLLVM-18.so",
                "/usr/lib/llvm-18/lib/intermediate", "/usr/lib/llvm-18/lib/library-bytes",
            })
            for index in reversed(range(17)):
                (library_dir / f"hop{index}").symlink_to("library-bytes" if index == 16 else f"hop{index + 1}")
            self.assertEqual(len(provision.symlink_chain(rootfs, "/usr/lib/llvm-18/lib/hop1")[0]), 16)
            with self.assertRaisesRegex(provision.ProvisionError, "cycle/depth overflow"):
                provision.symlink_chain(rootfs, "/usr/lib/llvm-18/lib/hop0")

    def test_driver_symlinks_resolve_parent_segments_after_directory_links(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            directory = rootfs / "usr/lib/llvm-18/bin"
            (directory / "other/subdir").mkdir(parents=True)
            (directory / "target").write_bytes(b"wrong lexical target")
            target = directory / "other/target"
            target.write_bytes(b"actual compiler")
            (directory / "alias").symlink_to("other/subdir")
            (directory / "clang").symlink_to("alias/../target")
            chain, resolved = provision.symlink_chain(rootfs, "/usr/lib/llvm-18/bin/clang")
            self.assertEqual(resolved, target)
            self.assertEqual(chain, [
                "/usr/lib/llvm-18/bin/clang -> alias/../target",
                "/usr/lib/llvm-18/bin/alias -> other/subdir",
            ])
            (directory / "escape").symlink_to("../../../../../../outside")
            with self.assertRaisesRegex(provision.ProvisionError, "escapes rootfs"):
                provision.symlink_chain(rootfs, "/usr/lib/llvm-18/bin/escape")

    def test_loader_resource_manifest_is_rechecked_before_emitting_input(self):
        record = self.valid_build_record()
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            resource_file = rootfs / "usr/lib/llvm-18/lib/clang/18.1.3/include/stddef.h"
            resource_file.parent.mkdir(parents=True)
            resource_file.write_bytes(b"resource header")
            record["resources"] = provision.resource_manifest(rootfs, record["resourceDirectory"])
            self.assertEqual(provision.verify_recorded_resource_manifest(rootfs, record), record["resources"])
            resource_file.write_bytes(b"changed resource header")
            with self.assertRaisesRegex(provision.ProvisionError, "resource-directory bytes differ"):
                provision.verify_recorded_resource_manifest(rootfs, record)

    def test_frontend_hashes_match_real_a_loader_vectors(self):
        # Independently emitted by the real Java A loader using synthetic bytes;
        # these pin its canonical encoding without asserting a qualified compiler.
        record = self.valid_build_record()
        self.assertEqual(provision.frontend_cxx_driver_identity_sha256(record, "b" * 64),
                         "7142e7789d3b8c9714f3468a4f571b40ff9db017ca271fcba3b4a394095af455")
        header = b"synthetic header\n"
        resources = provision.manifest([{
            "path": record["resourceDirectory"] + "/include/stddef.h",
            "bytes": len(header), "sha256": provision.sha256(header),
        }])
        self.assertEqual(provision.frontend_resource_manifest_sha256(record["resourceDirectory"], resources),
                         "26b8373fc116f0dd9ad8c09f98391092f66e87f254e6cff13d37cb2601208faf")

    def local_network_normalization_fixture(self, rootfs):
        """Run fixed network helper on real FDs, simulating only root ownership."""
        metadata = rootfs.stat()
        real_fstat = os.fstat
        def root_metadata(descriptor):
            fields = list(real_fstat(descriptor))
            fields[stat.ST_UID], fields[stat.ST_GID] = 0, 0
            return os.stat_result(fields)
        with mock.patch.object(sys, "argv", ["helper", str(rootfs), str(metadata.st_dev), str(metadata.st_ino)]), \
                mock.patch.object(os, "fstat", side_effect=root_metadata), \
                mock.patch.object(os, "fchown") as chown:
            exec(compile(provision.NETWORK_IDENTITY_NORMALIZE_PROGRAM, "<network-normalization>", "exec"), {})
        self.assertEqual([call.args[1:] for call in chown.call_args_list], [(0, 0), (0, 0)])

    def test_normalization_removes_inode_bearing_ldconfig_aux_cache(self):
        with self.temporary_directory() as temp:
            rootfs = Path(temp) / "rootfs"
            rootfs.mkdir()
            with mock.patch.object(provision, "run_checked") as run:
                provision.normalize_rootfs(rootfs, 1714003200)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertTrue(any(str(rootfs / "var/cache/ldconfig/aux-cache") in command for command in commands))
            self.assertTrue(any(command[:3] == ["sudo", "find", f"{rootfs}/."] for command in commands))

    def test_successful_retained_probe_replay_returns_authenticated_source_and_file_identities(self):
        with self.temporary_directory() as temporary:
            rootfs = Path(temporary) / "rootfs"
            record = self.valid_build_record()
            binary, fixture, mode = self.prepare_probe_rootfs(record, rootfs)
            source = provision.rootfs_path(rootfs, provision.PROBE_SOURCE_IN_ROOT)
            replay = {key: value for key, value in record["probe"].items()
                      if key not in ("sourceSha256", "binarySha256", "fixtureSha256")}
            with mock.patch.object(provision, "run_probe_sandboxed", return_value=json.dumps(replay)) as run, \
                    mock.patch.object(provision, "audit_langoptions", return_value=self.probe_inventory(record)):
                result = provision.validate_provenance_probe_report(record["probe"], record, rootfs, self.contract)
            self.assertEqual(result, (binary, fixture, source, mode))
            run.assert_called_once_with(
                rootfs, [provision.PROBE_BINARY_IN_ROOT, provision.PROBE_FIXTURE_IN_ROOT],
                self.contract, timeout=120,
            )
            for path, field in ((result[0], "binarySha256"), (result[1], "fixtureSha256"),
                                (result[2], "sourceSha256")):
                self.assertEqual(provision.sha256_file(path), record["probe"][field])

    def test_provenance_reports_must_bind_to_build_record_and_locked_comparator(self):
        record = self.valid_build_record()
        rootfs = Path(self.temp_root) / "loader-report-rootfs"
        shutil.rmtree(rootfs, ignore_errors=True)
        self.prepare_runtime_rootfs(record, rootfs)
        probe_binary, probe_fixture, _ = self.prepare_probe_rootfs(record, rootfs)
        probe_source = provision.rootfs_path(rootfs, provision.PROBE_SOURCE_IN_ROOT)
        replay = {key: value for key, value in record["probe"].items()
                  if key not in ("sourceSha256", "binarySha256", "fixtureSha256")}
        with mock.patch.object(provision, "run_probe_sandboxed", side_effect=provision.ProvisionError(
                provision.PROBE_SANDBOX_BLOCK_REASON)) as replay_run, \
                mock.patch.object(provision, "rootfs_run") as chroot_run, \
                mock.patch.object(provision, "audit_langoptions", return_value=self.probe_inventory(record)) as audit:
            with self.assertRaisesRegex(provision.ProvisionError, "no reviewed unprivileged"):
                provision.validate_provenance_probe_report(dict(record["probe"]), record, rootfs, self.contract)
        replay_run.assert_called_once_with(
            rootfs, [provision.PROBE_BINARY_IN_ROOT, provision.PROBE_FIXTURE_IN_ROOT], self.contract, timeout=120,
        )
        chroot_run.assert_not_called()
        audit.assert_not_called()

        with mock.patch.object(provision, "run_probe_sandboxed", side_effect=provision.ProvisionError(
                provision.PROBE_SANDBOX_BLOCK_REASON)), \
                mock.patch.object(provision, "audit_langoptions", return_value=self.probe_inventory(record)):
            with self.assertRaisesRegex(provision.ProvisionError, "probe provenance report differs"):
                provision.validate_provenance_probe_report(dict(record["probe"], target="tampered"),
                                                           record, rootfs, self.contract)
        original_binary = probe_binary.read_bytes()
        probe_binary.write_bytes(original_binary + b"tamper")
        with mock.patch.object(provision, "run_probe_sandboxed") as replay_run:
            with self.assertRaisesRegex(provision.ProvisionError, "binarySha256"):
                provision.validate_provenance_probe_report(dict(record["probe"]), record, rootfs, self.contract)
            replay_run.assert_not_called()
        probe_binary.write_bytes(original_binary)
        original_source = probe_source.read_bytes()
        probe_source.chmod(0o644)
        probe_source.write_bytes(original_source + b"tamper")
        with mock.patch.object(provision, "run_probe_sandboxed") as replay_run:
            with self.assertRaisesRegex(provision.ProvisionError, "expected recipe source bytes"):
                provision.validate_provenance_probe_report(dict(record["probe"]), record, rootfs, self.contract)
            replay_run.assert_not_called()
        probe_source.write_bytes(original_source)
        probe_source.chmod(0o444)
        changed_record = json.loads(json.dumps(record))
        changed_record["probe"]["sourceSha256"] = "0" * 64
        with mock.patch.object(provision, "run_probe_sandboxed") as replay_run:
            with self.assertRaisesRegex(provision.ProvisionError, "differ from the build-record sourceSha256"):
                provision.validate_provenance_probe_report(
                    changed_record["probe"], changed_record, rootfs, self.contract,
                )
            replay_run.assert_not_called()
        probe_binary.chmod(0o644)
        with mock.patch.object(provision, "run_probe_sandboxed") as replay_run:
            with self.assertRaisesRegex(provision.ProvisionError, "execute permission"):
                provision.validate_provenance_probe_report(dict(record["probe"]), record, rootfs, self.contract)
            replay_run.assert_not_called()
        probe_binary.chmod(0o755)
        probe_binary.unlink()
        with mock.patch.object(provision, "run_probe_sandboxed") as replay_run:
            with self.assertRaisesRegex(provision.ProvisionError, "unavailable"):
                provision.validate_provenance_probe_report(dict(record["probe"]), record, rootfs, self.contract)
            replay_run.assert_not_called()
        alternate = probe_binary.with_name("alternate-probe")
        alternate.write_bytes(original_binary)
        alternate.chmod(0o755)
        probe_binary.symlink_to(alternate.name)
        with mock.patch.object(provision, "run_probe_sandboxed") as replay_run:
            with self.assertRaisesRegex(provision.ProvisionError, "contains a symlink"):
                provision.validate_provenance_probe_report(dict(record["probe"]), record, rootfs, self.contract)
            replay_run.assert_not_called()
        probe_binary.unlink()
        probe_binary.write_bytes(original_binary)
        probe_binary.chmod(0o755)
        fixture_bytes = probe_fixture.read_bytes()
        probe_fixture.chmod(0o644)
        probe_fixture.write_bytes(fixture_bytes + b"tamper")
        with mock.patch.object(provision, "run_probe_sandboxed") as replay_run:
            with self.assertRaisesRegex(provision.ProvisionError, "fixture bytes"):
                provision.validate_provenance_probe_report(dict(record["probe"]), record, rootfs, self.contract)
            replay_run.assert_not_called()
        probe_fixture.write_bytes(fixture_bytes)
        probe_fixture.chmod(0o444)
        with mock.patch.object(provision, "run_probe_sandboxed", side_effect=provision.ProvisionError(
                provision.PROBE_SANDBOX_BLOCK_REASON)), \
                mock.patch.object(provision, "rootfs_run") as replay_run, \
                mock.patch.object(provision, "audit_langoptions", return_value=self.probe_inventory(record)):
            with self.assertRaises(provision.ProvisionError):
                provision.validate_provenance_probe_report(dict(record["probe"]), record, rootfs, self.contract)
            replay_run.assert_not_called()
        with mock.patch.object(provision, "run_probe_sandboxed", return_value=provision.canonical_json(
                {**replay, "macroObservations": {"expansionCount": 2, "macroInfoChecks": 1,
                                                   "nonBuiltinClassifications": 1}}).decode()), \
                mock.patch.object(provision, "audit_langoptions", return_value=self.probe_inventory(record)):
            with self.assertRaisesRegex(provision.ProvisionError, "replay differs"):
                provision.validate_provenance_probe_report(dict(record["probe"]), record, rootfs, self.contract)

        record_sha = "b" * 64
        loader_report = self.valid_loader_report(record, record_sha, rootfs)
        provision.validate_provenance_loader_report(loader_report, record, record_sha, rootfs)
        for field in ("cxxDriverIdentitySha256", "imageDigest", "resourceManifestSha256"):
            changed = dict(loader_report, **{field: "0" * 64})
            with self.subTest(field=field), self.assertRaises(provision.ProvisionError):
                provision.validate_provenance_loader_report(changed, record, record_sha, rootfs)
        for field in ("infrastructureProfileProjectionSha256", "pathTransformSha256"):
            digest = loader_report[field]
            wrong_digest = ("1" if digest[0] == "0" else "0") + digest[1:]
            changed = dict(loader_report, **{field: wrong_digest})
            with self.subTest(field=field), self.assertRaises(provision.ProvisionError):
                provision.validate_provenance_loader_report(changed, record, record_sha, rootfs)
        omitted = json.loads(json.dumps(loader_report))
        omitted_projection = omitted["infrastructureProfileProjection"]
        omitted_projection["runtimeLibraryDigests"].pop()
        omitted["infrastructureProfileProjectionSha256"] = provision.frontend_profile_projection_sha256(
            omitted_projection)
        with self.assertRaisesRegex(provision.ProvisionError, "frontend profile projection differs"):
            provision.validate_provenance_loader_report(omitted, record, record_sha, rootfs)
        added = json.loads(json.dumps(loader_report))
        added_projection = added["infrastructureProfileProjection"]
        added_projection["runtimeLibraryDigests"].append({
            "path": "toolchain/usr/lib/llvm-18/lib/unrecorded.so", "sha256": "d" * 64,
        })
        added["infrastructureProfileProjectionSha256"] = provision.frontend_profile_projection_sha256(
            added_projection)
        with self.assertRaisesRegex(provision.ProvisionError, "frontend profile projection differs"):
            provision.validate_provenance_loader_report(added, record, record_sha, rootfs)
        duplicated = json.loads(json.dumps(loader_report))
        duplicate_projection = duplicated["infrastructureProfileProjection"]
        duplicate_projection["runtimeLibraryDigests"].append(
            dict(duplicate_projection["runtimeLibraryDigests"][0]))
        duplicate_projection["runtimeLibraryDigests"].sort(key=lambda row: row["path"])
        duplicated["infrastructureProfileProjectionSha256"] = provision.frontend_profile_projection_sha256(
            duplicate_projection)
        with self.assertRaisesRegex(provision.ProvisionError, "frontend profile projection differs"):
            provision.validate_provenance_loader_report(duplicated, record, record_sha, rootfs)
        for field, changed_value in (("sha256", "0" * 64), ("bytes", 2), ("mode", "0755"),
                                     ("symlinkChain", ["/usr/bin/clang++-18 -> changed-target"])):
            changed_record = json.loads(json.dumps(record))
            next(row for row in changed_record["tools"] if row["role"] == "cxx-driver")[field] = changed_value
            with self.subTest(driver_field=field), self.assertRaisesRegex(provision.ProvisionError, "C\\+\\+ driver identity"):
                provision.validate_provenance_loader_report(loader_report, changed_record, record_sha, rootfs)
        loader_report["buildRecordSha256"] = "f" * 64
        with self.assertRaisesRegex(provision.ProvisionError, "does not bind the build record"):
            provision.validate_provenance_loader_report(loader_report, record, record_sha, rootfs)

        lock_path = ROOT / self.contract["negativeControl"]["artifactLock"]
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        artifact = lock["artifacts"][self.contract["negativeControl"]["artifactRole"]]
        fixture = ROOT / self.contract["negativeControl"]["fixture"]
        negative = {
            "scope": "negative-version-gate-only; not a Clang 18.1.3 identity",
            "artifactOracleId": self.contract["negativeControl"]["oracleId"],
            "artifactLockSha256": provision.sha256_file(lock_path),
            "compilerBytes": artifact["bytes"],
            "compilerSha256": artifact["sha256"],
            "compilerVersionOutput": "Ubuntu clang version 22.1.6",
            "fixtureBytes": fixture.stat().st_size,
            "fixtureSha256": record["probe"]["fixtureSha256"],
            "fixtureAcceptedByClang22": True,
            "compiler18GateRejected": "probe compiler version or target mismatch",
        }
        provision.validate_provenance_negative_report(negative, record, self.contract)
        negative["compilerSha256"] = "0" * 64
        with self.assertRaisesRegex(provision.ProvisionError, "does not match the locked comparator"):
            provision.validate_provenance_negative_report(negative, record, self.contract)

        with self.temporary_directory() as temp:
            base = Path(temp)
            copied_lock = base / "release-artifacts.json"
            copied_manifest = base / "oracle-manifest.json"
            shutil.copyfile(lock_path, copied_lock)
            shutil.copyfile(lock_path.parent / "oracle-manifest.json", copied_manifest)
            negative_contract = self.contract["negativeControl"]
            lock_copy = json.loads(copied_lock.read_bytes())
            self.assertEqual(provision.validate_locked_comparator_manifest(copied_lock, negative_contract)[1],
                             copied_manifest)

            copied_manifest.write_bytes(copied_manifest.read_bytes() + b"\n")
            with self.assertRaisesRegex(provision.ProvisionError, "manifest digest differs from the release-artifacts lock"):
                provision.validate_locked_comparator_manifest(copied_lock, negative_contract)

            manifest_copy = json.loads((lock_path.parent / "oracle-manifest.json").read_bytes())
            manifest_copy["oracle"]["id"] = "unlocked-comparator"
            modified_manifest = provision.canonical_json(manifest_copy)
            copied_manifest.write_bytes(modified_manifest)
            lock_copy["oracle"]["artifactManifestSha256"] = provision.sha256(modified_manifest)
            copied_lock.write_bytes(provision.canonical_json(lock_copy))
            with self.assertRaisesRegex(provision.ProvisionError, "manifest oracle identity differs"):
                provision.validate_locked_comparator_manifest(copied_lock, negative_contract)

    def test_deb822_rejects_duplicate_fields(self):
        with self.assertRaises(provision.ProvisionError):
            provision.parse_deb822("Package: llvm\nPackage: forged\n")

    def test_deb822_rejects_orphan_continuation(self):
        with self.assertRaises(provision.ProvisionError):
            provision.parse_deb822(" continuation\n")

    def test_streamed_index_rejects_an_oversized_line_before_unbounded_read(self):
        with self.temporary_directory() as temp:
            path = Path(temp) / "Packages.gz"
            path.write_bytes(gzip.compress(b"12345\n"))
            with mock.patch.object(provision, "MAX_INDEX_LINE_BYTES", 4):
                with self.assertRaisesRegex(provision.ProvisionError, "oversized control line"):
                    list(provision.iter_compressed_index(path))

    def test_signed_empty_package_index_is_allowed_but_empty_control_document_is_not(self):
        with self.temporary_directory() as temp:
            path = Path(temp) / "Packages.gz"
            path.write_bytes(gzip.compress(b""))
            self.assertEqual(list(provision.iter_compressed_index(path)), [])
        with self.assertRaisesRegex(provision.ProvisionError, "empty Debian control/index document"):
            provision.parse_deb822("")

    def test_inrelease_cleartext_unescapes_dash_prefixed_lines(self):
        data = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
                "Suite: noble\n- -leading dash\n-----BEGIN PGP SIGNATURE-----\n"
                "signature\n-----END PGP SIGNATURE-----\n").encode()
        self.assertEqual(provision.cleartext_body(data), b"Suite: noble\n-leading dash\n")

    def test_release_identity_mismatch_fails_closed(self):
        with self.assertRaises(provision.ProvisionError):
            provision.verify_release_identity({"Suite": "noble", "Codename": "jammy"}, "noble", "noble")

    def test_official_release_component_superset_is_valid_for_selected_components(self):
        release = {"Origin": "Ubuntu", "Label": "Ubuntu", "Suite": "noble", "Codename": "noble",
                   "Architectures": "amd64 arm64", "Components": "main restricted universe multiverse"}
        provision.verify_release_profile(release, "noble", self.contract["profile"])
        release["Origin"] = "Ubuntu mirror"
        with self.assertRaises(provision.ProvisionError):
            provision.verify_release_profile(release, "noble", self.contract["profile"])

    def test_signed_index_selection_uses_architecture_packages_and_sources(self):
        table = {
            "main/binary-amd64/Packages.gz": (1, "0" * 64),
            "main/source/Sources.xz": (1, "1" * 64),
        }
        self.assertEqual(provision.index_path(table, "main", "binary-amd64", "amd64"),
                         "main/binary-amd64/Packages.gz")
        self.assertEqual(provision.index_path(table, "main", "source"), "main/source/Sources.xz")

    def test_release_sha256_table_accepts_standard_empty_field_value_line(self):
        digest = "a" * 64
        release = provision.parse_deb822(
            "Suite: noble\nSHA256:\n  " + digest + " 123 main/binary-amd64/Packages.gz\n"
        )[0]
        self.assertEqual(
            provision.release_sha256_table(release),
            {"main/binary-amd64/Packages.gz": (123, digest)},
        )

    def test_release_sha256_table_rejects_an_internal_blank_row(self):
        digest = "a" * 64
        release = provision.parse_deb822(
            "SHA256:\n  " + digest + " 123 Packages.gz\n \n  " + "b" * 64 + " 456 Sources.gz\n"
        )[0]
        with self.assertRaisesRegex(provision.ProvisionError, "malformed SHA256 row"):
            provision.release_sha256_table(release)

    def test_source_checksums_accept_standard_empty_field_value_line(self):
        digest = "c" * 64
        source = provision.parse_deb822(
            "Package: llvm-toolchain-18\nChecksums-Sha256:\n  " + digest + " 456 llvm-toolchain-18.tar.xz\n"
        )[0]
        self.assertEqual(
            provision.source_file_rows(source),
            [{"name": "llvm-toolchain-18.tar.xz", "bytes": 456, "sha256": digest}],
        )

    def test_source_checksums_reject_an_internal_blank_row(self):
        digest = "c" * 64
        source = provision.parse_deb822(
            "Package: llvm-toolchain-18\nChecksums-Sha256:\n  " + digest +
            " 456 first.tar.xz\n \n  " + "d" * 64 + " 789 second.tar.xz\n"
        )[0]
        with self.assertRaisesRegex(provision.ProvisionError, "malformed source Checksums-Sha256 row"):
            provision.source_file_rows(source)

    def test_source_selection_error_reports_versions_from_signed_package_records(self):
        rows = [{
            "Package": "llvm-toolchain-18", "Version": "1:18.1.3-1ubuntu0",
            "_suite": "noble", "_component": "universe",
        }]
        with self.assertRaisesRegex(
            provision.ProvisionError,
            r"expected a unique signed source record.*observed signed versions: 1:18.1.3-1ubuntu0@noble/universe",
        ):
            provision.select_source_record(rows, "llvm-toolchain-18", "1:18.1.3-1ubuntu1",
                                           self.contract["profile"])

    def test_source_selection_uses_explicit_pinned_pocket_precedence_and_rejects_conflicts(self):
        profile = self.contract["profile"]
        source = {
            "Package": "llvm-toolchain-18", "Version": "1:18.1.3-1ubuntu1",
            "Directory": "pool/universe/l/llvm-toolchain-18",
            "Checksums-Sha256": "a" * 64 + " 12 source.dsc",
            "_component": "universe",
        }
        noble = {**source, "_suite": "noble"}
        updates = {**source, "_suite": "noble-updates"}
        selected = provision.select_source_record([updates, noble], "llvm-toolchain-18",
                                                  "1:18.1.3-1ubuntu1", profile)
        self.assertEqual(selected["_suite"], profile["suites"][0])
        conflict = {**updates, "Directory": "pool/universe/l/llvm-toolchain-18-shadow"}
        with self.assertRaisesRegex(provision.ProvisionError, "expected a unique signed source record"):
            provision.select_source_record([noble, conflict], "llvm-toolchain-18",
                                           "1:18.1.3-1ubuntu1", profile)
        invalid = {**noble, "_component": "main"}
        with self.assertRaisesRegex(provision.ProvisionError, "Directory"):
            provision.select_source_record([invalid], "llvm-toolchain-18",
                                           "1:18.1.3-1ubuntu1", profile)

    def test_source_index_diagnostic_binds_snapshot_hashes_versions_and_binary_sources(self):
        profile = self.contract["profile"]
        digest = "e" * 64
        repositories = [{
            "suite": "noble",
            "signerPrimaryFingerprint": profile["ubuntuArchivePrimaryFingerprints"][0],
            "inRelease": {"bytes": 123, "sha256": digest},
            "releaseIdentity": {"Date": "Thu, 25 Apr 2024 00:00:00 UTC", "Suite": "noble"},
        }]
        indexes = [{
            "suite": "noble", "component": "universe", "kind": "source",
            "path": "downloads/noble/universe/source/Sources.xz", "bytes": 456, "sha256": digest,
        }, {
            "suite": "noble", "component": "universe", "kind": "binary-amd64",
            "path": "downloads/noble/universe/binary-amd64/Packages.xz", "bytes": 654, "sha256": digest,
        }]
        sources = [{
            "_suite": "noble", "_component": "universe", "Package": "llvm-toolchain-18",
            "Version": "1:18.1.3-1ubuntu0", "Directory": "pool/universe/l/llvm-toolchain-18",
            "Checksums-Sha256": "f" * 64 + " 789 llvm-toolchain-18_18.1.3.orig.tar.xz",
        }]
        binaries = [{
            "_suite": "noble", "_component": "universe", "Package": "clang-18",
            "Version": "1:18.1.3-1ubuntu1", "Architecture": "amd64",
            "Source": "llvm-toolchain-18 (1:18.1.3-1ubuntu0)",
            "Filename": "pool/universe/l/llvm-toolchain-18/clang-18.deb",
            "Size": "987", "SHA256": digest,
        }]

        related_sources = [{
            "_suite": "noble", "_component": "universe", "Package": "llvm-toolchain-17",
            "Version": "1:17.0.6-9ubuntu1", "Directory": "pool/universe/l/llvm-toolchain-17",
        }]
        report = provision.source_index_diagnostic(
            profile, repositories, indexes, sources, related_sources, len(related_sources), binaries
        )
        self.assertEqual(report["snapshot"], profile["snapshot"])
        self.assertEqual(report["expectedSource"], profile["sourcePackage"])
        self.assertEqual(report["sourceIndexes"][0]["sha256"], digest)
        self.assertEqual(report["binaryIndexes"][0]["sha256"], digest)
        self.assertEqual(report["sourcePackageVersionsObserved"], ["1:18.1.3-1ubuntu0"])
        self.assertEqual(report["exactSourceVersionRecordCount"], 0)
        self.assertEqual(report["selectionAssessment"], "package-found-but-exact-version-not-found")
        self.assertEqual(report["selectionSemantics"], "exact Package and Version strings; no epoch or version normalization")
        self.assertEqual(report["matchingSourcePackageRecords"][0]["package"], "llvm-toolchain-17")
        self.assertEqual(report["binaryRootRecords"][0]["source"], binaries[0]["Source"])

    def test_source_index_diagnostic_caps_related_rows_and_marks_truncation(self):
        profile = self.contract["profile"]
        related_sources = [{
            "_suite": "noble", "_component": "universe", "Package": f"llvm-toolchain-{index}",
            "Version": f"1:{index}.0.0-1", "Directory": f"pool/universe/l/llvm-toolchain-{index}",
        } for index in range(provision.MAX_SOURCE_DIAGNOSTIC_ROWS + 1)]
        report = provision.source_index_diagnostic(profile, [], [], [], related_sources,
                                                   len(related_sources), [])
        self.assertEqual(len(report["matchingSourcePackageRecords"]), provision.MAX_SOURCE_DIAGNOSTIC_ROWS)
        self.assertEqual(report["matchingPackageRecordCount"], provision.MAX_SOURCE_DIAGNOSTIC_ROWS + 1)
        self.assertTrue(report["matchingPackageRecordsTruncated"])

    def test_snapshot_metadata_probe_reports_exact_source_and_binary_roots_without_payload_claims(self):
        profile = {**self.contract["profile"], "snapshot": provision.SNAPSHOT_METADATA_PROBE,
                   "snapshotBase": f"https://snapshot.ubuntu.com/ubuntu/{provision.SNAPSHOT_METADATA_PROBE}/"}
        source_pin = profile["sourcePackage"]
        source = {
            "Package": source_pin["name"], "Version": source_pin["version"],
            "Directory": "pool/main/l/llvm-toolchain-18",
            "Checksums-Sha256": "\n  ".join([
                "e" * 64 + " 8313 llvm-toolchain-18_18.1.3-1ubuntu1.dsc",
                "d" * 64 + " 155361864 llvm-toolchain-18_18.1.3.orig.tar.xz",
                "a" * 64 + " 162568 llvm-toolchain-18_18.1.3-1ubuntu1.debian.tar.xz",
            ]),
            "_suite": "noble-updates", "_component": "main",
        }
        binaries = []
        for index, pin in enumerate(profile["binaryRoots"]):
            binaries.append({
                "Package": pin["name"], "Version": pin["version"], "Architecture": "amd64",
                "Source": "llvm-toolchain-18 (18.1.3-1ubuntu1)",
                "Filename": f"pool/universe/l/llvm-toolchain-18/{pin['name']}_18.1.3-1ubuntu1_amd64.deb",
                "Size": 100 + index, "SHA256": f"{index + 1:x}" * 64,
                "_suite": "noble-updates", "_component": "universe",
            })
        with self.temporary_directory() as temp:
            keyring = Path(temp) / "ubuntu-archive-keyring.gpg"
            keyring.write_bytes(b"fixture keyring bytes")
            report = provision.snapshot_metadata_selection(
                self.contract, profile, [], [], [source], binaries, 1234, keyring,
            )
        self.assertEqual(report["status"], "exact-contract-records-present")
        self.assertEqual(report["candidateSnapshot"], provision.SNAPSHOT_METADATA_PROBE)
        self.assertEqual(report["configuredSnapshot"], self.contract["profile"]["snapshot"])
        self.assertEqual(report["payloadBytesDownloaded"], 0)
        self.assertEqual(report["sourcePackage"]["exactRecords"][0]["sourceFiles"][0]["name"],
                         "llvm-toolchain-18_18.1.3-1ubuntu1.dsc")
        self.assertEqual({row["package"] for row in report["binaryRoots"]},
                         {row["name"] for row in profile["binaryRoots"]})
        self.assertTrue(all(row["status"] == "exact-version-unique" for row in report["binaryRoots"]))

    def test_snapshot_metadata_probe_does_not_normalize_source_or_binary_versions(self):
        profile = {**self.contract["profile"], "snapshot": provision.SNAPSHOT_METADATA_PROBE,
                   "snapshotBase": f"https://snapshot.ubuntu.com/ubuntu/{provision.SNAPSHOT_METADATA_PROBE}/"}
        source = {"Package": "llvm-toolchain-18", "Version": "1:18.1.3-1",
                  "Directory": "pool/main/l/llvm-toolchain-18",
                  "Checksums-Sha256": "f" * 64 + " 1 x.dsc",
                  "_suite": "noble-updates", "_component": "main"}
        binaries = [{
            "Package": pin["name"],
            "Version": "1:18.1.3-1" if pin["name"] == "clang-18" else pin["version"],
            "Architecture": "amd64", "Source": "llvm-toolchain-18 (18.1.3-1)",
            "Filename": f"pool/universe/llvm/{pin['name']}.deb", "Size": 2,
            "SHA256": "b" * 64, "_suite": "noble-updates", "_component": "universe",
        } for pin in profile["binaryRoots"]]
        with self.temporary_directory() as temp:
            keyring = Path(temp) / "ubuntu-archive-keyring.gpg"
            keyring.write_bytes(b"fixture keyring bytes")
            report = provision.snapshot_metadata_selection(
                self.contract, profile, [], [], [source], binaries, 1234, keyring,
            )
        self.assertEqual(report["status"], "source-exact-version-not-found")
        self.assertEqual(report["sourcePackage"]["observedVersions"], ["1:18.1.3-1"])
        clang = next(row for row in report["binaryRoots"] if row["package"] == "clang-18")
        self.assertEqual(clang["status"], "exact-version-not-found")
        self.assertEqual(clang["observedVersions"], ["1:18.1.3-1"])

    def test_snapshot_metadata_probe_is_locked_to_the_reviewed_timestamp(self):
        with self.temporary_directory() as temp:
            output = Path(temp) / "metadata"
            with self.assertRaisesRegex(provision.ProvisionError, "metadata-only probe is pinned"):
                provision.probe_snapshot_metadata(
                    self.contract, "20240425T000000Z", output, Path(temp) / "keyring"
                )
            self.assertFalse(output.exists())

    def test_snapshot_metadata_probe_authenticates_only_inrelease_and_index_urls(self):
        profile = self.contract["profile"]
        snapshot = provision.SNAPSHOT_METADATA_PROBE
        base = f"https://snapshot.ubuntu.com/ubuntu/{snapshot}/"
        objects = {}

        def packed_text(value):
            return gzip.compress(value.encode("utf-8"), mtime=0)

        source = (
            "Package: llvm-toolchain-18\n"
            "Version: 1:18.1.3-1ubuntu1\n"
            "Directory: pool/main/l/llvm-toolchain-18\n"
            "Checksums-Sha256:\n"
            " " + "e" * 64 + " 8313 llvm-toolchain-18_18.1.3-1ubuntu1.dsc\n"
            " " + "d" * 64 + " 155361864 llvm-toolchain-18_18.1.3.orig.tar.xz\n"
            " " + "a" * 64 + " 162568 llvm-toolchain-18_18.1.3-1ubuntu1.debian.tar.xz\n"
        )
        packages = []
        for index, pin in enumerate(profile["binaryRoots"]):
            package_digest = f"{index + 1:x}" * 64
            packages.append(
                f"Package: {pin['name']}\n"
                f"Version: {pin['version']}\n"
                "Architecture: amd64\n"
                "Source: llvm-toolchain-18 (18.1.3-1ubuntu1)\n"
                f"Filename: pool/universe/l/llvm-toolchain-18/{pin['name']}.deb\n"
                f"Size: {100 + index}\n"
                f"SHA256: {package_digest}\n"
            )
        release_docs = []
        for suite in profile["suites"]:
            entries = []
            for component in profile["components"]:
                for kind in ("source", "binary-amd64"):
                    relative_index = (f"{component}/source/Sources.gz" if kind == "source" else
                                      f"{component}/binary-amd64/Packages.gz")
                    if suite == "noble-updates" and component == "main" and kind == "source":
                        index_bytes = packed_text(source)
                    elif suite == "noble-updates" and component == "universe" and kind == "binary-amd64":
                        index_bytes = packed_text("\n".join(packages))
                    else:
                        index_bytes = packed_text("")
                    index_url = base + f"dists/{suite}/{relative_index}"
                    objects[index_url] = index_bytes
                    entries.append(f"  {provision.sha256(index_bytes)} {len(index_bytes)} {relative_index}")
            body = (
                f"Origin: Ubuntu\nLabel: Ubuntu\nSuite: {suite}\nCodename: noble\n"
                "Date: Fri, 14 Jun 2024 23:00:00 UTC\n"
                "Architectures: amd64 arm64\nComponents: main universe\n"
                "SHA256:\n" + "\n".join(entries) + "\n"
            )
            inrelease = (
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" + body +
                "-----BEGIN PGP SIGNATURE-----\n\nfixture-signature\n-----END PGP SIGNATURE-----\n"
            ).encode("utf-8")
            objects[base + f"dists/{suite}/InRelease"] = inrelease
            release_docs.append(suite)

        class FakeDownloader:
            all_calls = []

            def __init__(self, root, total_limit):
                self.total = 0
                self.calls = []

            def get(self, url, expected_size=None, expected_sha256=None, max_bytes=0, allow_github_redirect=False):
                self.calls.append(url)
                self.all_calls.append(url)
                data = objects[url]
                if len(data) > max_bytes:
                    raise AssertionError("probe exceeded its test byte bound")
                if expected_size is not None:
                    self_test.assertEqual(len(data), expected_size)
                digest = provision.sha256(data)
                if expected_sha256 is not None:
                    self_test.assertEqual(digest, expected_sha256)
                self.total += len(data)
                return data, {"url": url, "finalUrl": url, "bytes": len(data), "sha256": digest}

        self_test = self
        with self.temporary_directory() as temp:
            keyring = Path(temp) / "ubuntu-archive-keyring.gpg"
            keyring.write_bytes(b"test keyring")
            output = Path(temp) / "metadata"
            with mock.patch.object(provision, "BoundedDownloader", FakeDownloader), \
                 mock.patch.object(provision, "check_runner_bounds"), \
                 mock.patch.object(provision, "verify_gpgv",
                                   return_value=profile["ubuntuArchivePrimaryFingerprints"][0]):
                report = provision.probe_snapshot_metadata(self.contract, snapshot, output, keyring)
            report_exists = (output / "snapshot-metadata-report.json").is_file()
            payload_files_exist = any(path.suffix in (".deb", ".dsc") for path in output.rglob("*"))

        self.assertEqual(report["status"], "exact-contract-records-present")
        self.assertEqual(len(report["repositories"]), 3)
        self.assertEqual(len(report["indexes"]), 12)
        self.assertEqual(report["payloadBytesDownloaded"], 0)
        self.assertEqual(len(release_docs), 3)
        self.assertEqual(len(FakeDownloader.all_calls), 15)
        self.assertTrue(all(url.startswith(base + "dists/") for url in FakeDownloader.all_calls))
        self.assertTrue(report_exists)
        self.assertFalse(payload_files_exist)

    def test_gpgv_primary_fingerprint_is_not_signature_class(self):
        signing = "A" * 40
        primary = "B" * 40
        fields = ["[GNUPG:]", "VALIDSIG", signing, "20261005", "1", "0", "4", "0", "1", "8", "00", primary]
        self.assertEqual(provision.valid_sig_primary_fingerprint(fields), primary)

    def test_gpgv_malformed_validsig_fails_closed(self):
        with self.assertRaises(provision.ProvisionError):
            provision.valid_sig_primary_fingerprint(["[GNUPG:]", "VALIDSIG", "A" * 40, "00"])

    def test_gpgv_requires_an_allowlisted_primary_fingerprint(self):
        with self.temporary_directory() as temp:
            keyring = Path(temp) / "keyring.gpg"
            keyring.write_bytes(b"fixture")
            data = Path(temp) / "InRelease"
            data.write_bytes(b"inert clear-signed document fixture")
            signing, primary = "A" * 40, "B" * 40
            status = ("[GNUPG:] VALIDSIG " + signing +
                      " 20261005 1 0 4 0 1 8 00 " + primary + "\n")
            proc = mock.Mock(returncode=0, stdout=status, stderr="")
            with mock.patch.object(provision.subprocess, "run", return_value=proc):
                self.assertEqual(provision.verify_gpgv(data, keyring, {primary}), primary)
                with self.assertRaises(provision.ProvisionError):
                    provision.verify_gpgv(data, keyring, {signing})

    def test_armored_upstream_key_is_dearmored_with_a_workspace_local_gnupg_home(self):
        with self.temporary_directory() as temp:
            proc = mock.Mock(returncode=0, stdout=b"\x99binary-keyring", stderr=b"")
            with mock.patch.object(provision.subprocess, "run", return_value=proc) as run:
                result = provision.dearmor_release_key(
                    provision.ROOT / self.contract["profile"]["upstream"]["keyFile"], Path(temp),
                )
            self.assertEqual(result, b"\x99binary-keyring")
            command = run.call_args.args[0]
            self.assertIn("--homedir", command)
            self.assertTrue(Path(command[command.index("--homedir") + 1]).parent == Path(temp))

    def test_armored_upstream_key_dearmor_failure_rejects(self):
        with self.temporary_directory() as temp:
            proc = mock.Mock(returncode=1, stdout=b"", stderr=b"bad key")
            with mock.patch.object(provision.subprocess, "run", return_value=proc):
                with self.assertRaises(provision.ProvisionError):
                    provision.dearmor_release_key(
                        provision.ROOT / self.contract["profile"]["upstream"]["keyFile"], Path(temp),
                    )

    def test_redirect_handler_rejects_unapproved_destination_before_following(self):
        handler = provision.LockedRedirectHandler("snapshot.ubuntu.com", False)
        request = provision.urllib.request.Request("https://snapshot.ubuntu.com/object")
        with self.assertRaises(provision.urllib.error.URLError):
            handler.redirect_request(request, None, 302, "Found", {}, "https://attacker.invalid/object")

    def test_redirect_handler_allows_only_locked_github_release_cdns(self):
        handler = provision.LockedRedirectHandler("github.com", True)
        request = provision.urllib.request.Request("https://github.com/llvm/asset")
        redirected = handler.redirect_request(request, None, 302, "Found", {},
                                               "https://release-assets.githubusercontent.com/asset")
        self.assertEqual(redirected.full_url, "https://release-assets.githubusercontent.com/asset")

    def test_public_downloader_rejects_untrusted_redirect_host(self):
        class Response(io.BytesIO):
            headers = {"Content-Encoding": "identity", "Content-Length": "4"}

            def __enter__(self):
                return self

            def __exit__(self, *_):
                self.close()

            def geturl(self):
                return "https://attacker.invalid/payload"

        with self.temporary_directory() as temp:
            downloader = provision.BoundedDownloader(Path(temp))
            with mock.patch.object(downloader, "_open_request", return_value=Response(b"data")):
                with self.assertRaises(provision.ProvisionError):
                    downloader.get("https://snapshot.ubuntu.com/object")

    def test_public_downloader_rejects_size_and_digest_mismatch(self):
        class Response(io.BytesIO):
            headers = {"Content-Encoding": "identity", "Content-Length": "4"}

            def __enter__(self):
                return self

            def __exit__(self, *_):
                self.close()

            def geturl(self):
                return "https://snapshot.ubuntu.com/object"

        with self.temporary_directory() as temp:
            downloader = provision.BoundedDownloader(Path(temp))
            with mock.patch.object(downloader, "_open_request", return_value=Response(b"data")):
                with self.assertRaises(provision.ProvisionError):
                    downloader.get("https://snapshot.ubuntu.com/object", expected_size=5)
            downloader = provision.BoundedDownloader(Path(temp) / "second")
            with mock.patch.object(downloader, "_open_request", return_value=Response(b"data")):
                with self.assertRaises(provision.ProvisionError):
                    downloader.get("https://snapshot.ubuntu.com/object", expected_sha256="0" * 64)

    def test_public_downloader_limits_each_read_to_remaining_cumulative_allowance(self):
        with self.temporary_directory() as temp:
            downloader = provision.BoundedDownloader(Path(temp), total_limit=10)
            first = DownloadResponseFixture(b"first!", announced=6)
            overflow = DownloadResponseFixture(b"12345678")
            with mock.patch.object(downloader, "_open_request", side_effect=[first, overflow]):
                self.assertEqual(downloader.get("https://snapshot.ubuntu.com/object", max_bytes=8)[0], b"first!")
                with self.assertRaisesRegex(provision.ProvisionError, "cumulative acquisition"):
                    downloader.get("https://snapshot.ubuntu.com/object", max_bytes=8)
            self.assertEqual(first.read_sizes, [9])
            self.assertEqual(overflow.read_sizes, [5])  # remaining four bytes plus one overflow sentinel
            self.assertEqual(downloader.total, 11)
            with mock.patch.object(downloader, "_open_request") as network:
                with self.assertRaisesRegex(provision.ProvisionError, "cumulative acquisition"):
                    downloader.get("https://snapshot.ubuntu.com/object", max_bytes=8)
                network.assert_not_called()

    def test_public_downloader_rejects_announced_or_expected_overflow_before_body_read(self):
        with self.temporary_directory() as temp:
            downloader = provision.BoundedDownloader(Path(temp), total_limit=10)
            downloader.total = 8
            response = DownloadResponseFixture(b"payload", announced=3)
            with mock.patch.object(downloader, "_open_request", return_value=response) as network:
                with self.assertRaisesRegex(provision.ProvisionError, "cumulative acquisition"):
                    downloader.get("https://snapshot.ubuntu.com/object", max_bytes=8)
                network.assert_called_once()
            self.assertEqual(response.read_sizes, [])
            self.assertEqual(downloader.total, 8)
            with mock.patch.object(downloader, "_open_request") as network:
                with self.assertRaisesRegex(provision.ProvisionError, "cumulative acquisition"):
                    downloader.get("https://snapshot.ubuntu.com/object", expected_size=3, max_bytes=8)
                network.assert_not_called()

    def test_public_downloader_accepts_exact_total_boundary_and_preserves_object_ceiling(self):
        with self.temporary_directory() as temp:
            downloader = provision.BoundedDownloader(Path(temp), total_limit=10)
            first, last = DownloadResponseFixture(b"first!"), DownloadResponseFixture(b"last", announced=4)
            with mock.patch.object(downloader, "_open_request", side_effect=[first, last]):
                downloader.get("https://snapshot.ubuntu.com/object", max_bytes=8)
                data, identity = downloader.get("https://snapshot.ubuntu.com/object", expected_size=4,
                                               expected_sha256=provision.sha256(b"last"), max_bytes=8)
            self.assertEqual(data, b"last")
            self.assertEqual(identity["bytes"], 4)
            self.assertEqual(last.read_sizes, [5])
            self.assertEqual(downloader.total, 10)
            with mock.patch.object(downloader, "_open_request") as network:
                with self.assertRaisesRegex(provision.ProvisionError, "cumulative acquisition"):
                    downloader.get("https://snapshot.ubuntu.com/object", max_bytes=8)
                network.assert_not_called()
            downloader = provision.BoundedDownloader(Path(temp) / "object", total_limit=10)
            response = DownloadResponseFixture(b"123456")
            with mock.patch.object(downloader, "_open_request", return_value=response):
                with self.assertRaisesRegex(provision.ProvisionError, "per-object"):
                    downloader.get("https://snapshot.ubuntu.com/object", max_bytes=2)
            self.assertEqual(response.read_sizes, [3])
            self.assertEqual(downloader.total, 3)

    def test_public_downloader_rejected_digest_bytes_consume_cumulative_budget(self):
        with self.temporary_directory() as temp:
            downloader = provision.BoundedDownloader(Path(temp), total_limit=4)
            with mock.patch.object(downloader, "_open_request", return_value=DownloadResponseFixture(b"data")):
                with self.assertRaisesRegex(provision.ProvisionError, "SHA-256 mismatch"):
                    downloader.get("https://snapshot.ubuntu.com/object", expected_sha256="0" * 64)
            self.assertEqual(downloader.total, 4)
            with mock.patch.object(downloader, "_open_request") as network:
                with self.assertRaisesRegex(provision.ProvisionError, "cumulative acquisition"):
                    downloader.get("https://snapshot.ubuntu.com/object")
                network.assert_not_called()

    def test_public_downloader_rejects_nonpositive_or_noninteger_limits_before_io(self):
        with self.temporary_directory() as temp:
            for limit in (0, -1, True, 1.5):
                root = Path(temp) / ("invalid-" + str(limit))
                with self.subTest(total_limit=limit), self.assertRaisesRegex(provision.ProvisionError, "positive integer"):
                    provision.BoundedDownloader(root, total_limit=limit)
                self.assertFalse(root.exists())
            downloader = provision.BoundedDownloader(Path(temp) / "valid", total_limit=4)
            with mock.patch.object(downloader, "_open_request") as network:
                for limit in (0, -1, True, 1.5):
                    with self.subTest(max_bytes=limit), self.assertRaisesRegex(provision.ProvisionError, "positive integer"):
                        downloader.get("https://snapshot.ubuntu.com/object", max_bytes=limit)
                network.assert_not_called()

    def test_provisioning_rejects_canonical_output_overlap_before_all_mutations(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            canary = base / "unrelated"
            canary.write_bytes(b"must remain unchanged")
            real = base / "real"
            real.mkdir()
            alias = base / "alias"
            alias.symlink_to(real, target_is_directory=True)
            tree = base / "absent/tree"
            relative = Path(os.path.relpath(tree, Path.cwd()))
            pairs = ((tree, tree), (tree, tree / "nested"), (tree / "nested", tree),
                     (relative, tree), (real / "run/rootfs", alias / "run"),
                     (alias / "run", real / "run/rootfs"),
                     (base / "missing/../absent/tree", tree))
            for index, (rootfs, output) in enumerate(pairs):
                args = provision.argparse.Namespace(contract=provision.CONTRACT_PATH,
                    workdir=base / ("work-" + str(index)), rootfs=rootfs, output=output,
                    acquisition=base / "acquisition", keyring=base / "keyring")
                with self.subTest(rootfs=rootfs, output=output), \
                        mock.patch.object(provision, "read_contract") as contract, \
                        mock.patch.object(provision, "load_candidate") as candidate, \
                        mock.patch.object(provision, "remove_optional_source_caches") as cleanup, \
                        mock.patch.object(provision, "run_checked") as bootstrap, \
                        mock.patch.object(provision.BoundedDownloader, "get") as network:
                    with self.assertRaisesRegex(provision.ProvisionError, "must be disjoint"):
                        provision._provision_rootfs_unqualified(args)
                    for action in (contract, candidate, cleanup, bootstrap, network):
                        action.assert_not_called()
                self.assertFalse(args.workdir.exists())
                self.assertFalse(rootfs.exists())
                self.assertFalse(output.exists())
                self.assertEqual(canary.read_bytes(), b"must remain unchanged")

    def test_provisioning_accepts_disjoint_siblings_and_rejects_dangling_output_link(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            args = provision.argparse.Namespace(contract=provision.CONTRACT_PATH, workdir=base / "work",
                rootfs=base / "rootfs", output=base / "output", acquisition=base / "acquisition",
                keyring=base / "keyring")
            with mock.patch.object(provision, "load_candidate", side_effect=provision.ProvisionError("fixture stop")) as candidate:
                with self.assertRaisesRegex(provision.ProvisionError, "fixture stop"):
                    provision._provision_rootfs_unqualified(args)
                candidate.assert_called_once()
            self.assertTrue(args.workdir.is_dir())
            self.assertFalse(args.rootfs.exists())
            self.assertFalse(args.output.exists())
            args.output.symlink_to(base / "missing")
            with mock.patch.object(provision, "load_candidate") as candidate:
                with self.assertRaisesRegex(provision.ProvisionError, "paths must not exist"):
                    provision._provision_rootfs_unqualified(args)
                candidate.assert_not_called()

    def test_rootfs_directory_creation_pins_identity_and_refuses_same_uid_path_replacement(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs = (base / "rootfs").resolve()
            retained = base / "retained-rootfs"
            canary = base / "unintended-root-owned-tree"
            canary.mkdir()
            (canary / "canary").write_bytes(b"must remain untouched")
            observed = []

            def create_fixture(command, timeout=None):
                self.assertEqual(command[0], "sudo")
                if provision.ROOTFS_PARENT_RESTORE_PROGRAM in command:
                    return mock.Mock(stdout="")
                parent_path, name = command[6:8]
                parent_fd = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.mkdir(name, dir_fd=parent_fd)
                    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                         dir_fd=parent_fd)
                    try:
                        metadata = os.fstat(descriptor)
                    finally:
                        os.close(descriptor)
                finally:
                    os.close(parent_fd)
                observed.append(tuple(command[:2]))
                return mock.Mock(stdout=f"{metadata.st_dev}:{metadata.st_ino}\n")

            with mock.patch.object(provision, "run_checked", side_effect=create_fixture):
                binding = provision.create_pinned_rootfs_directory(rootfs)
            try:
                binding.require_path_binding()
                rootfs.rename(retained)
                rootfs.symlink_to(canary, target_is_directory=True)
                with self.assertRaisesRegex(provision.ProvisionError, "pathname binding changed"):
                    binding.require_path_binding()
                (binding.descriptor_path / "held-only").write_bytes(b"retained inode")
                self.assertEqual((retained / "held-only").read_bytes(), b"retained inode")
                self.assertEqual((canary / "canary").read_bytes(), b"must remain untouched")
                self.assertFalse((canary / "held-only").exists())
            finally:
                binding.close()
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0][0], "sudo")

            rootfs.unlink()
            (retained / "held-only").unlink()
            retained.rename(rootfs)
            rootfs.rmdir()
            def replace_before_pin(command, timeout=None):
                result = create_fixture(command, timeout=timeout)
                if provision.ROOTFS_PARENT_RESTORE_PROGRAM in command:
                    return result
                rootfs.rename(retained)
                rootfs.symlink_to(canary, target_is_directory=True)
                return result
            with mock.patch.object(provision, "run_checked", side_effect=replace_before_pin):
                with self.assertRaisesRegex(provision.ProvisionError, "privileged rootfs directory"):
                    provision.create_pinned_rootfs_directory(rootfs)
            self.assertEqual((canary / "canary").read_bytes(), b"must remain untouched")
            self.assertFalse((canary / "held-only").exists())

    def test_rootfs_directory_creation_recovers_parent_after_invalid_helper_result(self):
        with self.temporary_directory() as temp:
            parent = Path(temp)
            rootfs = (parent / "rootfs").resolve()
            calls = []

            def invalid_result_then_restore(command, timeout=None):
                calls.append(command)
                if provision.ROOTFS_DIRECTORY_CREATE_PROGRAM in command:
                    rootfs.mkdir()
                    return mock.Mock(stdout="invalid\n")
                self.assertIn(provision.ROOTFS_PARENT_RESTORE_PROGRAM, command)
                return mock.Mock(stdout="")

            with mock.patch.object(provision, "run_checked", side_effect=invalid_result_then_restore):
                with self.assertRaisesRegex(provision.ProvisionError, "invalid directory identity"):
                    provision.create_pinned_rootfs_directory(rootfs)
            self.assertEqual(len(calls), 2)
            self.assertIn(provision.ROOTFS_PARENT_RESTORE_PROGRAM, calls[1])
            self.assertEqual(calls[1][14:16], ["-1", "-1"])

    def run_authority_helper_fixture(self, program, arguments, states, *, fail_mkdir=False,
                                     fail_marker_retirement=False):
        """Execute the real helper with real FDs and simulated privileged metadata."""
        real_fstat = os.fstat
        operations = []

        def metadata(descriptor):
            original = real_fstat(descriptor)
            values = list(original)
            uid, gid, mode = states[(original.st_dev, original.st_ino)]
            values[0] = stat.S_IFMT(original.st_mode) | mode
            values[4], values[5] = uid, gid
            return os.stat_result(values)

        def change_owner(descriptor, uid, gid):
            original = real_fstat(descriptor)
            identity = (original.st_dev, original.st_ino)
            operations.append(("chown", identity, uid, gid))
            if fail_marker_retirement and stat.S_ISREG(original.st_mode) and uid != 0:
                raise OSError("marker retirement failed")
            states[identity] = (uid, gid, states[identity][2])

        def change_mode(descriptor, mode):
            original = real_fstat(descriptor)
            identity = (original.st_dev, original.st_ino)
            operations.append(("chmod", identity, mode))
            uid, gid, _ = states[identity]
            states[identity] = (uid, gid, mode)

        with mock.patch.object(sys, "argv", ["helper", *map(str, arguments)]), \
                mock.patch.object(os, "fstat", side_effect=metadata), \
                mock.patch.object(os, "fchown", side_effect=change_owner), \
                mock.patch.object(os, "fchmod", side_effect=change_mode), \
                mock.patch.object(os, "mkdir", side_effect=OSError("injected creation failure") if fail_mkdir else None):
            try:
                exec(compile(program, "<rootfs-authority-helper>", "exec"), {})
            except (OSError, SystemExit) as error:
                return operations, error
        return operations, None

    def test_failed_creator_retires_marker_before_release_and_stale_helpers_cannot_unlock_successor(self):
        with self.temporary_directory() as temp:
            parent = Path(temp).resolve()
            marker = parent / "marker"
            marker.touch(mode=0o600)
            parent_stat, marker_stat = parent.stat(), marker.stat()
            parent_id = (parent_stat.st_dev, parent_stat.st_ino)
            marker_id = (marker_stat.st_dev, marker_stat.st_ino)
            expected_parent = (*parent_id, 12345, 12345, 0o700, stat.S_IFDIR)
            expected_marker = (*marker_id, 12345, 12345, 0o600, stat.S_IFREG)
            create_args = [parent, "rootfs", marker, *expected_parent, *expected_marker]
            recover_args = [parent, "rootfs", marker, *parent_id, 12345, 12345, 0o700,
                            -1, -1, *expected_marker]
            for retirement_fails in (False, True):
                with self.subTest(retirement_fails=retirement_fails):
                    states = {parent_id: (12345, 12345, 0o700), marker_id: (12345, 12345, 0o600)}
                    operations, error = self.run_authority_helper_fixture(
                        provision.ROOTFS_DIRECTORY_CREATE_PROGRAM, create_args, states,
                        fail_mkdir=True, fail_marker_retirement=retirement_fails)
                    self.assertIsInstance(error, OSError)
                    if retirement_fails:
                        self.assertEqual(states[parent_id], (0, 12345, 0o710))
                        self.assertNotIn(("chown", parent_id, 12345, 12345), operations)
                        continue
                    self.assertEqual(states[marker_id], (12345, 12345, 0o600))
                    self.assertLess(operations.index(("chmod", marker_id, 0o600)),
                                    operations.index(("chown", parent_id, 12345, 12345)))
                    # A second attempt now holds the parent; the first attempt's
                    # delayed creation and recovery must both leave it locked.
                    states[parent_id] = (0, 12345, 0o710)
                    for program, arguments in ((provision.ROOTFS_DIRECTORY_CREATE_PROGRAM, create_args),
                                               (provision.ROOTFS_PARENT_RESTORE_PROGRAM, recover_args)):
                        operations, error = self.run_authority_helper_fixture(program, arguments, states)
                        self.assertIsInstance(error, SystemExit)
                        self.assertNotEqual(error.code, 0)
                        self.assertEqual(operations, [])
                        self.assertEqual(states[parent_id], (0, 12345, 0o710))

    def test_parent_recovery_refuses_unknown_marker_without_mutating_authority(self):
        with self.temporary_directory() as temp:
            parent = Path(temp).resolve()
            marker = parent / "marker"
            marker.touch(mode=0o600)
            parent_stat, marker_stat = parent.stat(), marker.stat()
            parent_id = (parent_stat.st_dev, parent_stat.st_ino)
            marker_id = (marker_stat.st_dev, marker_stat.st_ino)
            states = {parent_id: (0, 12345, 0o710), marker_id: (12345, 12345, 0o600)}
            arguments = [parent, "rootfs", marker, *parent_id, 12345, 12345, 0o700, -1, -1,
                         *marker_id, 12345, 12345, 0o600, stat.S_IFREG]
            operations, error = self.run_authority_helper_fixture(
                provision.ROOTFS_PARENT_RESTORE_PROGRAM, arguments, states)
            self.assertIsInstance(error, SystemExit)
            self.assertIn("authority changed", str(error))
            self.assertEqual(operations, [])
            self.assertEqual(states[parent_id], (0, 12345, 0o710))

    def test_recovery_failure_closes_actual_parent_marker_and_root_descriptors(self):
        with self.temporary_directory() as temp:
            rootfs = (Path(temp) / "rootfs").resolve()
            descriptors = []
            real_open = os.open

            def record_open(*args, **kwargs):
                descriptor = real_open(*args, **kwargs)
                descriptors.append(descriptor)
                return descriptor

            def create_then_fail_recovery(command, timeout=None):
                if provision.ROOTFS_DIRECTORY_CREATE_PROGRAM in command:
                    rootfs.mkdir()
                    metadata = rootfs.stat()
                    return mock.Mock(stdout=f"{metadata.st_dev}:{metadata.st_ino}\n")
                raise provision.ProvisionError("injected recovery failure")

            with mock.patch.object(provision, "run_checked", side_effect=create_then_fail_recovery), \
                    mock.patch.object(os, "open", side_effect=record_open):
                with self.assertRaisesRegex(provision.ProvisionError, "could not restore rootfs parent authority"):
                    provision.create_pinned_rootfs_directory(rootfs)
            self.assertEqual(len(descriptors), 3)
            for descriptor in descriptors:
                with self.assertRaises(OSError) as caught:
                    os.fstat(descriptor)
                self.assertEqual(caught.exception.errno, errno.EBADF)
            self.assertEqual(list(rootfs.parent.glob(".clang1813-rootfs-authority-*")), [])

    def test_provisioning_rejects_output_containing_workdir_before_all_mutations(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            canary = base / "unrelated"
            canary.write_bytes(b"must remain unchanged")
            real = base / "real"
            real.mkdir()
            alias = base / "alias"
            alias.symlink_to(real, target_is_directory=True)
            output = base / "absent/run"
            pairs = ((output, output), (output, output / "work"),
                     (Path(os.path.relpath(output, Path.cwd())), output / "work"),
                     (real / "run", alias / "run/work"), (alias / "run", real / "run/work"),
                     (base / "missing/../absent/run", output / "work"),
                     (output, base / "missing/../absent/run/work"))
            for index, (output, workdir) in enumerate(pairs):
                args = provision.argparse.Namespace(contract=provision.CONTRACT_PATH,
                    workdir=workdir, rootfs=base / ("rootfs-" + str(index)), output=output,
                    acquisition=base / "acquisition", keyring=base / "keyring")
                with self.subTest(output=output, workdir=workdir), \
                        mock.patch.object(provision, "read_contract") as contract, \
                        mock.patch.object(Path, "mkdir") as mkdir, \
                        mock.patch.object(provision, "load_candidate") as candidate, \
                        mock.patch.object(provision, "remove_optional_source_caches") as cleanup, \
                        mock.patch.object(provision, "run_checked") as bootstrap, \
                        mock.patch.object(provision.BoundedDownloader, "get") as network:
                    with self.assertRaisesRegex(provision.ProvisionError, "must not equal or contain the work directory"):
                        provision._provision_rootfs_unqualified(args)
                    for action in (contract, mkdir, candidate, cleanup, bootstrap, network):
                        action.assert_not_called()
                self.assertFalse(workdir.exists())
                self.assertFalse(args.rootfs.exists())
                self.assertFalse(output.exists())
                self.assertEqual(canary.read_bytes(), b"must remain unchanged")

    def test_provisioning_accepts_absent_output_nested_under_workdir(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            args = provision.argparse.Namespace(contract=provision.CONTRACT_PATH, workdir=base / "work",
                rootfs=base / "rootfs", output=base / "work/output", acquisition=base / "acquisition",
                keyring=base / "keyring")
            with mock.patch.object(provision, "load_candidate", side_effect=provision.ProvisionError("fixture stop")) as candidate:
                with self.assertRaisesRegex(provision.ProvisionError, "fixture stop"):
                    provision._provision_rootfs_unqualified(args)
                candidate.assert_called_once()
            self.assertTrue(args.workdir.is_dir())
            self.assertFalse(args.rootfs.exists())
            self.assertFalse(args.output.exists())

    def test_rootfs_tar_output_accepts_relative_parent_and_rejects_escape(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            def identity(path):
                payload = path.read_bytes()
                return {"bytes": len(payload), "sha256": provision.sha256(payload)}
            original_stat = provision.os.stat
            original_fstat = provision.os.fstat
            execute_patch = mock.patch.object(
                provision, "run_checked", side_effect=self.simulate_privileged_rootfs_tar_publication,
            )
            stat_patch = mock.patch.object(
                provision.os, "stat", side_effect=self.report_fixture_publications_as_root_owned(original_stat),
            )
            fstat_patch = mock.patch.object(
                provision.os, "fstat", side_effect=self.report_fixture_descriptors_as_root_owned(original_fstat),
            )
            execute_patch.start()
            stat_patch.start()
            fstat_patch.start()
            previous_cwd = Path.cwd()
            try:
                os.chdir(base)
                output = Path("run1")
                output.mkdir()
                source = base / "work/rootfs.tar"
                source.parent.mkdir()
                source.write_bytes(b"verified rootfs tar")
                destination = output / "rootfs.tar"
                provision.publish_rootfs_tar(source, output, destination, identity(source))
                self.assertFalse(source.exists())
                self.assertEqual(destination.read_bytes(), b"verified rootfs tar")

                source = base / "work/rootfs-absolute.tar"
                source.write_bytes(b"absolute spelling")
                absolute_output = output.resolve(strict=True)
                absolute_destination = absolute_output / "rootfs-absolute.tar"
                provision.publish_rootfs_tar(source, absolute_output, absolute_destination, identity(source))
                self.assertFalse(source.exists())
                self.assertEqual(absolute_destination.read_bytes(), b"absolute spelling")

                alias = base / "output-alias"
                alias.symlink_to(output, target_is_directory=True)
                source = base / "work/rootfs-alias.tar"
                source.write_bytes(b"directory alias spelling")
                provision.publish_rootfs_tar(source, output, alias / "rootfs-alias.tar", identity(source))
                self.assertFalse(source.exists())
                self.assertEqual((output / "rootfs-alias.tar").read_bytes(), b"directory alias spelling")

                existing = output / "existing.tar"
                existing.write_bytes(b"existing destination")
                source = base / "work/rootfs-existing.tar"
                source.write_bytes(b"must remain before existing refusal")
                with self.assertRaisesRegex(provision.ProvisionError, "must not already exist"):
                    provision.publish_rootfs_tar(source, output, existing, identity(source))
                self.assertEqual(source.read_bytes(), b"must remain before existing refusal")
                self.assertEqual(existing.read_bytes(), b"existing destination")

                target = output / "symlink-target.tar"
                target.write_bytes(b"symlink target")
                destination_link = output / "symlink-destination.tar"
                destination_link.symlink_to(target.name)
                source = base / "work/rootfs-symlink.tar"
                source.write_bytes(b"must remain before symlink refusal")
                with self.assertRaisesRegex(provision.ProvisionError, "must not already exist"):
                    provision.publish_rootfs_tar(source, output, destination_link, identity(source))
                self.assertEqual(source.read_bytes(), b"must remain before symlink refusal")
                self.assertEqual(target.read_bytes(), b"symlink target")

                source = base / "work/rootfs-escape.tar"
                source.write_bytes(b"must remain on refusal")
                (base / "outside").mkdir()
                with self.assertRaisesRegex(provision.ProvisionError, "canonical run output directory"):
                    provision.publish_rootfs_tar(
                        source, output, base / "outside/rootfs.tar", identity(source),
                    )
                self.assertEqual(source.read_bytes(), b"must remain on refusal")
            finally:
                os.chdir(previous_cwd)
                fstat_patch.stop()
                stat_patch.stop()
                execute_patch.stop()

    def test_rootfs_tar_publication_holds_authenticated_bytes_across_source_replacement(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            work = base / "work"
            output = base / "output"
            work.mkdir()
            output.mkdir()
            source = work / "rootfs.tar"
            original = b"authenticated deterministic rootfs tar"
            attacker = b"same-uid replacement must not be published"
            source.write_bytes(original)
            expected = {"bytes": len(original), "sha256": provision.sha256(original)}
            destination = output / "rootfs.tar"
            original_stat = provision.os.stat
            original_fstat = provision.os.fstat
            with mock.patch.object(
                    provision, "run_checked", side_effect=self.simulate_privileged_rootfs_tar_publication), \
                    mock.patch.object(
                        provision.os, "stat",
                        side_effect=self.report_fixture_publications_as_root_owned(original_stat)), \
                    mock.patch.object(
                        provision.os, "fstat",
                        side_effect=self.report_fixture_descriptors_as_root_owned(original_fstat)):
                provision.publish_rootfs_tar(source, output, destination, expected)
            self.assertEqual(destination.read_bytes(), original)
            self.assertFalse(source.exists())

            replaced = work / "replaced.tar"
            replaced.write_bytes(original)
            refused_replacement = output / "replaced.tar"
            def replace_before_privileged_copy(command, timeout=None):
                replaced.write_bytes(attacker)
                return self.simulate_privileged_rootfs_tar_publication(command)
            with mock.patch.object(provision, "run_checked", side_effect=replace_before_privileged_copy):
                with self.assertRaisesRegex(provision.ProvisionError, "differs from its recorded identity"):
                    provision.publish_rootfs_tar(replaced, output, refused_replacement, expected)
            self.assertFalse(refused_replacement.exists())
            self.assertEqual(replaced.read_bytes(), attacker)

            changed = work / "changed.tar"
            changed.write_bytes(attacker)
            refused = output / "refused.tar"
            with mock.patch.object(
                    provision, "run_checked", side_effect=self.simulate_privileged_rootfs_tar_publication):
                with self.assertRaisesRegex(provision.ProvisionError, "differs from its recorded identity"):
                    provision.publish_rootfs_tar(changed, output, refused, expected)
            self.assertFalse(refused.exists())
            self.assertEqual(changed.read_bytes(), attacker)

            substituted_source = work / "substituted-source.tar"
            substituted_source.write_bytes(original)
            substituted = output / "substituted.tar"
            same_size_attacker = b"x" * len(original)
            original_stat = provision.os.stat
            original_fstat = provision.os.fstat

            def substitute_after_privileged_publication(command, timeout=None):
                result = self.simulate_privileged_rootfs_tar_publication(command, timeout)
                before = substituted.stat()
                replacement = output / "substituted-staged.tar"
                replacement.write_bytes(same_size_attacker)
                replacement.chmod(0o444)
                staged = replacement.stat()
                self.assertNotEqual((before.st_dev, before.st_ino), (staged.st_dev, staged.st_ino))
                os.replace(replacement, substituted)
                return result

            with mock.patch.object(
                    provision, "run_checked", side_effect=substitute_after_privileged_publication), \
                    mock.patch.object(
                        provision.os, "stat",
                        side_effect=self.report_fixture_publications_as_root_owned(original_stat)), \
                    mock.patch.object(
                        provision.os, "fstat",
                        side_effect=self.report_fixture_descriptors_as_root_owned(original_fstat)):
                with self.assertRaisesRegex(provision.ProvisionError, "did not retain the privileged inode"):
                    provision.publish_rootfs_tar(substituted_source, output, substituted, expected)
            self.assertEqual(substituted.read_bytes(), same_size_attacker)
            self.assertEqual(substituted_source.read_bytes(), original)

            tampered_source = work / "same-inode-source.tar"
            tampered_source.write_bytes(original)
            tampered = output / "same-inode.tar"

            def tamper_after_privileged_publication(command, timeout=None):
                result = self.simulate_privileged_rootfs_tar_publication(command, timeout)
                before = tampered.stat()
                tampered.chmod(0o644)
                with tampered.open("r+b") as stream:
                    stream.write(same_size_attacker)
                tampered.chmod(0o444)
                after = tampered.stat()
                self.assertEqual((before.st_dev, before.st_ino, before.st_size),
                                 (after.st_dev, after.st_ino, after.st_size))
                return result

            with mock.patch.object(
                    provision, "run_checked", side_effect=tamper_after_privileged_publication), \
                    mock.patch.object(
                        provision.os, "stat",
                        side_effect=self.report_fixture_publications_as_root_owned(original_stat)), \
                    mock.patch.object(
                        provision.os, "fstat",
                        side_effect=self.report_fixture_descriptors_as_root_owned(original_fstat)):
                with self.assertRaisesRegex(provision.ProvisionError, "verified rootfs tar publication bytes changed"):
                    provision.publish_rootfs_tar(tampered_source, output, tampered, expected)
            self.assertEqual(tampered.read_bytes(), same_size_attacker)
            self.assertEqual(tampered_source.read_bytes(), original)

    def test_provisioning_rejects_workdir_equal_or_beneath_rootfs_before_all_mutations(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            real = base / "real"
            real.mkdir()
            alias = base / "alias"
            alias.symlink_to(real, target_is_directory=True)
            root = base / "absent/rootfs"
            pairs = ((root, root), (root, root / "work"),
                     (Path(os.path.relpath(root, Path.cwd())), root / "work"),
                     (real / "rootfs", alias / "rootfs/work"), (alias / "rootfs", real / "rootfs/work"),
                     (base / "missing/../absent/rootfs", root / "work"))
            for index, (rootfs, workdir) in enumerate(pairs):
                args = provision.argparse.Namespace(contract=provision.CONTRACT_PATH, rootfs=rootfs,
                    workdir=workdir, output=base / ("output-" + str(index)), acquisition=base / "acquisition",
                    keyring=base / "keyring")
                with self.subTest(rootfs=rootfs, workdir=workdir), mock.patch.object(Path, "mkdir") as mkdir, \
                        mock.patch.object(provision, "read_contract") as contract, \
                        mock.patch.object(provision, "run_checked") as bootstrap:
                    with self.assertRaisesRegex(provision.ProvisionError, "rootfs must not equal or contain"):
                        provision._provision_rootfs_unqualified(args)
                    mkdir.assert_not_called()
                    contract.assert_not_called()
                    bootstrap.assert_not_called()
                self.assertFalse(rootfs.exists())
                self.assertFalse(workdir.exists())
    def test_acquisition_status_is_read_only_and_cannot_be_enabled_by_environment(self):
        stdout = io.StringIO()
        with mock.patch.dict(provision.os.environ, {"UPSTREAM_SIGNATURE_ACCESS_ENABLED": "true",
                                                   "INPUT_ACQUISITION_ENABLED": "true",
                                                   "INPUT_MODE": "full-qualification"}), \
                mock.patch.object(provision.sys, "stdout", stdout), \
                mock.patch.object(provision, "read_contract") as contract, \
                mock.patch.object(provision.BoundedDownloader, "__init__") as downloader, \
                mock.patch.object(provision, "atomic_write") as write, \
                mock.patch.object(Path, "mkdir") as mkdir:
            self.assertEqual(provision.main(["acquisition-status"]), 0)
        status = json.loads(stdout.getvalue())
        self.assertEqual(status, {
            "schemaVersion": 1, "scope": "acquisition-prerequisite-status-only",
            "acquisitionEnabled": False, "acquisitionStatus": "paused",
            "nativeQualification": "skipped", "acceptanceStatus": "incomplete", "qualified": False,
            "reason": provision.ACQUISITION_PAUSE_REASON,
        })
        contract.assert_not_called()
        downloader.assert_not_called()
        write.assert_not_called()
        mkdir.assert_not_called()
        self.assertEqual(stdout.getvalue().encode(), provision.canonical_json(status))

    def test_acquisition_status_has_no_contract_output_or_enable_override(self):
        for extra in (["--contract", "unreviewed.json"], ["--output", "unrequested-output"], ["--enable"]):
            with self.subTest(extra=extra), mock.patch.object(provision.sys, "stderr", io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    provision.main(["acquisition-status", *extra])
                self.assertEqual(error.exception.code, 2)

    def test_direct_acquire_cli_fails_with_status_reason_before_reading_contract_or_creating_output(self):
        with self.temporary_directory() as temp:
            output = Path(temp) / "acquisition"
            stderr = io.StringIO()
            with mock.patch.dict(provision.os.environ, {"UPSTREAM_SIGNATURE_ACCESS_ENABLED": "true"}), \
                    mock.patch.object(provision.sys, "stderr", stderr), \
                    mock.patch.object(provision, "read_contract") as contract, \
                    mock.patch.object(provision.BoundedDownloader, "__init__") as downloader:
                self.assertEqual(provision.main([
                    "acquire", "--output", str(output), "--contract", str(Path(temp) / "missing-contract.json"),
                ]), 1)
            self.assertEqual(stderr.getvalue(), "provisioning failed: " + provision.acquisition_status()["reason"] + "\n")
            contract.assert_not_called()
            downloader.assert_not_called()
            self.assertFalse(output.exists())

    def test_upstream_signature_pause_rejects_exact_and_changed_urls_before_download(self):
        with self.temporary_directory() as temp:
            upstream = self.contract["profile"]["upstream"]
            signature_urls = (
                upstream["signatureUrl"],
                provision.PAUSED_UPSTREAM_SIGNATURE_URL + "?download=1",
                "https://mirror.example.invalid/llvm-project-18.1.3.src.tar.xz.sig",
            )
            for index, signature_url in enumerate(signature_urls):
                with self.subTest(signature_url=signature_url):
                    contract = {
                        **self.contract,
                        "profile": {
                            **self.contract["profile"],
                            "upstream": {**upstream, "signatureUrl": signature_url},
                        },
                    }
                    output = Path(temp) / f"acquisition-{index}"
                    with mock.patch.object(provision.BoundedDownloader, "__init__") as init, \
                            mock.patch.object(provision.BoundedDownloader, "get") as get:
                        with self.assertRaisesRegex(provision.ProvisionError, "no acquisition requests were made") as error:
                            provision.acquire_candidate(contract, output, Path(temp) / "missing-keyring.gpg")
                    self.assertEqual(str(error.exception), provision.acquisition_status()["reason"])
                    init.assert_not_called()
                    get.assert_not_called()
                    self.assertFalse(output.exists())

    def test_source_package_identity_requires_unambiguous_syntax(self):
        self.assertEqual(provision.package_source_identity({"Source": "llvm-toolchain-18 (18.1.3-1ubuntu1)"}),
                         ("llvm-toolchain-18", "18.1.3-1ubuntu1"))
        with self.assertRaises(provision.ProvisionError):
            provision.package_source_identity({"Source": "llvm toolchain"})

    def test_safe_upstream_extractor_rejects_parent_path(self):
        with self.temporary_directory() as temp:
            archive = Path(temp) / "malicious.tar.xz"
            with tarfile.open(archive, mode="w:xz") as output:
                member = tarfile.TarInfo("llvm-project/../../escape")
                member.size = 1
                output.addfile(member, io.BytesIO(b"x"))
            with self.assertRaises(provision.ProvisionError):
                provision.safe_extract_xz_tar(archive, Path(temp) / "out")

    def test_langoptions_inventory_rejects_family_count_drift(self):
        report = {"compilerVersion": "18.1.3", "target": "x86_64-pc-linux-gnu",
                  "callingConventions": self.contract["langOptions"]["callingConventions"],
                  "apiChecks": self.contract["langOptions"]["apiChecks"]}
        inventory = {"generatedFields": 297, "familyCounts": self.contract["langOptions"]["familyCounts"],
                     "manualFields": self.contract["langOptions"]["manualFields"],
                     "manualFieldsCount": 28}
        with self.assertRaises(provision.ProvisionError):
            provision.validate_probe_report(report, inventory, self.contract)

    def test_standalone_probe_report_binds_pinned_fixture_and_rejects_missing_or_changed_bytes(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            probe = self.valid_build_record()["probe"]
            inventory = {**probe, "manualFieldsCount": self.contract["langOptions"]["manualFieldsCount"]}
            report_path, inventory_path = base / "raw.json", base / "inventory.json"
            report_path.write_bytes(provision.canonical_json(probe))
            inventory_path.write_bytes(provision.canonical_json(inventory))
            source, binary = base / "source.cpp", base / "probe"
            source.write_bytes(b"inert standalone source")
            binary.write_bytes(b"inert standalone binary")
            pinned = provision.RECIPE_FILES["fixtureSha256"].read_bytes()
            selected = base / "selected.cpp"
            selected.write_bytes(pinned)
            for label in ("default", "explicit", "changed", "missing"):
                with self.subTest(label=label):
                    output = base / (label + ".json")
                    argv = ["verify-probe", "--report", str(report_path), "--inventory", str(inventory_path),
                            "--source", str(source), "--binary", str(binary), "--output", str(output)]
                    if label != "default":
                        argv.extend(["--fixture", str(selected)])
                    if label == "changed":
                        selected.write_bytes(bytes([pinned[0] ^ 1]) + pinned[1:])
                    elif label == "missing":
                        selected.unlink()
                    args = provision.build_parser().parse_args(argv)
                    if label in ("changed", "missing"):
                        with self.assertRaises(provision.ProvisionError):
                            args.run(args)
                        self.assertFalse(output.exists())
                    else:
                        self.assertEqual(args.run(args), 0)
                        expected = provision.validate_probe_report(probe, inventory, self.contract)
                        expected.update(sourceSha256=provision.sha256(source.read_bytes()),
                                        binarySha256=provision.sha256(binary.read_bytes()),
                                        fixtureSha256=provision.sha256(pinned))
                        self.assertEqual(json.loads(output.read_bytes()), expected)

    def test_probe_report_rejects_real_22_1_6_identity(self):
        report = {"compilerVersion": "22.1.6", "target": "x86_64-pc-linux-gnu",
                  "callingConventions": self.contract["langOptions"]["callingConventions"],
                  "apiChecks": self.contract["langOptions"]["apiChecks"],
                  "runtimeLangOptionsChecks": self.contract["langOptions"]["runtimeChecks"],
                  "macroObservations": {"expansionCount": 1, "macroInfoChecks": 1,
                                         "nonBuiltinClassifications": 1}}
        inventory = {"generatedFields": 298, "familyCounts": self.contract["langOptions"]["familyCounts"],
                     "manualFields": self.contract["langOptions"]["manualFields"],
                     "manualFieldsCount": 28,
                     "inventoryEvidence": self.contract["langOptions"]["inventoryEvidence"]}
        with self.assertRaisesRegex(provision.ProvisionError, "compiler version or target mismatch"):
            provision.validate_probe_report(report, inventory, self.contract)

    def test_probe_report_rejects_missing_runtime_macro_observations(self):
        report = {"compilerVersion": "18.1.3", "target": "x86_64-pc-linux-gnu",
                  "callingConventions": self.contract["langOptions"]["callingConventions"],
                  "apiChecks": self.contract["langOptions"]["apiChecks"],
                  "runtimeLangOptionsChecks": self.contract["langOptions"]["runtimeChecks"],
                  "macroObservations": {"expansionCount": 1, "macroInfoChecks": 1,
                                         "nonBuiltinClassifications": 0}}
        inventory = {"generatedFields": 298, "familyCounts": self.contract["langOptions"]["familyCounts"],
                     "manualFields": self.contract["langOptions"]["manualFields"],
                     "manualFieldsCount": 28,
                     "inventoryEvidence": self.contract["langOptions"]["inventoryEvidence"]}
        with self.assertRaisesRegex(provision.ProvisionError, "macro expansion and MacroInfo classification"):
            provision.validate_probe_report(report, inventory, self.contract)

    def test_runtime_discovery_refuses_unresolved_dependency(self):
        with mock.patch.object(provision, "run_probe_sandboxed", return_value="libmissing.so => not found\n"):
            with self.assertRaisesRegex(provision.ProvisionError, "runtime dependency is unresolved"):
                provision.runtime_dependencies(ROOT / "build/inert-never-executed", list(provision.FRONTEND_RUNTIME_ROOTS), self.contract)

    def test_runtime_and_driver_replay_refuse_without_reviewed_sandbox(self):
        with mock.patch.object(provision, "rootfs_run") as chroot, \
                mock.patch.object(provision, "run_checked") as child:
            for operation in (provision.verify_recorded_driver_identities, provision.verify_recorded_runtime_closure):
                with self.subTest(operation=operation.__name__), self.assertRaisesRegex(
                        provision.ProvisionError, "no reviewed unprivileged"):
                    operation(ROOT / "build/inert-never-executed", self.valid_build_record(), self.contract)
            chroot.assert_not_called()
            child.assert_not_called()

    def test_probe_runner_fails_closed_before_unbounded_chroot_or_subprocess(self):
        with mock.patch.object(provision, "rootfs_run") as chroot, \
                mock.patch.object(provision, "run_checked") as unbounded, \
                mock.patch.object(provision.subprocess, "run") as child:
            with self.assertRaisesRegex(provision.ProvisionError, "CPU/RSS/process/disk/output/wall-time"):
                provision.run_probe_sandboxed(
                    Path("/candidate-rootfs"),
                    [provision.PROBE_BINARY_IN_ROOT, provision.PROBE_FIXTURE_IN_ROOT],
                    self.contract,
                )
        chroot.assert_not_called()
        unbounded.assert_not_called()
        child.assert_not_called()

    def test_build_record_rejects_missing_root_package(self):
        record = self.valid_build_record()
        record["packages"] = [row for row in record["packages"] if row["name"] != "libclang-18-dev"]
        record["downloadedPackages"] = [row for row in record["downloadedPackages"] if row["name"] != "libclang-18-dev"]
        with self.assertRaisesRegex(provision.ProvisionError, "missing the pinned package"):
            provision.validate_build_record(record, self.contract)

    def test_build_record_rejects_wrong_root_package_version(self):
        record = self.valid_build_record()
        for rows in (record["packages"], record["downloadedPackages"]):
            next(row for row in rows if row["name"] == "clang-18")["version"] = "1:18.1.8-1ubuntu1"
        with self.assertRaisesRegex(provision.ProvisionError, "missing the pinned package"):
            provision.validate_build_record(record, self.contract)

    def test_build_record_rejects_non_executable_driver_mode(self):
        record = self.valid_build_record()
        record["tools"][0]["mode"] = "0444"
        with self.assertRaisesRegex(provision.ProvisionError, "tool executable byte identity"):
            provision.validate_build_record(record, self.contract)

    def test_build_record_probe_source_digest_must_match_recipe(self):
        record = self.valid_build_record()
        record["probe"]["sourceSha256"] = "0" * 64
        with self.assertRaisesRegex(provision.ProvisionError, "probe source digest differs from its recipe"):
            provision.validate_build_record(record, self.contract)

    def test_build_record_rejects_downloaded_package_digest_drift(self):
        record = self.valid_build_record()
        record["downloadedPackages"][0]["sha256"] = "b" * 64
        with self.assertRaisesRegex(provision.ProvisionError, "differs from the installed signed package"):
            provision.validate_build_record(record, self.contract)

    def test_build_record_package_closure_binds_every_tuple_to_signed_metadata(self):
        record = self.valid_build_record()
        signed = provision.package_metadata_map(signed_package_rows_for_fixture(record))
        installed_keys = {
            (row["name"], row["version"], row["architecture"]) for row in record["packages"]
        }
        provision.validate_record_package_metadata(record, signed, installed_keys)

        bootstrap = next(row for row in record["packages"] if row["name"] == "ca-certificates")
        for field, value in (
                ("name", "ca-certificates-forged"), ("version", "0:0"), ("architecture", "amd64"),
                ("suite", "noble-security"), ("component", "universe"),
                ("file", "pool/main/c/ca-certificates/forged.deb"), ("bytes", 2), ("sha256", "f" * 64)):
            changed = json.loads(json.dumps(record))
            row = next(item for item in changed["packages"] if item["name"] == "ca-certificates")
            row[field] = value
            changed_keys = {
                (item["name"], item["version"], item["architecture"]) for item in changed["packages"]
            }
            with self.subTest(field=field), self.assertRaises(provision.ProvisionError):
                provision.validate_record_package_metadata(changed, signed, changed_keys)

        omitted = json.loads(json.dumps(record))
        omitted["packages"] = [row for row in omitted["packages"] if row["name"] != "ca-certificates"]
        with self.assertRaisesRegex(provision.ProvisionError, "differs from the installed rootfs"):
            provision.validate_record_package_metadata(omitted, signed, installed_keys)
        added = json.loads(json.dumps(record))
        extra = dict(bootstrap, name="unindexed-bootstrap-package")
        added["packages"].append(extra)
        added_keys = installed_keys | {(extra["name"], extra["version"], extra["architecture"])}
        with self.assertRaisesRegex(provision.ProvisionError, "differs from signed Packages metadata"):
            provision.validate_record_package_metadata(added, signed, added_keys)

    def test_build_record_rejects_missing_or_malformed_source_inventory_digests(self):
        for field in ("definitionSha256", "headerSha256"):
            for omit in (True, False):
                with self.subTest(field=field, omit=omit):
                    record = self.valid_build_record()
                    if omit:
                        record["probe"].pop(field)
                    else:
                        record["probe"][field] = "not-a-sha256"
                    with self.assertRaisesRegex(provision.ProvisionError, r"checked-in schema.*probe"):
                        provision.validate_build_record(record, self.contract)

    def langoptions_definition_fixture(self, base):
        definitions = []
        serial = 0
        for family, count in self.contract["langOptions"]["familyCounts"].items():
            for _ in range(count):
                name = "C99" if serial == 0 else f"Field{serial}"
                definitions.append(f"{family}({name}, x)\n")
                serial += 1
        definition = base / "LangOptions.def"
        definition.write_text("".join(definitions), encoding="utf-8")
        return definition

    def test_langoptions_source_audit_accepts_exact_pinned_inventory(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            definition = self.langoptions_definition_fixture(base)
            header = base / "LangOptions.h"
            members = "\n".join(f"  int {name};" for name in self.contract["langOptions"]["manualFields"])
            header.write_text(
                "class LangOptions : public LangOptionsBase {\npublic:\n" + members +
                "\n  void localMethod() { int localOnly; }\n  struct Nested { int nestedOnly; };\n};\n"
                "class Unrelated { int unrelatedOnly; };\n", encoding="utf-8")
            inventory = provision.audit_langoptions(definition, header, self.contract)
            self.assertEqual(inventory["generatedFields"], 298)
            self.assertEqual(inventory["inventoryEvidence"], self.contract["langOptions"]["inventoryEvidence"])
            self.assertEqual(inventory["manualFieldsCount"], 28)
            report = {
                "compilerVersion": "18.1.3",
                "target": "x86_64-pc-linux-gnu",
                "callingConventions": self.contract["langOptions"]["callingConventions"],
                "apiChecks": self.contract["langOptions"]["apiChecks"],
                "runtimeLangOptionsChecks": self.contract["langOptions"]["runtimeChecks"],
                "macroObservations": {"expansionCount": 1, "macroInfoChecks": 1,
                                       "nonBuiltinClassifications": 1},
            }
            checked = provision.validate_probe_report(report, inventory, self.contract)
            self.assertEqual(checked["inventoryEvidence"], self.contract["langOptions"]["inventoryEvidence"])
            self.assertEqual(checked["runtimeLangOptionsChecks"], self.contract["langOptions"]["runtimeChecks"])

    def test_langoptions_full_audit_accepts_public_llvmorg_18_1_3_fixtures(self):
        fixtures = ROOT / "oracle/clang/18.1.3/fixtures"
        definition = fixtures / "llvmorg-18.1.3-LangOptions.def"
        header = fixtures / "llvmorg-18.1.3-LangOptions.h"
        inventory = provision.audit_langoptions(definition, header, self.contract)
        self.assertEqual(inventory["generatedFields"], self.contract["langOptions"]["generatedFieldCount"])
        self.assertEqual(inventory["familyCounts"], self.contract["langOptions"]["familyCounts"])
        self.assertEqual(inventory["manualFields"], self.contract["langOptions"]["manualFields"])
        self.assertEqual(inventory["manualFieldsCount"], 28)

    def test_langoptions_source_audit_rejects_added_or_removed_manual_members(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            definition = self.langoptions_definition_fixture(base)
            fields = list(self.contract["langOptions"]["manualFields"])
            mutations = (
                ("added", "\n".join(f"int {name};" for name in fields) + "\nint UnexpectedManualField;"),
                ("added-nested-member", "\n".join(f"int {name};" for name in fields) +
                 "\nstruct Additional { int nestedOnly; } nestedField;"),
                ("removed", "\n".join(f"int {name};" for name in fields[:-1])),
            )
            for label, members in mutations:
                header = base / f"LangOptions-{label}.h"
                declarations = "\n".join("  " + line for line in members.splitlines())
                header.write_text(
                    "class LangOptions : public LangOptionsBase {\npublic:\n" + declarations + "\n};\n",
                    encoding="utf-8")
                with self.subTest(change=label), self.assertRaisesRegex(
                        provision.ProvisionError, "direct manual member inventory mismatch"):
                    provision.audit_langoptions(definition, header, self.contract)

    def test_langoptions_source_audit_rejects_added_state_hidden_in_declarator_shapes(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            definition = self.langoptions_definition_fixture(base)
            fields = self.contract["langOptions"]["manualFields"]
            members = "\n".join(f"int {name};" for name in fields)
            mutations = {
                "function-pointer": members + "\nint (*AddedCallback)(int);",
                "comma-declarator": members.replace(f"int {fields[0]};", f"int {fields[0]}, AddedMember;"),
                "comma-initializers": members.replace(f"int {fields[0]};", f"int {fields[0]}=0, AddedMember=1;"),
                "array-size-expression": members + "\nint Added[sizeof(int)];",
                "template-size-expression": members + "\nstd::array<int, sizeof(int)> Added;",
                "braced-array-size-expression": members + "\nint Added[sizeof(int)]{};",
                "braced-template-size-expression": members + "\nstd::array<int, sizeof(int)> Added{};",
                "gnu-attribute": members + "\nint Added __attribute__((aligned(16)));",
                "annotation-macro": members + "\nint Added MEMBER_ATTRIBUTE(16);",
                "mixed-method-and-field": members + "\nint method(), Added;",
                "anonymous-union-state": members + "\nunion { int Added; };",
            }
            for label, changed in mutations.items():
                header = base / f"LangOptions-{label}.h"
                header.write_text("class LangOptions {\n" + changed + "\n};\n")
                with self.subTest(label=label), self.assertRaisesRegex(
                        provision.ProvisionError, "direct manual member inventory mismatch|unsupported direct"):
                    provision.audit_langoptions(definition, header, self.contract)

    def test_langoptions_member_scanner_preserves_supported_initializers_and_method_boundaries(self):
        header = """class LangOptions {
          int First = 0, Second = makeValue(1, 2);
          std::vector<int> Third{1, 2}, Fourth = {3, 4};
          unsigned Bits : 1, OtherBits : 2;
          int Array[sizeof(int)]{};
          std::array<int, sizeof(int)> Sized{};
          const char *Text = "braces { commas , and fake int Added; }";
          LangOptions() { int localOnly; }
          ~LangOptions() {}
          void method(int *parameter) const { int localOnly; }
          void declaredMethod(int *parameter) const;
          const std::vector<int> &items() const;
          unsigned long long flags() const;
          struct Nested { int nestedOnly; };
        };"""
        self.assertEqual(provision.extract_cxx_class_data_members(header, "LangOptions"),
                         ["First", "Second", "Third", "Fourth", "Bits", "OtherBits", "Array", "Sized", "Text"])

    def test_langoptions_member_scanner_rejects_unrecognized_direct_state_declarations(self):
        for declaration in ("DECLARE_STATE(Added);", "MYSTERY_STATE;", "int (*Added)(int);",
                            "int (LangOptions::*Added)(int);", "int [[gnu::aligned(16)]] Added;",
                            "int Added __attribute__((aligned(16)));", "int Added __declspec(align(16));",
                            "int Added MEMBER_ATTRIBUTE(16);",
                            "int method(), Added;",
                            "union { int Added; };",
                            "template <typename T> static T Added;", "int MissingSemicolon"):
            with self.subTest(declaration=declaration), self.assertRaisesRegex(
                    provision.ProvisionError, "unsupported direct|unterminated direct"):
                provision.extract_cxx_class_data_members("class LangOptions {" + declaration + "};", "LangOptions")

    def test_langoptions_source_audit_rejects_comma_declarator_injection(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            definition = self.langoptions_definition_fixture(base)
            members = list(self.contract["langOptions"]["manualFields"])
            declarations = [
                f"bool {name} = false, Injected = false;" if name == "SanitizeCoverage"
                else f"bool {name};"
                for name in members
            ]
            header = base / "LangOptions-comma-injection.h"
            header.write_text(
                "class LangOptions : public LangOptionsBase {\npublic:\n  " +
                "\n  ".join(declarations) + "\n};\n", encoding="utf-8")
            with self.assertRaisesRegex(provision.ProvisionError, "direct manual member inventory mismatch"):
                provision.audit_langoptions(definition, header, self.contract)

    def test_langoptions_member_parser_preserves_nested_initializer_commas(self):
        header = """class LangOptions {
public:
  std::pair<int, int> templateField = std::pair<int, int>{1, 2};
  bool functionField = consume(1, 2);
  int unqualifiedTemplateField = consume<int, long>(1, 2);
  std::function<void(int, int)> callbackField;
  int bracedField{1, 2};
  int commaExpressionField = (1, 2);
  void methodWithPointerParameter(void (*callback)(int, int)) const;
  decltype(auto) inferredMethod();
};
"""
        self.assertEqual(
            provision.extract_cxx_class_data_members(header, "LangOptions"),
            ["templateField", "functionField", "unqualifiedTemplateField", "callbackField",
             "bracedField", "commaExpressionField"],
        )

    def test_langoptions_member_parser_handles_default_argument_methods_and_templated_function_braces(self):
        header = """class LangOptions {
public:
  std::function<void()> AddedCallback{};
  void setLangDefaults(int value = defaultValue()) { int methodLocal; }
  template <typename T> void setTemplatedDefaults(T value = T{}) { int templateLocal; }
  decltype(auto) inferredBody() { int inferredLocal; }
  auto trailingReturnBody() -> decltype(0 + 1) { int trailingLocal; }
  bool operator<(int other) { int operatorLocal; return false; }
  int FollowingField;
};
"""
        self.assertEqual(
            provision.extract_cxx_class_data_members(header, "LangOptions"),
            ["AddedCallback", "FollowingField"],
        )

    def test_langoptions_source_audit_rejects_parenthesized_type_and_member_declarators(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            definition = self.langoptions_definition_fixture(base)
            fields = list(self.contract["langOptions"]["manualFields"])
            injections = (
                "decltype(0 + 1) stealth{};",
                "static decltype(0 + 1) staticStealth{};",
                "int (stealth){};",
                "alignas(8) int (alignedStealth){};",
                "typeof(0 + 1) typeofStealth{};",
                "__typeof__(0 + 1) gnuTypeofStealth{};",
            )
            for index, declaration in enumerate(injections):
                header = base / f"LangOptions-parenthesized-{index}.h"
                header.write_text(
                    "class LangOptions : public LangOptionsBase {\npublic:\n  " +
                    "\n  ".join(f"int {name};" for name in fields) +
                    "\n  " + declaration + "\n};\n",
                    encoding="utf-8")
                with self.subTest(declaration=declaration), self.assertRaisesRegex(
                        provision.ProvisionError, "unsupported direct|unsupported or ambiguous parenthesized"):
                    provision.audit_langoptions(definition, header, self.contract)

    def test_langoptions_source_audit_fails_closed_on_function_pointer_member(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            definition = self.langoptions_definition_fixture(base)
            fields = self.contract["langOptions"]["manualFields"]
            header = base / "LangOptions-function-pointer.h"
            header.write_text(
                "class LangOptions : public LangOptionsBase {\npublic:\n  " +
                "\n  ".join(f"int {name};" for name in fields) +
                "\n  void (*AddedCallback)(int);\n};\n", encoding="utf-8")
            with self.assertRaisesRegex(provision.ProvisionError, "unsupported direct parenthesized"):
                provision.audit_langoptions(definition, header, self.contract)

    def test_source_patch_audit_emits_rejection_for_contract_file_difference(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            package = base / "package"
            upstream = base / "upstream"
            (package / "debian/patches").mkdir(parents=True)
            (package / "debian/patches/series").write_text("", encoding="utf-8")
            rel = self.contract["relevantFiles"][0]
            (package / rel).parent.mkdir(parents=True)
            (upstream / rel).parent.mkdir(parents=True)
            (package / rel).write_bytes(b"patched package bytes")
            (upstream / rel).write_bytes(b"upstream bytes")
            with self.assertRaises(provision.ProvisionError):
                provision.audit_patches(package, upstream, base / "patch-audit.json", self.contract)
            result = json.loads((base / "patch-audit.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "incompatible")
            self.assertEqual(result["decision"], "reject-distro-profile")
            self.assertTrue((base / "patch-audit.json").is_file())

    def test_source_patch_audit_covers_tooling_and_recursive_visitor_headers(self):
        tooling_header = "clang/include/clang/Tooling/Tooling.h"
        visitor_header = "clang/include/clang/AST/RecursiveASTVisitor.h"
        self.assertIn(tooling_header, self.contract["relevantFiles"])
        self.assertIn(visitor_header, self.contract["relevantFiles"])
        self.assertEqual(len(self.contract["relevantFiles"]), 34)
        with self.temporary_directory() as temp:
            base = Path(temp)
            package = base / "package"
            upstream = base / "upstream"
            (package / "debian/patches").mkdir(parents=True)
            (package / "debian/patches/series").write_text("", encoding="utf-8")
            for rel in self.contract["relevantFiles"]:
                package_path, upstream_path = package / rel, upstream / rel
                package_path.parent.mkdir(parents=True, exist_ok=True)
                upstream_path.parent.mkdir(parents=True, exist_ok=True)
                package_path.write_bytes(b"identical source bytes")
                upstream_path.write_bytes(b"identical source bytes")
            (package / visitor_header).write_bytes(b"changed visitor semantics")
            with self.assertRaises(provision.ProvisionError):
                provision.audit_patches(package, upstream, base / "patch-audit.json", self.contract)
            result = json.loads((base / "patch-audit.json").read_text(encoding="utf-8"))
            self.assertEqual(result["relevantFileCount"], 34)
            self.assertEqual([row["path"] for row in result["unresolvedContractRelevantDifferences"]],
                             [visitor_header])

    def test_oci_selected_environment_and_config_semantics_are_bound(self):
        environment = {**self.contract["environment"], "PATH": "/selected/bin", "SOURCE_DATE_EPOCH": "7"}
        changes = [
            ("architecture", lambda c: c.update(architecture="arm64")),
            ("os", lambda c: c.update(os="windows")),
            ("created", lambda c: c.update(created="2024-04-25T00:00:00Z")),
            ("history", lambda c: c.update(history=[])),
            ("environment", lambda c: c["config"].update(Env=["PATH=/different/bin"])),
            ("labels", lambda c: c["config"].update(Labels={})),
            ("working directory", lambda c: c["config"].update(WorkingDir="/tmp")),
            ("entrypoint", lambda c: c["config"].update(Entrypoint=["/bin/sh"])),
            ("command", lambda c: c["config"].update(Cmd=["unrecorded"])),
            ("user", lambda c: c["config"].update(User="1000")),
            ("rootfs type", lambda c: c["rootfs"].update(type="unrecorded")),
            ("extra field", lambda c: c.update(unrecorded=True)),
        ]
        with self.temporary_directory() as temp:
            base = Path(temp)
            payload = b"synthetic rootfs bytes; not a qualified image"
            rootfs_tar = base / "rootfs.tar"
            rootfs_tar.write_bytes(payload)
            for label, mutate in [("valid", None), *changes]:
                with self.subTest(label=label):
                    layout = base / label
                    image = provision.create_oci_layout(rootfs_tar, layout, "fixture", environment)
                    manifest_path = layout / "blobs/sha256" / image["manifestSha256"]
                    manifest = json.loads(manifest_path.read_text())
                    config_path = layout / "blobs/sha256" / manifest["config"]["digest"].removeprefix("sha256:")
                    config = json.loads(config_path.read_text())
                    self.assertEqual(config["created"], "1970-01-01T00:00:07Z")
                    self.assertEqual(config["config"]["Env"], [f"{key}={value}" for key, value in sorted(environment.items())])
                    if mutate:
                        mutate(config)
                        config_bytes = provision.canonical_json(config)
                        config_digest = provision.sha256(config_bytes)
                        config_path.unlink()
                        (config_path.parent / config_digest).write_bytes(config_bytes)
                        manifest["config"].update(digest="sha256:" + config_digest, size=len(config_bytes))
                        manifest_bytes = provision.canonical_json(manifest)
                        manifest_digest = provision.sha256(manifest_bytes)
                        manifest_path.unlink()
                        (manifest_path.parent / manifest_digest).write_bytes(manifest_bytes)
                        index_path = layout / "index.json"
                        index = json.loads(index_path.read_text())
                        index["manifests"][0].update(digest="sha256:" + manifest_digest, size=len(manifest_bytes))
                        index_path.write_bytes(provision.canonical_json(index))
                        image.update(manifestSha256=manifest_digest, imageDigest="sha256:" + manifest_digest)
                    archive_path = base / (label + ".tar")
                    with tarfile.open(archive_path, "w") as archive:
                        for path in sorted(layout.rglob("*")):
                            if path.is_file():
                                archive.add(path, arcname=path.relative_to(layout).as_posix())
                    record = {
                        "profile": {"id": "fixture"}, "environment": environment,
                        "rootfs": {"bytes": len(payload), "sha256": provision.sha256(payload)},
                        "image": image,
                        "imageArtifact": {"bytes": archive_path.stat().st_size, "sha256": provision.sha256_file(archive_path)},
                    }
                    if mutate:
                        with self.assertRaisesRegex(provision.ProvisionError, "config semantics"):
                            provision.verify_oci_archive(archive_path, record, 1024 * 1024)
                    else:
                        provision.verify_oci_archive(archive_path, record, 1024 * 1024)

    def test_oci_reference_annotation_is_exact_even_with_rehashed_outer_archive(self):
        annotation_key = "org.opencontainers.image.ref.name"
        annotations = [None, {}, {annotation_key: "attacker-reference"},
                       {"renamed.annotation": "clang-18.1.3-noble-amd64"},
                       {annotation_key: "clang-18.1.3-noble-amd64", "extra": "claim"},
                       [], {annotation_key: "clang-18.1.3-noble-amd64"}]
        with self.temporary_directory() as temp:
            base = Path(temp)
            payload = b"inert OCI annotation fixture"
            rootfs_tar = base / "rootfs.tar"
            rootfs_tar.write_bytes(payload)
            for index, annotation in enumerate(annotations):
                with self.subTest(annotation=annotation):
                    layout = base / f"layout-{index}"
                    image = provision.create_oci_layout(rootfs_tar, layout, "fixture", self.contract["environment"])
                    index_path = layout / "index.json"
                    data = json.loads(index_path.read_bytes())
                    self.assertEqual(data["manifests"][0]["annotations"],
                                     {annotation_key: "clang-18.1.3-noble-amd64"})
                    if annotation is None:
                        data["manifests"][0].pop("annotations")
                    else:
                        data["manifests"][0]["annotations"] = annotation
                    index_path.write_bytes(provision.canonical_json(data))
                    archive_path = base / f"archive-{index}.tar"
                    with tarfile.open(archive_path, "w") as archive:
                        for path in sorted(layout.rglob("*")):
                            if path.is_file():
                                archive.add(path, arcname=path.relative_to(layout).as_posix())
                    record = {"profile": {"id": "fixture"}, "environment": self.contract["environment"],
                              "rootfs": {"bytes": len(payload), "sha256": provision.sha256(payload)},
                              "image": image,
                              "imageArtifact": {"bytes": archive_path.stat().st_size,
                                                "sha256": provision.sha256_file(archive_path)}}
                    if annotation == {annotation_key: "clang-18.1.3-noble-amd64"}:
                        provision.verify_oci_archive(archive_path, record, 1024 * 1024)
                    else:
                        with self.assertRaisesRegex(provision.ProvisionError, "reference annotation"):
                            provision.verify_oci_archive(archive_path, record, 1024 * 1024)

    def test_oci_image_verifier_rejects_rehashed_duplicate_json_members(self):
        def duplicate(payload, name, marker=b"{"):
            injected = marker + json.dumps(name).encode("utf-8") + b":null,"
            self.assertIn(marker, payload)
            changed = payload.replace(marker, injected, 1)
            self.assertEqual(json.loads(changed), json.loads(payload))
            self.assertNotEqual(changed, payload)
            return changed

        cases = ("layout", "index", "index-descriptor", "manifest", "manifest-config", "config", "config-env")
        with self.temporary_directory() as temp:
            base = Path(temp)
            payload = b"synthetic rootfs layer; not a qualified image"
            rootfs_tar = base / "rootfs.tar"
            rootfs_tar.write_bytes(payload)
            for case in cases:
                with self.subTest(case=case):
                    layout = base / case
                    image = provision.create_oci_layout(rootfs_tar, layout, "fixture", self.contract["environment"])
                    manifest_path = layout / "blobs/sha256" / image["manifestSha256"]
                    manifest = json.loads(manifest_path.read_bytes())
                    config_path = layout / "blobs/sha256" / manifest["config"]["digest"].removeprefix("sha256:")
                    if case in ("config", "config-env"):
                        config_bytes = config_path.read_bytes()
                        config_bytes = (duplicate(config_bytes, "architecture") if case == "config"
                                        else duplicate(config_bytes, "Env", b'"config":{'))
                        config_digest = provision.sha256(config_bytes)
                        config_path.unlink()
                        (config_path.parent / config_digest).write_bytes(config_bytes)
                        manifest["config"].update(digest="sha256:" + config_digest, size=len(config_bytes))
                    manifest_bytes = provision.canonical_json(manifest)
                    if case == "manifest":
                        manifest_bytes = duplicate(manifest_bytes, "schemaVersion")
                    elif case == "manifest-config":
                        manifest_bytes = duplicate(manifest_bytes, "digest", b'"config":{')
                    manifest_digest = provision.sha256(manifest_bytes)
                    if manifest_digest != image["manifestSha256"]:
                        manifest_path.unlink()
                    (manifest_path.parent / manifest_digest).write_bytes(manifest_bytes)
                    index_path = layout / "index.json"
                    index = json.loads(index_path.read_bytes())
                    index["manifests"][0].update(digest="sha256:" + manifest_digest, size=len(manifest_bytes))
                    index_bytes = provision.canonical_json(index)
                    if case == "index":
                        index_bytes = duplicate(index_bytes, "schemaVersion")
                    elif case == "index-descriptor":
                        index_bytes = duplicate(index_bytes, "mediaType", b'"manifests":[{')
                    index_path.write_bytes(index_bytes)
                    image.update(manifestSha256=manifest_digest, imageDigest="sha256:" + manifest_digest)
                    if case == "layout":
                        layout_path = layout / "oci-layout"
                        layout_path.write_bytes(duplicate(layout_path.read_bytes(), "imageLayoutVersion"))
                    archive_path = base / (case + ".tar")
                    with tarfile.open(archive_path, "w") as archive:
                        for path in sorted(layout.rglob("*")):
                            if path.is_file():
                                archive.add(path, arcname=path.relative_to(layout).as_posix())
                    record = {
                        "profile": {"id": "fixture"}, "environment": self.contract["environment"],
                        "rootfs": {"bytes": len(payload), "sha256": provision.sha256(payload)},
                        "image": image,
                        "imageArtifact": {"bytes": archive_path.stat().st_size,
                                          "sha256": provision.sha256_file(archive_path)},
                    }
                    with self.assertRaisesRegex(provision.ProvisionError, "duplicate object member"):
                        provision.verify_oci_archive(archive_path, record, 1024 * 1024)

    def test_oci_image_verifier_rejects_unrecorded_blob(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs_tar = base / "rootfs.tar"
            payload = b"bounded synthetic rootfs tar payload"
            rootfs_tar.write_bytes(payload)
            layout = base / "layout"
            image = provision.create_oci_layout(rootfs_tar, layout, "fixture", self.contract["environment"])
            archive_path = base / "image.tar"
            names = sorted(path.relative_to(layout).as_posix() for path in layout.rglob("*") if path.is_file())
            provision.run_checked([
                "tar", "--sort=name", "--format=posix", "--numeric-owner", "--owner=0", "--group=0",
                "--mtime=@1714003200", "--pax-option=delete=atime,delete=ctime", "-cf", str(archive_path),
                "-C", str(layout), *names,
            ])
            record = {"profile": {"id": "fixture"}, "environment": self.contract["environment"],
                      "rootfs": {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
                      "image": image,
                      "imageArtifact": {"bytes": archive_path.stat().st_size,
                                        "sha256": provision.sha256_file(archive_path)}}
            provision.verify_oci_archive(archive_path, record, 1024 * 1024)
            record["imageArtifact"]["sha256"] = "f" * 64
            with self.assertRaisesRegex(provision.ProvisionError, "checksummed build-record artifact identity"):
                provision.verify_oci_archive(archive_path, record, 1024 * 1024)
            with tarfile.open(archive_path, "a") as archive:
                info = tarfile.TarInfo("blobs/sha256/" + "f" * 64)
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
            record["imageArtifact"] = {"bytes": archive_path.stat().st_size,
                                       "sha256": provision.sha256_file(archive_path)}
            with self.assertRaisesRegex(provision.ProvisionError, "unrecorded files or blobs"):
                provision.verify_oci_archive(archive_path, record, 1024 * 1024)

    def test_oci_image_verifier_rejects_config_descriptor_size_mismatch(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            rootfs_tar = base / "rootfs.tar"
            payload = b"bounded synthetic rootfs tar payload"
            rootfs_tar.write_bytes(payload)
            layout = base / "layout"
            image = provision.create_oci_layout(rootfs_tar, layout, "fixture", self.contract["environment"])

            manifest_path = layout / "blobs/sha256" / image["manifestSha256"]
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            config_path = layout / "blobs/sha256" / manifest["config"]["digest"].removeprefix("sha256:")
            config_bytes = config_path.read_bytes()
            manifest["config"]["size"] = len(config_bytes) + 1
            manifest_bytes = provision.canonical_json(manifest)
            manifest_sha256 = provision.sha256(manifest_bytes)
            (manifest_path.parent / manifest_sha256).write_bytes(manifest_bytes)
            manifest_path.unlink()

            index_path = layout / "index.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["manifests"][0]["digest"] = "sha256:" + manifest_sha256
            index["manifests"][0]["size"] = len(manifest_bytes)
            index_path.write_bytes(provision.canonical_json(index))

            archive_path = base / "image.tar"
            names = sorted(path.relative_to(layout).as_posix() for path in layout.rglob("*") if path.is_file())
            provision.run_checked([
                "tar", "--sort=name", "--format=posix", "--numeric-owner", "--owner=0", "--group=0",
                "--mtime=@1714003200", "--pax-option=delete=atime,delete=ctime", "-cf", str(archive_path),
                "-C", str(layout), *names,
            ])
            record = {
                "profile": {"id": "fixture"}, "environment": self.contract["environment"],
                "rootfs": {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
                "image": {**image, "manifestSha256": manifest_sha256,
                          "imageDigest": "sha256:" + manifest_sha256},
                "imageArtifact": {"bytes": archive_path.stat().st_size,
                                  "sha256": provision.sha256_file(archive_path)},
            }
            with self.assertRaisesRegex(provision.ProvisionError, "config descriptor size differs"):
                provision.verify_oci_archive(archive_path, record, 1024 * 1024)

    def test_oci_image_verifier_rejects_missing_or_untrusted_media_types(self):
        descriptor_fields = ("index", "index-manifest", "manifest", "config", "layer")
        for field in descriptor_fields:
            for mutation in ("missing", "untrusted"):
                with self.subTest(field=field, mutation=mutation), self.temporary_directory() as temp:
                    base = Path(temp)
                    rootfs_tar = base / "rootfs.tar"
                    payload = b"synthetic rootfs bytes for media-type validation"
                    rootfs_tar.write_bytes(payload)
                    layout = base / "layout"
                    image = provision.create_oci_layout(rootfs_tar, layout, "fixture", self.contract["environment"])
                    index_path = layout / "index.json"
                    index = json.loads(index_path.read_text(encoding="utf-8"))
                    descriptor = index["manifests"][0]
                    manifest_path = layout / "blobs/sha256" / image["manifestSha256"]
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    target = {
                        "index": (index, "mediaType"),
                        "index-manifest": (descriptor, "mediaType"),
                        "manifest": (manifest, "mediaType"),
                        "config": (manifest["config"], "mediaType"),
                        "layer": (manifest["layers"][0], "mediaType"),
                    }[field]
                    if mutation == "missing":
                        target[0].pop(target[1])
                    else:
                        target[0][target[1]] = "application/x-untrusted"
                    if field in ("manifest", "config", "layer"):
                        manifest_bytes = provision.canonical_json(manifest)
                        manifest_sha256 = provision.sha256(manifest_bytes)
                        (manifest_path.parent / manifest_sha256).write_bytes(manifest_bytes)
                        manifest_path.unlink()
                        descriptor.update(digest="sha256:" + manifest_sha256, size=len(manifest_bytes))
                        image.update(manifestSha256=manifest_sha256, imageDigest="sha256:" + manifest_sha256)
                    index_path.write_bytes(provision.canonical_json(index))

                    archive_path = base / "image.tar"
                    with tarfile.open(archive_path, "w") as archive:
                        for path in sorted(layout.rglob("*")):
                            if path.is_file():
                                archive.add(path, arcname=path.relative_to(layout).as_posix())
                    record = {
                        "profile": {"id": "fixture"}, "environment": self.contract["environment"],
                        "rootfs": {"bytes": len(payload), "sha256": provision.sha256(payload)},
                        "image": image,
                        "imageArtifact": {"bytes": archive_path.stat().st_size,
                                          "sha256": provision.sha256_file(archive_path)},
                    }
                    with self.assertRaisesRegex(provision.ProvisionError, "media type"):
                        provision.verify_oci_archive(archive_path, record, 1024 * 1024)


    def test_json_boundaries_reject_nonfinite_constants_overflow_and_encoding(self):
        for token in ("NaN", "Infinity", "-Infinity", "1e400", "-1e400"):
            for payload in (f'{{"downloadedBytes":{token}}}', f'{{"nested":[{token}]}}'):
                for data in (payload, payload.encode()):
                    with self.subTest(payload=payload, binary=isinstance(data, bytes)), self.assertRaisesRegex(
                            provision.ProvisionError, "non-finite"):
                        provision.strict_json_loads(data)
                with self.assertRaises(provision.host_worker.WorkerRefusal):
                    provision.host_worker.parse(payload.encode())
        for value in (float("nan"), float("inf"), -float("inf")):
            for encode in (provision.canonical_json, provision.host_worker.canonical):
                with self.subTest(value=value, encode=encode.__name__), self.assertRaises(ValueError):
                    encode({"nested": [value]})
        finite = {"fraction": 1.25, "integer": 7, "nested": [None, True, -0.5]}
        self.assertEqual(provision.strict_json_loads(provision.canonical_json(finite)), finite)
        self.assertEqual(provision.host_worker.parse(provision.host_worker.canonical(finite)), finite)

    def test_oci_layout_modes_and_archived_bytes_are_independent_of_umask(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            source = base / "rootfs.tar"
            source.write_bytes(b"inert fixed rootfs bytes")
            archives = []
            for mask in (0o022, 0o077, 0o777):
                layout = base / f"layout-{mask}"
                previous = os.umask(mask)
                try:
                    provision.create_oci_layout(source, layout, "fixture", self.contract["environment"])
                finally:
                    os.umask(previous)
                entries = [layout, *sorted(layout.rglob("*"))]
                output = io.BytesIO()
                with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for path in entries:
                        mode = 0o755 if path.is_dir() else 0o644
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
                        info = archive.gettarinfo(str(path), arcname="." if path == layout else path.relative_to(layout).as_posix())
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        info.mtime = 7
                        if path.is_file():
                            with path.open("rb") as stream:
                                archive.addfile(info, stream)
                        else:
                            archive.addfile(info)
                archives.append(output.getvalue())
            self.assertEqual(archives[0], archives[1])
            self.assertEqual(archives[0], archives[2])

    def test_oci_manifest_and_layer_sizes_require_exact_integer_values(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            source = base / "rootfs.tar"
            payload = b"inert descriptor type fixture"
            source.write_bytes(payload)
            for role in ("manifest", "layer"):
                for index, kind in enumerate(("exact", "float", "true", "false", "missing", "null", "string", "negative")):
                    with self.subTest(role=role, kind=kind):
                        layout = base / f"{role}-{index}"
                        image = provision.create_oci_layout(source, layout, "fixture", self.contract["environment"])
                        manifest_path = layout / "blobs/sha256" / image["manifestSha256"]
                        manifest = json.loads(manifest_path.read_bytes())
                        index_path = layout / "index.json"
                        document = json.loads(index_path.read_bytes())
                        descriptor = document["manifests"][0] if role == "manifest" else manifest["layers"][0]
                        size = descriptor["size"]
                        if kind == "missing":
                            del descriptor["size"]
                        else:
                            descriptor["size"] = {"exact": size, "float": float(size), "true": True,
                                "false": False, "null": None, "string": str(size), "negative": -size}[kind]
                        if role == "layer":
                            raw = provision.canonical_json(manifest)
                            digest = provision.sha256(raw)
                            manifest_path.unlink()
                            (manifest_path.parent / digest).write_bytes(raw)
                            document["manifests"][0].update(digest="sha256:" + digest, size=len(raw))
                            image.update(manifestSha256=digest, imageDigest="sha256:" + digest)
                        index_path.write_bytes(provision.canonical_json(document))
                        archive_path = base / f"{role}-{index}.tar"
                        with tarfile.open(archive_path, "w") as archive:
                            for path in sorted(layout.rglob("*")):
                                if path.is_file():
                                    archive.add(path, arcname=path.relative_to(layout).as_posix(), recursive=False)
                        record = {"profile": {"id": "fixture"}, "environment": self.contract["environment"],
                                  "rootfs": {"bytes": len(payload), "sha256": provision.sha256(payload)}, "image": image,
                                  "imageArtifact": {"bytes": archive_path.stat().st_size,
                                                    "sha256": provision.sha256_file(archive_path)}}
                        if kind == "exact":
                            provision.verify_oci_archive(archive_path, record, 1024 * 1024)
                        else:
                            with self.assertRaises(provision.ProvisionError):
                                provision.verify_oci_archive(archive_path, record, 1024 * 1024)

    def test_loader_input_digest_uses_the_same_captured_record_as_validation(self):
        with self.temporary_directory() as temp:
            _, rootfs, record_path, output, properties = self.prepare_loader_input_fixture(Path(temp), "captured-record")
            original = record_path.read_bytes()
            properties.unlink()  # The fixture's first publication must not be overwritten.
            validate = provision.validate_build_record
            def validate_then_replace(*args, **kwargs):
                validate(*args, **kwargs)
                replacement = record_path.with_suffix(".replacement")
                replacement.write_bytes(b'{"replacement":true}\n')
                replacement.replace(record_path)
            args = provision.argparse.Namespace(contract=provision.CONTRACT_PATH, record=record_path,
                                               rootfs=rootfs, output=output)
            with mock.patch.object(provision, "validate_build_record", side_effect=validate_then_replace):
                self.assertEqual(provision.command_write_loader_input(args), 0)
            self.assertIn(f"buildRecordSha256={provision.sha256(original)}\n".encode(), properties.read_bytes())
            self.assertNotEqual(provision.sha256_file(record_path), provision.sha256(original))


class RecipeAndCandidateBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = provision.read_contract()
        (ROOT / "build").mkdir(exist_ok=True)
        cls.temp_root = Path(tempfile.mkdtemp(prefix="clang1813-binding-tests-", dir=ROOT / "build"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_root, ignore_errors=True)

    def temporary_directory(self):
        return tempfile.TemporaryDirectory(dir=self.temp_root)

    def valid_build_record(self):
        return ProvisioningNegativeTests.valid_build_record(self)

    def candidate_fixture(self, base):
        root = base / "acquisition"
        root.mkdir()
        keyring = base / "ubuntu-keyring.gpg"
        keyring.write_bytes(b"synthetic keyring; signatures are mocked")

        def artifact(relative):
            payload = ("synthetic bytes for " + relative).encode()
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            return {"path": relative, "bytes": len(payload), "sha256": provision.sha256(payload)}

        profile = self.contract["profile"]
        repositories, indexes = [], []
        for suite in profile["suites"]:
            repositories.append({
                "suite": suite,
                "inRelease": {**artifact(f"downloads/{suite}/InRelease"),
                              "finalUrl": f"{profile['snapshotBase']}dists/{suite}/InRelease"},
                "signerPrimaryFingerprint": profile["ubuntuArchivePrimaryFingerprints"][0],
            })
            for component in profile["components"]:
                for kind in ("source", "binary-amd64"):
                    indexes.append({**artifact(f"downloads/{suite}/{component}/{kind}/index.gz"),
                                    "suite": suite, "component": component, "kind": kind})
        package_source = root / "source/package-source"
        upstream_source = root / "source/upstream/llvm-project-18.1.3.src"
        (package_source / "debian/patches").mkdir(parents=True)
        (package_source / "debian/patches/series").write_bytes(b"")
        for relative in self.contract["relevantFiles"]:
            for source_root in (package_source, upstream_source):
                path = source_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"matching synthetic source\n")
        audit = provision.audit_patches(package_source, upstream_source, root / "patch-audit.json", self.contract)
        candidate = {
            "schemaVersion": 1, "status": "authenticated-candidate-awaiting-repository-lock-review",
            "profileId": profile["id"], "snapshot": profile["snapshot"],
            "trustedKeyring": {"bytes": keyring.stat().st_size, "sha256": provision.sha256_file(keyring)},
            "repositories": repositories, "indexes": indexes,
            "source": {
                **profile["sourcePackage"],
                "directory": "pool/universe/l/llvm-toolchain-18",
                "suite": "noble",
                "component": "universe",
                "files": [{**artifact("downloads/source/source.dsc"), "name": "source.dsc"}],
                "upstreamArchive": artifact("downloads/upstream/source.tar.xz"),
                "upstreamArchivePath": "downloads/upstream/source.tar.xz",
                "upstreamSignature": artifact("downloads/upstream/source.tar.xz.sig"),
                "upstreamSignaturePath": "downloads/upstream/source.tar.xz.sig",
                "upstreamKeyring": artifact("downloads/upstream/llvm-release-keyring.gpg"),
            },
            "patchAudit": {key: audit[key] for key in (
                "status", "patchCount", "patchInventorySha256", "relevantFileCount", "relevantFileManifestSha256")},
            "binaryRoots": sorted(profile["binaryRoots"], key=lambda row: row["name"]),
            "downloadedBytes": 1,
        }
        self.write_candidate(root, candidate)
        record = self.valid_build_record()
        record.update(provision.candidate_build_evidence(candidate, self.contract))
        record["commands"] = provision.canonical_commands(self.contract, candidate["trustedKeyring"]["sha256"])
        return root, candidate, record, keyring

    def test_rehashed_source_coordinate_changes_do_not_override_the_signed_row(self):
        with self.temporary_directory() as temp:
            _, candidate, _, _ = self.candidate_fixture(Path(temp))
            profile = self.contract["profile"]
            signed = {
                "Package": candidate["source"]["name"],
                "Version": candidate["source"]["version"],
                "Directory": candidate["source"]["directory"],
                "_suite": candidate["source"]["suite"],
                "_component": candidate["source"]["component"],
                "Checksums-Sha256": "a" * 64 + " 12 source.dsc",
            }
            mutations = {
                "name": "llvm-toolchain-19",
                "version": "1:18.1.3-1ubuntu2",
                "directory": "pool/universe/l/llvm-toolchain-18-shadow",
                "suite": "noble-updates",
            }
            for field, value in mutations.items():
                changed = json.loads(json.dumps(candidate))
                changed["source"][field] = value
                changed.pop("candidateSha256")
                changed["candidateSha256"] = provision.sha256(provision.canonical_json(changed))
                with self.subTest(field=field):
                    # The attacker can recompute the candidate's public self-digest;
                    # the authenticated row comparison still rejects the mutation.
                    if field in ("name", "version"):
                        with self.assertRaises(provision.ProvisionError):
                            provision.ensure_source_artifact_contract(changed, self.contract)
                    else:
                        provision.ensure_source_artifact_contract(changed, self.contract)
                    with self.assertRaises(provision.ProvisionError):
                        provision.verify_candidate_source_identity(changed["source"], signed, profile)

            changed_component = json.loads(json.dumps(candidate))
            changed_component["source"]["component"] = "main"
            changed_component["source"]["directory"] = "pool/main/l/llvm-toolchain-18"
            changed_component.pop("candidateSha256")
            changed_component["candidateSha256"] = provision.sha256(provision.canonical_json(changed_component))
            provision.ensure_source_artifact_contract(changed_component, self.contract)
            with self.assertRaisesRegex(provision.ProvisionError, "selected signed source row"):
                provision.verify_candidate_source_identity(changed_component["source"], signed, profile)

    def test_provenance_output_preflight_rejects_input_tree_and_symlink_aliases_before_creation(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            acquisition = base / "acquisition"
            rootfs = base / "rootfs"
            (acquisition / "downloads").mkdir(parents=True)
            rootfs.mkdir()
            (rootfs / "tmp").mkdir()
            ordinary = base / "record.json"
            ordinary.write_text("{}", encoding="utf-8")

            rejected = [
                acquisition / "downloads" / "provenance.tar",
                rootfs / "tmp" / "provenance.tar",
                acquisition / "provenance.tar",
                acquisition / "not-created" / "nested" / "provenance.tar",
            ]
            alias = base / "downloads-alias"
            alias.symlink_to(acquisition / "downloads", target_is_directory=True)
            rejected.append(alias / "provenance.tar")
            root_alias = base / "rootfs-alias"
            root_alias.symlink_to(rootfs, target_is_directory=True)
            rejected.append(root_alias / "tmp" / "provenance.tar")
            for output in rejected:
                with self.subTest(output=output), self.assertRaisesRegex(
                    provision.ProvisionError, "overlaps a recursively packaged input tree",
                ):
                    provision.preflight_provenance_output(output, [acquisition, rootfs], [ordinary])
                self.assertFalse(output.exists())
            self.assertFalse((acquisition / "not-created").exists())

            with self.assertRaisesRegex(provision.ProvisionError, "must not already exist"):
                provision.preflight_provenance_output(ordinary, [acquisition, rootfs], [ordinary])
            sibling = base / "sibling" / "provenance.tar"
            resolved = provision.preflight_provenance_output(sibling, [acquisition, rootfs], [ordinary])
            self.assertEqual(resolved, sibling.resolve(strict=False))
            self.assertFalse(sibling.parent.exists())

    def retained_rootfs_image_fixture(self, base, record):
        rootfs = base / "rootfs"
        ProvisioningNegativeTests.prepare_runtime_rootfs(self, record, rootfs)
        for role, logical in provision.FRONTEND_DRIVER_ROOTS:
            target = rootfs / "usr/lib/llvm-18/bin/clang"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"synthetic inert fixed driver bytes\n")
            target.chmod(0o755)
            link = rootfs / logical.lstrip("/")
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to("../lib/llvm-18/bin/clang")
            row = provision.driver_record(rootfs, logical, role, "clang version 18.1.3")
            record["tools"] = [row if old["role"] == role else old for old in record["tools"]]
        (rootfs / "etc").mkdir(exist_ok=True)
        probe_binary, probe_fixture, _ = ProvisioningNegativeTests.prepare_probe_rootfs(self, record, rootfs)
        cleanup_marker = rootfs / "tmp/unowned-normalization-marker"
        cleanup_marker.write_bytes(b"/tmp remains fully cleaned")
        rootfs_tar = base / "rootfs.tar"

        def local_tar(command, timeout=None, stdout_file=None):
            return subprocess.run(command[2:] if command[:2] == ["sudo", "-n"] else command[1:], check=False, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, timeout=timeout) if stdout_file is None else subprocess.run(
                                      command[1:], check=False, stdout=stdout_file, stderr=subprocess.PIPE, timeout=timeout)

        with mock.patch.object(provision, "run_checked", side_effect=local_tar), \
                mock.patch.object(provision, "normalize_network_identity_files",
                                  side_effect=lambda root: ProvisioningNegativeTests.local_network_normalization_fixture(self, root)):
            rootfs_identity = provision.deterministic_rootfs_tar(
                rootfs, rootfs_tar, int(self.contract["environment"]["SOURCE_DATE_EPOCH"]),
                normalize=True, max_bytes=self.contract["profile"]["bounds"]["maxArtifactBytes"],
            )
        self.assertFalse(cleanup_marker.exists(), "normalization must still clear arbitrary /tmp files")
        self.assertTrue(probe_binary.is_file() and probe_fixture.is_file())
        with tarfile.open(rootfs_tar, mode="r:") as retained:
            retained_names = {member.name.removeprefix("./") for member in retained.getmembers()}
        self.assertIn(provision.PROBE_BINARY_IN_ROOT.lstrip("/"), retained_names)
        self.assertIn(provision.PROBE_FIXTURE_IN_ROOT.lstrip("/"), retained_names)
        self.assertIn(provision.PROBE_SOURCE_IN_ROOT.lstrip("/"), retained_names)
        self.assertNotIn("tmp/unowned-normalization-marker", retained_names)
        record["rootfs"] = rootfs_identity
        layout = base / "image-layout"
        image = provision.create_oci_layout(
            rootfs_tar, layout, record["profile"]["id"], self.contract["environment"],
        )
        with gzip.open(layout / "blobs/sha256" / image["layerSha256"], mode="rb") as layer_stream:
            with tarfile.open(fileobj=layer_stream, mode="r:") as layer:
                image_rootfs_names = {member.name.removeprefix("./") for member in layer.getmembers()}
        self.assertIn(provision.PROBE_BINARY_IN_ROOT.lstrip("/"), image_rootfs_names)
        self.assertIn(provision.PROBE_FIXTURE_IN_ROOT.lstrip("/"), image_rootfs_names)
        self.assertIn(provision.PROBE_SOURCE_IN_ROOT.lstrip("/"), image_rootfs_names)
        record["image"] = {
            "format": image["format"], "manifestSha256": image["manifestSha256"],
            "imageDigest": image["imageDigest"],
        }
        oci_archive = base / "run2.oci.tar"
        with tarfile.open(oci_archive, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(item for item in layout.rglob("*") if item.is_file()):
                data = path.read_bytes()
                member = tarfile.TarInfo(path.relative_to(layout).as_posix())
                member.size = len(data)
                member.mode = 0o644
                member.uid = member.gid = 0
                member.mtime = int(self.contract["environment"]["SOURCE_DATE_EPOCH"])
                archive.addfile(member, io.BytesIO(data))
        record["imageArtifact"] = {
            "bytes": oci_archive.stat().st_size, "sha256": provision.sha256_file(oci_archive),
        }
        return rootfs, oci_archive

    def write_candidate(self, root, candidate):
        candidate.pop("candidateSha256", None)
        candidate["candidateSha256"] = provision.sha256(provision.canonical_json(candidate))
        (root / "acquisition-candidate.json").write_bytes(provision.canonical_json(candidate))

    def test_recipe_hashes_selected_contract_bytes_and_preserves_other_recipe_files(self):
        with self.temporary_directory() as temp:
            selected = Path(temp) / "custom-contract.json"
            contract = json.loads(json.dumps(self.contract))
            contract["environment"]["PATH"] = "/custom/bin"
            selected.write_bytes(provision.canonical_json(contract))
            actual = provision.recipe_identity(selected)
            default = provision.recipe_identity()
            self.assertNotEqual(actual["contractSha256"], default["contractSha256"])
            self.assertEqual(actual, {**default, "contractSha256": provision.sha256_file(selected)})
            record = self.valid_build_record()
            record["environment"] = contract["environment"]
            record["commands"] = provision.canonical_commands(contract, record["acquisition"]["ubuntuKeyring"]["sha256"])
            with self.assertRaisesRegex(provision.ProvisionError, r"recipe hashes|checked-in schema.*recipe"):
                provision.validate_build_record(record, contract, selected)
            record["recipe"] = actual
            provision.validate_build_record(record, contract, selected)
            selected.write_bytes(selected.read_bytes() + b" ")
            with self.assertRaisesRegex(provision.ProvisionError, r"recipe hashes|checked-in schema.*recipe"):
                provision.validate_build_record(record, contract, selected)

    def test_recipe_binds_production_a_loader_bytes_and_rejects_stale_records(self):
        loader = ROOT / "src/main/kotlin/decompengine/oracle/fulltree/FullTreeGenericTemplateFrontendProfileV1.kt"
        self.assertEqual(provision.RECIPE_FILES["aLoaderSha256"], loader)
        record = self.valid_build_record()
        self.assertEqual(record["recipe"]["aLoaderSha256"], provision.sha256_file(loader))
        provision.validate_build_record(record, self.contract)
        with self.temporary_directory() as temp:
            changed_loader = Path(temp) / loader.name
            changed_loader.write_bytes(loader.read_bytes() + b"\n// changed loader semantics\n")
            with mock.patch.dict(provision.RECIPE_FILES, {"aLoaderSha256": changed_loader}):
                with self.assertRaisesRegex(provision.ProvisionError, r"recipe hashes|checked-in schema.*recipe"):
                    provision.validate_build_record(record, self.contract)
        del record["recipe"]["aLoaderSha256"]
        with self.assertRaisesRegex(provision.ProvisionError, r"recipe hashes|checked-in schema.*recipe"):
            provision.validate_build_record(record, self.contract)

    def test_record_commands_propagate_selected_contract_to_verification(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            selected, record_path = base / "contract.json", base / "record.json"
            selected.write_bytes(provision.canonical_json(self.contract))
            record_path.write_bytes(provision.canonical_json(self.valid_build_record()))
            commands = (provision.command_verify_record, provision.command_write_loader_input,
                        provision.command_verify_image, provision._package_provenance_unqualified)
            for command in commands:
                args = provision.argparse.Namespace(contract=selected, record=record_path)
                with self.subTest(command=command.__name__), mock.patch.object(
                    provision, "validate_build_record", side_effect=provision.ProvisionError("stop before work")
                ) as validate:
                    with self.assertRaisesRegex(provision.ProvisionError, "stop before work"):
                        command(args)
                    self.assertEqual(validate.call_args.args[2], selected)

    def test_compare_runs_and_metadata_report_bind_selected_contract(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            selected = base / "contract.json"
            selected.write_bytes(provision.canonical_json(self.contract))
            record = self.valid_build_record()
            record["recipe"] = provision.recipe_identity(selected)
            first, second = base / "first.json", base / "second.json"
            first.write_bytes(provision.canonical_json(record))
            second.write_bytes(provision.canonical_json(record))
            args = provision.argparse.Namespace(contract=selected, first=first, second=second,
                                               output=base / "final.json")
            self.assertEqual(provision.command_compare_runs(args), 0)
            self.assertEqual(json.loads(args.output.read_bytes())["recipe"], record["recipe"])
            keyring = base / "keyring"
            keyring.write_bytes(b"fixture")
            report = provision.snapshot_metadata_selection(
                self.contract, self.contract["profile"], [], [], [], [], 0, keyring, selected)
            self.assertEqual(report["contractSha256"], provision.sha256_file(selected))
            self.assertEqual(report["recipe"], record["recipe"])

    def test_candidate_replay_accepts_bound_evidence_and_cleans_temporary_audit(self):
        with self.temporary_directory() as temp:
            root, candidate, record, keyring = self.candidate_fixture(Path(temp))
            for source_root in (root / "source/package-source",
                                root / "source/upstream/llvm-project-18.1.3.src"):
                (source_root / self.contract["relevantFiles"][0]).write_bytes(b"untrusted cached tree\n")

            def create_package_source(destination):
                destination.mkdir(parents=True)
                patches = destination / "debian/patches"
                patches.mkdir(parents=True)
                (patches / "series").write_bytes(b"")
                for relative in self.contract["relevantFiles"]:
                    target = destination / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(b"matching synthetic source\n")

            def extract_dsc(command, **kwargs):
                self.assertEqual(command[0:2], ["dpkg-source", "-x"])
                self.assertEqual(Path(kwargs["cwd"]), Path(command[-2]).parent)
                self.assertEqual(Path(command[-2]).read_bytes(), b"synthetic bytes for downloads/source/source.dsc")
                create_package_source(Path(command[-1]))
                return subprocess.CompletedProcess(command, 0, "")

            def extract_upstream(archive, destination):
                self.assertEqual(archive.read_bytes(), b"synthetic bytes for downloads/upstream/source.tar.xz")
                destination.mkdir(parents=True)
                source = destination / "llvm-project-18.1.3.src"
                source.mkdir()
                for relative in self.contract["relevantFiles"]:
                    target = source / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(b"matching synthetic source\n")
                return source

            with mock.patch.object(provision, "verify_candidate_data", return_value=[]) as signed, \
                    mock.patch.object(provision.subprocess, "run", side_effect=extract_dsc), \
                    mock.patch.object(provision, "safe_extract_xz_tar", side_effect=extract_upstream):
                actual, parsed = provision.load_candidate(root, self.contract, keyring, record)
            self.assertEqual(actual, candidate)
            self.assertEqual(parsed, [])
            expected_names = {row["name"] for section in ("packages", "downloadedPackages")
                              for row in record[section]}
            signed.assert_called_once_with(root, candidate, self.contract, keyring,
                                           extra_binary_package_names=expected_names)
            self.assertEqual(list(root.glob("patch-audit-replay-*")), [])

    def test_sequential_provisioning_replays_authenticated_sources_after_optional_caches_are_removed(self):
        with self.temporary_directory() as temporary:
            base = Path(temporary)
            root, candidate, _, keyring = self.candidate_fixture(base)
            download_hashes = {path.relative_to(root): provision.sha256_file(path)
                               for path in (root / "downloads").rglob("*") if path.is_file()}

            def extract_dsc(command, **kwargs):
                self.assertEqual(command[:2], ["dpkg-source", "-x"])
                destination = Path(command[-1])
                (destination / "debian/patches").mkdir(parents=True)
                (destination / "debian/patches/series").write_bytes(b"")
                for relative in self.contract["relevantFiles"]:
                    target = destination / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(b"matching synthetic source\n")
                return subprocess.CompletedProcess(command, 0, "")

            def extract_upstream(archive, destination):
                self.assertEqual(archive.read_bytes(), b"synthetic bytes for downloads/upstream/source.tar.xz")
                source = destination / "llvm-project-18.1.3.src"
                for relative in self.contract["relevantFiles"]:
                    target = source / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(b"matching synthetic source\n")
                return source

            class ReachedRunnerBounds(RuntimeError):
                pass

            with mock.patch.object(provision, "verify_candidate_data", return_value=[]) as signed, \
                    mock.patch.object(provision.subprocess, "run", side_effect=extract_dsc) as extracted, \
                    mock.patch.object(provision, "safe_extract_xz_tar", side_effect=extract_upstream) as upstream, \
                    mock.patch.object(provision, "check_runner_bounds", side_effect=ReachedRunnerBounds) as bounds, \
                    mock.patch.object(provision, "run_checked") as native:
                for label in ("run1", "run2"):
                    args = provision.argparse.Namespace(
                        contract=provision.CONTRACT_PATH, acquisition=root, keyring=keyring,
                        workdir=base / "work", rootfs=base / f"rootfs-{label}", output=base / label,
                    )
                    with self.subTest(label=label), self.assertRaises(ReachedRunnerBounds):
                        provision._provision_rootfs_unqualified(args)
                    self.assertFalse((root / "source/package-source").exists())
                    self.assertFalse((root / "source/upstream").exists())
                    self.assertEqual(list(root.glob("patch-audit-replay-*")), [])
                    self.assertEqual(json.loads((root / "acquisition-candidate.json").read_bytes()), candidate)
                    self.assertEqual({path.relative_to(root): provision.sha256_file(path)
                                      for path in (root / "downloads").rglob("*") if path.is_file()}, download_hashes)
                self.assertEqual(signed.call_count, 2)
                self.assertEqual(extracted.call_count, 2)
                self.assertEqual(upstream.call_count, 2)
                self.assertEqual(bounds.call_count, 2)
                native.assert_not_called()

    def test_optional_source_cache_cleanup_rejects_links_files_and_real_removal_failures(self):
        for relative in ("source", "source/package-source", "source/upstream"):
            for kind in ("file", "directory-link", "missing-link"):
                with self.subTest(relative=relative, kind=kind), self.temporary_directory() as temporary:
                    base = Path(temporary)
                    acquisition = base / "acquisition"
                    acquisition.mkdir()
                    ordinary = base / "ordinary"
                    ordinary.mkdir()
                    canary = ordinary / "canary.txt"
                    canary.write_bytes(b"preserve unrelated bytes")
                    malformed = acquisition / relative
                    malformed.parent.mkdir(parents=True, exist_ok=True)
                    if kind == "file":
                        malformed.write_bytes(b"not an extraction directory")
                    else:
                        malformed.symlink_to(ordinary if kind == "directory-link" else base / "absent")
                    with self.assertRaisesRegex(provision.ProvisionError, "source cache.*real directory"):
                        provision.remove_optional_source_caches(acquisition)
                    self.assertTrue(malformed.is_symlink() or malformed.is_file())
                    self.assertEqual(canary.read_bytes(), b"preserve unrelated bytes")
        with self.temporary_directory() as temporary:
            acquisition = Path(temporary) / "acquisition"
            cached = acquisition / "source/package-source"
            cached.mkdir(parents=True)
            with mock.patch.object(provision.shutil, "rmtree", side_effect=PermissionError("real removal refused")):
                with self.assertRaisesRegex(PermissionError, "real removal refused"):
                    provision.remove_optional_source_caches(acquisition)
            self.assertTrue(cached.is_dir())

    def test_optional_source_cache_cleanup_rejects_parent_swap_before_deleting_any_tree(self):
        with self.temporary_directory() as temporary:
            base = Path(temporary)
            acquisition = base / "acquisition"
            source = acquisition / "source"
            ordinary = base / "ordinary"
            for parent in (source, ordinary):
                for name in ("package-source", "upstream"):
                    tree = parent / name
                    tree.mkdir(parents=True)
                    (tree / "canary.txt").write_bytes(b"preserve this tree")
            held = acquisition / "source-held"
            real_stat = provision.os.stat
            swapped = False

            def swap_after_child_stat(path, *args, **kwargs):
                nonlocal swapped
                result = real_stat(path, *args, **kwargs)
                if path == "package-source" and kwargs.get("dir_fd") is not None and not swapped:
                    source.rename(held)
                    source.symlink_to(ordinary)
                    swapped = True
                return result

            with mock.patch.object(provision.os, "stat", side_effect=swap_after_child_stat), \
                    mock.patch.object(provision.shutil, "rmtree") as removed:
                with self.assertRaisesRegex(provision.ProvisionError, "cache parent pathname changed"):
                    provision.remove_optional_source_caches(acquisition)
                removed.assert_not_called()
            self.assertTrue(swapped)
            for parent in (held, ordinary):
                for name in ("package-source", "upstream"):
                    self.assertEqual((parent / name / "canary.txt").read_bytes(), b"preserve this tree")

    def test_candidate_replay_rejects_rehashed_attacker_owned_source_trees(self):
        with self.temporary_directory() as temp:
            root, candidate, record, keyring = self.candidate_fixture(Path(temp))
            for relative in self.contract["relevantFiles"]:
                for source_root in (root / "source/package-source",
                                    root / "source/upstream/llvm-project-18.1.3.src"):
                    target = source_root / relative
                    target.write_bytes(b"attacker-owned replacement\n")
            attacker_audit = provision.audit_patches(
                root / "source/package-source", root / "source/upstream/llvm-project-18.1.3.src",
                root / "attacker-patch-audit.json", self.contract,
            )
            shutil.copyfile(root / "attacker-patch-audit.json", root / "patch-audit.json")
            candidate["patchAudit"] = {key: attacker_audit[key] for key in (
                "status", "patchCount", "patchInventorySha256", "relevantFileCount", "relevantFileManifestSha256",
            )}
            record["patchAudit"] = dict(candidate["patchAudit"])
            self.write_candidate(root, candidate)
            record["acquisition"]["candidateSha256"] = candidate["candidateSha256"]

            def create_package_source(destination):
                destination.mkdir(parents=True)
                patches = destination / "debian/patches"
                patches.mkdir(parents=True)
                (patches / "series").write_bytes(b"")
                for relative in self.contract["relevantFiles"]:
                    target = destination / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(b"matching synthetic source\n")

            def extract_dsc(command, **kwargs):
                create_package_source(Path(command[-1]))
                return subprocess.CompletedProcess(command, 0, "")

            def extract_upstream(archive, destination):
                destination.mkdir(parents=True)
                source = destination / "llvm-project-18.1.3.src"
                source.mkdir()
                for relative in self.contract["relevantFiles"]:
                    target = source / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(b"matching synthetic source\n")
                return source

            with mock.patch.object(provision, "verify_candidate_data", return_value=[]), \
                    mock.patch.object(provision.subprocess, "run", side_effect=extract_dsc), \
                    mock.patch.object(provision, "safe_extract_xz_tar", side_effect=extract_upstream):
                with self.assertRaisesRegex(provision.ProvisionError, "patch audit inventory changed"):
                    provision.load_candidate(root, self.contract, keyring, record)
            self.assertEqual(list(root.glob("patch-audit-replay-*")), [])

    def test_candidate_replay_rejects_stale_self_digest_and_different_candidate(self):
        with self.temporary_directory() as temp:
            root, candidate, record, keyring = self.candidate_fixture(Path(temp))
            candidate["downloadedBytes"] += 1
            (root / "acquisition-candidate.json").write_bytes(provision.canonical_json(candidate))
            with self.assertRaisesRegex(provision.ProvisionError, "self-digest mismatch"):
                provision.load_candidate(root, self.contract, keyring, record)
            self.write_candidate(root, candidate)
            with self.assertRaisesRegex(provision.ProvisionError, "acquisition differs from the build record"):
                provision.load_candidate(root, self.contract, keyring, record)

    def test_candidate_replay_rejects_unrelated_record_sections(self):
        with self.temporary_directory() as temp:
            root, candidate, record, keyring = self.candidate_fixture(Path(temp))
            for section, field in (("acquisition", "sourceIndexesSha256"),
                                   ("acquisition", "binaryIndexesSha256"),
                                   ("source", "dsc"), ("patchAudit", "patchInventorySha256")):
                changed = json.loads(json.dumps(record))
                changed[section][field] = "f" * 64
                with self.subTest(section=section, field=field), self.assertRaisesRegex(
                    provision.ProvisionError, f"{section} differs from the build record"
                ):
                    provision.load_candidate(root, self.contract, keyring, changed)

    def test_candidate_download_inventory_rejects_changed_missing_extra_and_symlink_files(self):
        for mutation in ("same-size", "length", "missing", "extra", "symlink"):
            with self.subTest(mutation=mutation), self.temporary_directory() as temp:
                root, candidate, record, keyring = self.candidate_fixture(Path(temp))
                path = root / candidate["source"]["upstreamArchivePath"]
                if mutation == "same-size":
                    path.write_bytes(b"x" * path.stat().st_size)
                elif mutation == "length":
                    path.write_bytes(path.read_bytes() + b"x")
                elif mutation == "missing":
                    path.unlink()
                elif mutation == "extra":
                    (root / "downloads/unrecorded.txt").write_bytes(b"unrelated evidence")
                else:
                    path.unlink()
                    path.symlink_to(keyring)
                with mock.patch.object(provision, "verify_candidate_data") as signed:
                    with self.assertRaises(provision.ProvisionError):
                        provision.load_candidate(root, self.contract, keyring, record)
                    signed.assert_not_called()

    def test_candidate_replay_rejects_changed_recorded_patch_audit(self):
        for mutation in ("audit", "audit-details"):
            with self.subTest(mutation=mutation), self.temporary_directory() as temp:
                root, candidate, record, keyring = self.candidate_fixture(Path(temp))
                path = root / "patch-audit.json"
                trusted_replay = json.loads(path.read_bytes())
                audit = json.loads(path.read_bytes())
                if mutation == "audit":
                    audit["patchInventorySha256"] = "f" * 64
                else:
                    audit["patchInventory"] = []
                path.write_bytes(provision.canonical_json(audit))
                with mock.patch.object(provision, "verify_candidate_data", return_value=[]), \
                        mock.patch.object(provision, "audit_fresh_source_payloads", return_value=trusted_replay) as replay:
                    expected = "changed after acquisition" if mutation == "audit" else "patch audit inventory changed"
                    with self.assertRaisesRegex(provision.ProvisionError, expected):
                        provision.load_candidate(root, self.contract, keyring, record)
                    self.assertEqual(replay.call_count, int(mutation == "audit-details"))
                self.assertEqual(list(root.glob("patch-audit-replay-*")), [])

    def test_packaging_authenticates_candidate_before_creating_archive(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            root, candidate, record, keyring = self.candidate_fixture(base)
            rootfs = base / "rootfs"
            rootfs.mkdir()
            record_path = base / "record.json"
            record_path.write_bytes(provision.canonical_json(record))
            args = provision.argparse.Namespace(contract=provision.CONTRACT_PATH, record=record_path,
                                               acquisition=root, rootfs=rootfs, keyring=keyring,
                                               oci_archive=base / "run2.oci.tar",
                                               probe_report=base / "probe.json", loader_report=base / "loader.json",
                                               negative_report=base / "negative.json",
                                               negative_compiler=base / "retained-comparator",
                                               output=base / "provenance.tar")
            args.output = root / "not-created" / "nested" / "provenance.tar"
            with mock.patch.object(provision, "load_candidate") as load:
                with self.assertRaisesRegex(provision.ProvisionError, "overlaps a recursively packaged input tree"):
                    provision._package_provenance_unqualified(args)
                load.assert_not_called()
            self.assertFalse((root / "not-created").exists())

            args.output = base / "provenance.tar"
            with mock.patch.object(provision, "verify_candidate_data",
                                   side_effect=provision.ProvisionError("signature rejected")) as signed:
                with self.assertRaisesRegex(provision.ProvisionError, "signature rejected"):
                    provision._package_provenance_unqualified(args)
                expected_names = {row["name"] for section in ("packages", "downloadedPackages")
                                  for row in record[section]}
                signed.assert_called_once_with(root, candidate, self.contract, keyring,
                                               extra_binary_package_names=expected_names, captured=mock.ANY)
            self.assertFalse(args.output.exists())

    def test_package_provenance_rechecks_retained_rootfs_identity(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            _, _, record, _ = self.candidate_fixture(base)
            rootfs, oci_archive = self.retained_rootfs_image_fixture(base, record)
            changed = rootfs / record["runtime"]["entries"][0]["path"].lstrip("/")
            original_bytes = changed.read_bytes()
            changed.write_bytes(original_bytes + b"tamper")

            def local_tar(command, timeout=None, stdout_file=None):
                return subprocess.run(command[2:] if command[:2] == ["sudo", "-n"] else command[1:], check=False, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True, timeout=timeout) if stdout_file is None else subprocess.run(
                                          command[1:], check=False, stdout=stdout_file, stderr=subprocess.PIPE, timeout=timeout)

            with mock.patch.object(provision, "run_checked", side_effect=local_tar):
                with self.assertRaisesRegex(provision.ProvisionError, "retained rootfs differs"):
                    provision.verify_retained_rootfs_and_image(rootfs, oci_archive, record, self.contract)

            changed.write_bytes(original_bytes)
            with tarfile.open(oci_archive, mode="a") as archive:
                extra = tarfile.TarInfo("unrecorded-evidence")
                extra.size = 1
                archive.addfile(extra, io.BytesIO(b"x"))
            record["imageArtifact"] = {
                "bytes": oci_archive.stat().st_size, "sha256": provision.sha256_file(oci_archive),
            }
            with mock.patch.object(provision, "run_checked", side_effect=local_tar):
                with self.assertRaisesRegex(provision.ProvisionError, "unrecorded files or blobs"):
                    provision.verify_retained_rootfs_and_image(rootfs, oci_archive, record, self.contract)

    def test_full_probe_stage_normalize_retain_package_sequence_fails_closed_without_sandbox(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            root, candidate, record, keyring = self.candidate_fixture(base)
            selected = base / "selected-contract.json"
            selected.write_bytes(provision.canonical_json(self.contract))
            record["recipe"] = provision.recipe_identity(selected)
            record["probe"]["fixtureSha256"] = provision.sha256_file(
                ROOT / self.contract["negativeControl"]["fixture"])
            rootfs, oci_archive = self.retained_rootfs_image_fixture(base, record)
            self.authenticated_payloads_for_packaging_fixture(rootfs, record, base / "package-payloads")
            record_path = base / "record.json"
            record_path.write_bytes(provision.canonical_json(record))
            record_sha = provision.sha256_file(record_path)
            loader = ProvisioningNegativeTests.valid_loader_report(self, record, record_sha, rootfs)
            signed_rows = signed_package_rows_for_fixture(record)
            installed_keys = {
                (row["name"], row["version"], row["architecture"]) for row in record["packages"]
            }
            report_paths = {}
            for name, report in (("probe_report", record["probe"]), ("loader_report", loader),
                                 ("negative_report", {"scope": "synthetic negative test fixture"})):
                report_paths[name] = base / f"{name}.json"
                report_paths[name].write_bytes(provision.canonical_json(report))
            args = provision.argparse.Namespace(contract=selected, record=record_path, acquisition=root,
                                               rootfs=rootfs, oci_archive=oci_archive, keyring=keyring,
                                               negative_compiler=base / "retained-comparator",
                                               output=base / "provenance.tar", **report_paths)

            def local_tar(command, timeout=None, stdout_file=None):
                if command[:2] == ["sudo", "-n"]:
                    command = command[2:]
                elif command[:1] == ["sudo"]:
                    command = command[1:]
                return subprocess.run(command, check=False,
                                      stdout=subprocess.PIPE if stdout_file is None else stdout_file,
                                      stderr=subprocess.STDOUT if stdout_file is None else subprocess.PIPE,
                                      text=True, timeout=timeout)

            with mock.patch.object(provision, "pin_retained_rootfs_directory", side_effect=authored_retained_root_binding), \
                    mock.patch.object(provision, "load_candidate", return_value=(candidate, signed_rows)) as load, \
                    mock.patch.object(provision, "installed_package_keys", return_value=installed_keys), \
                    mock.patch.object(provision, "runtime_dependencies",
                                      return_value=record["runtime"]["entries"]) as runtime, \
                    mock.patch.object(provision, "rootfs_run") as chroot_run, \
                    mock.patch.object(provision, "run_checked", side_effect=local_tar), \
                    mock.patch.object(provision.BoundedDownloader, "get") as network:
                with self.assertRaisesRegex(provision.ProvisionError, "no reviewed unprivileged"):
                    provision._package_provenance_unqualified(args)
                load.assert_called_once()
                runtime.assert_not_called()
                network.assert_not_called()
            chroot_run.assert_not_called()
            self.assertFalse(args.output.exists())

    def authenticated_payloads_for_packaging_fixture(self, rootfs, record, destination):
        """Authored signed-index stand-in: archive actual inert fixture bytes, not a real package claim."""
        destination.mkdir()
        entries=[];inodes={}
        for count,path in enumerate(sorted(rootfs.rglob("*"))):
            if count>=4096:raise AssertionError("authored fixture inventory bound")
            metadata=path.lstat();name=path.relative_to(rootfs).as_posix();info=tarfile.TarInfo(name)
            info.mode=stat.S_IMODE(metadata.st_mode);info.uid=metadata.st_uid;info.gid=metadata.st_gid;data=b""
            if stat.S_ISLNK(metadata.st_mode):info.type=tarfile.SYMTYPE;info.linkname=os.readlink(path)
            elif stat.S_ISDIR(metadata.st_mode):info.type=tarfile.DIRTYPE
            elif stat.S_ISREG(metadata.st_mode):
                identity=(metadata.st_dev,metadata.st_ino)
                if identity in inodes:info.type=tarfile.LNKTYPE;info.linkname=inodes[identity]
                else:
                    inodes[identity]=name;data=path.read_bytes();info.size=len(data)
            else:raise AssertionError("unsupported authored fixture kind")
            entries.append((info,data))
        for index,row in enumerate(record["packages"]):
            data=authored_deb_payload(row,entries if index==0 else [])
            row.update(bytes=len(data),sha256=provision.sha256(data))
            (destination/(row["sha256"]+".deb")).write_bytes(data)
        expected={(row["name"],row["version"],row["architecture"]):row for row in record["packages"]}
        for row in record["downloadedPackages"]:
            row.update(expected[(row["name"],row["version"],row["architecture"])])

    @contextlib.contextmanager
    def offline_packaging_fixture(self, base):
        """Inert fixture; signatures, package query, probe and comparator execution are mocked."""
        root, candidate, record, keyring = self.candidate_fixture(base)
        selected = base / "contract.json"
        selected.write_bytes(provision.canonical_json(self.contract))
        record["recipe"] = provision.recipe_identity(selected)
        rootfs, image = self.retained_rootfs_image_fixture(base, record)
        inventory = provision.audit_langoptions(
            rootfs / "usr/lib/llvm-18/include/clang/Basic/LangOptions.def",
            rootfs / "usr/lib/llvm-18/include/clang/Basic/LangOptions.h", self.contract)
        for name in ("generatedFieldNames", "definitionSha256", "headerSha256"):
            record["probe"][name] = inventory[name]
        self.authenticated_payloads_for_packaging_fixture(rootfs, record, base / "package-payloads")
        record_path = base / "record.json"
        record_path.write_bytes(provision.canonical_json(record))
        negative_control = self.contract["negativeControl"]
        lock_path = ROOT / negative_control["artifactLock"]
        lock = json.loads(lock_path.read_bytes())
        artifact = lock["artifacts"][negative_control["artifactRole"]]
        negative = {"schemaVersion": 1,
            "scope": "negative-version-gate-only; not a Clang 18.1.3 identity",
            "artifactOracleId": negative_control["oracleId"],
            "artifactLockSha256": provision.sha256_file(lock_path),
            "compilerBytes": artifact["bytes"], "compilerSha256": artifact["sha256"],
            "compilerVersionOutput": "clang version 22.1.6\n",
            "fixtureBytes": (ROOT / negative_control["fixture"]).stat().st_size,
            "fixtureSha256": record["probe"]["fixtureSha256"], "fixtureAcceptedByClang22": True,
            "compiler18GateRejected": "probe compiler version or target mismatch"}
        reports = {"probe_report": record["probe"], "negative_report": negative,
            "loader_report": ProvisioningNegativeTests.valid_loader_report(
                self, record, provision.sha256_file(record_path), rootfs)}
        paths = {}
        for name, report in reports.items():
            paths[name] = base / (name + ".json")
            paths[name].write_bytes(provision.canonical_json(report))
        args = provision.argparse.Namespace(contract=selected, record=record_path,
            acquisition=root, rootfs=rootfs, oci_archive=image, keyring=keyring,
            negative_compiler=base / "retained-comparator",
            output=base / "provenance.tar", **paths)
        rows = signed_package_rows_for_fixture(record)
        installed = {(row["name"], row["version"], row["architecture"]) for row in record["packages"]}
        audit = json.loads((root / "patch-audit.json").read_bytes())

        def local_tar(command, timeout=None, stdout_file=None):
            if command[:2] == ["sudo", "-n"]:
                command = command[2:]
            elif command[:1] == ["sudo"]:
                command = command[1:]
            return subprocess.run(command, check=False,
                stdout=subprocess.PIPE if stdout_file is None else stdout_file,
                stderr=subprocess.STDOUT if stdout_file is None else subprocess.PIPE,
                text=True, timeout=timeout)

        with mock.patch.object(provision, "pin_retained_rootfs_directory", side_effect=authored_retained_root_binding), \
                mock.patch.object(provision, "verify_candidate_data", return_value=rows), \
                mock.patch.object(provision, "audit_fresh_source_payloads", return_value=audit), \
                mock.patch.object(provision, "installed_package_keys", return_value=installed), \
                mock.patch.object(provision, "runtime_dependencies", return_value=record["runtime"]["entries"]), \
                mock.patch.object(provision, "run_probe_sandboxed", side_effect=lambda root, command, contract, **kw:
                                      "clang version 18.1.3\n" if command[-1] == "--version"
                                      else provision.canonical_json(record["probe"])), \
                mock.patch.object(provision, "execute_locked_negative_comparator", return_value=negative), \
                mock.patch.object(provision, "run_checked", side_effect=local_tar):
            yield args, candidate

    def test_packaging_discovers_probe_only_runtime_dependency_from_ldd_output(self):
        actual_discovery = provision.runtime_dependencies
        with self.temporary_directory() as temp, self.offline_packaging_fixture(Path(temp)) as (args, _):
            record = json.loads(args.record.read_bytes())
            probe_only = "/usr/lib/llvm-18/lib/libclang.so"
            self.assertIn(probe_only, [row["path"] for row in record["runtime"]["entries"]])
            def inert_sandbox(root, command, contract, **kwargs):
                if command[-1] == "--version":
                    return "clang version 18.1.3\n"
                if command[0] == "/usr/bin/ldd":
                    return (f"\tlibclang.so => {probe_only} (0x1234)\n"
                            if command[1] == provision.PROBE_BINARY_IN_ROOT else "")
                return provision.canonical_json(record["probe"])
            with mock.patch.object(provision, "runtime_dependencies", wraps=actual_discovery), \
                    mock.patch.object(provision, "run_probe_sandboxed", side_effect=inert_sandbox) as sandbox:
                self.assertEqual(provision._package_provenance_unqualified(args), 0)
                args.output.unlink()
                ldd_roots = [call.args[1][1] for call in sandbox.call_args_list if call.args[1][0] == "/usr/bin/ldd"]
                self.assertEqual(ldd_roots, list(provision.FRONTEND_RUNTIME_ROOTS))
                self.assertIn(provision.PROBE_BINARY_IN_ROOT, ldd_roots)
                record["runtime"] = provision.manifest([
                    row for row in record["runtime"]["entries"] if row["path"] != probe_only])
                args.record.write_bytes(provision.canonical_json(record))
                loader = ProvisioningNegativeTests.valid_loader_report(
                    self, record, provision.sha256_file(args.record), args.rootfs)
                args.loader_report.write_bytes(provision.canonical_json(loader))
                provision.validate_build_record(record, self.contract, args.contract)
                provision.validate_provenance_loader_report(
                    loader, record, provision.sha256_file(args.record), args.rootfs)
                with self.assertRaisesRegex(provision.ProvisionError, "dependency closure"):
                    provision._package_provenance_unqualified(args)
                self.assertFalse(args.output.exists())

    def test_driver_replay_canonicalizes_raw_version_stdout_like_provisioning(self):
        with self.temporary_directory() as temp, self.offline_packaging_fixture(Path(temp)) as (args, _):
            record = json.loads(args.record.read_bytes())
            raw_stdout = "clang version 18.1.3\n"
            produced = [provision.driver_record(args.rootfs, path, role, raw_stdout.strip())
                        for role, path in provision.FRONTEND_DRIVER_ROOTS]
            self.assertEqual(record["tools"], produced)
            self.assertTrue(all(not row["versionOutput"].endswith("\n") for row in produced))
            with mock.patch.object(provision, "run_probe_sandboxed", return_value=raw_stdout) as sandbox:
                provision.verify_recorded_driver_identities(args.rootfs, record, self.contract)
            self.assertEqual([call.args[1] for call in sandbox.call_args_list],
                             [[path, "--version"] for _, path in provision.FRONTEND_DRIVER_ROOTS])

    def test_packaging_replays_both_drivers_and_rejects_rehashed_c_identity_changes(self):
        mutations = {
            "path": "/usr/bin/unrelated-18", "symlinkChain": [],
            "resolvedPath": "/usr/lib/llvm-18/bin/unrelated",
            "mode": "0555", "bytes": 999, "sha256": "f" * 64,
            "versionOutput": "unrelated clang version 18.1.3\n",
        }
        for field, changed in mutations.items():
            with self.subTest(field=field), self.temporary_directory() as temp, \
                    self.offline_packaging_fixture(Path(temp)) as (args, _):
                with mock.patch.object(provision, "run_probe_sandboxed", wraps=provision.run_probe_sandboxed) as sandbox:
                    self.assertEqual(provision._package_provenance_unqualified(args), 0)
                self.assertEqual([call.args[1] for call in sandbox.call_args_list[:2]],
                                 [[path, "--version"] for _, path in provision.FRONTEND_DRIVER_ROOTS])
                args.output.unlink()
                record = json.loads(args.record.read_bytes())
                driver = next(row for row in record["tools"] if row["role"] == "c-driver")
                self.assertNotEqual(driver[field], changed)
                driver[field] = changed
                args.record.write_bytes(provision.canonical_json(record))
                loader = ProvisioningNegativeTests.valid_loader_report(
                    self, record, provision.sha256_file(args.record), args.rootfs)
                args.loader_report.write_bytes(provision.canonical_json(loader))
                provision.validate_build_record(record, self.contract, args.contract)
                provision.validate_provenance_loader_report(
                    loader, record, provision.sha256_file(args.record), args.rootfs)
                with self.assertRaisesRegex(provision.ProvisionError, "driver identities"):
                    provision._package_provenance_unqualified(args)
                self.assertFalse(args.output.exists())

    def test_packaging_runtime_closure_rejects_rehashed_dependency_omission(self):
        with self.temporary_directory() as temp, self.offline_packaging_fixture(Path(temp)) as (args, _):
            self.assertEqual(provision._package_provenance_unqualified(args), 0)
            args.output.unlink()
            record = json.loads(args.record.read_bytes())
            actual_entries = record["runtime"]["entries"]
            self.assertGreater(len(actual_entries), 1)
            record["runtime"] = provision.manifest(actual_entries[:-1])
            args.record.write_bytes(provision.canonical_json(record))
            loader = ProvisioningNegativeTests.valid_loader_report(
                self, record, provision.sha256_file(args.record), args.rootfs)
            args.loader_report.write_bytes(provision.canonical_json(loader))
            # The shortened record and its loader projection are self-consistent;
            # only independent dependency discovery exposes the omitted library.
            provision.validate_build_record(record, self.contract, args.contract)
            provision.validate_provenance_loader_report(
                loader, record, provision.sha256_file(args.record), args.rootfs)
            with mock.patch.object(provision, "runtime_dependencies", return_value=actual_entries) as discover, \
                    mock.patch.object(provision, "run_probe_sandboxed", wraps=provision.run_probe_sandboxed) as probe:
                with self.assertRaisesRegex(provision.ProvisionError, "dependency closure"):
                    provision._package_provenance_unqualified(args)
            discover.assert_called_once_with(args.rootfs, list(provision.FRONTEND_RUNTIME_ROOTS), self.contract)
            self.assertEqual([call.args[1] for call in probe.call_args_list],
                             [[path, "--version"] for _, path in provision.FRONTEND_DRIVER_ROOTS])
            self.assertFalse(args.output.exists())

    def test_provenance_archives_captured_metadata_after_validated_path_replacement(self):
        with self.temporary_directory() as temp, self.offline_packaging_fixture(Path(temp)) as (args, candidate):
            originals = {"build-record.json": args.record.read_bytes(),
                "probe-report.json": args.probe_report.read_bytes(),
                "a-loader-smoke.json": args.loader_report.read_bytes(),
                "clang-22.1.6-negative-smoke.json": args.negative_report.read_bytes(),
                "acquisition/acquisition-candidate.json": (args.acquisition / "acquisition-candidate.json").read_bytes(),
                "acquisition/patch-audit.json": (args.acquisition / "patch-audit.json").read_bytes(),
                "provisioning-contract.json": args.contract.read_bytes()}
            validate = provision.validate_provenance_negative_report

            def validate_then_replace(*positional, **keywords):
                result = validate(*positional, **keywords)
                for path in (args.record, args.probe_report, args.loader_report, args.negative_report,
                             args.acquisition / "acquisition-candidate.json", args.acquisition / "patch-audit.json",
                             args.contract):
                    replacement = path.with_name(path.name + ".replacement")
                    replacement.write_bytes(b'{"replacement":true}\n')
                    replacement.replace(path)
                return result

            with mock.patch.object(provision, "validate_provenance_negative_report", side_effect=validate_then_replace):
                self.assertEqual(provision._package_provenance_unqualified(args), 0)
            with tarfile.open(args.output) as archive:
                for name, payload in originals.items():
                    self.assertEqual(archive.extractfile(name).read(), payload, name)
                for row in provision.candidate_download_rows(candidate):
                    payload = archive.extractfile("acquisition/" + row["path"]).read()
                    self.assertEqual(len(payload), row["bytes"])
                    self.assertEqual(provision.sha256(payload), row["sha256"])

    def test_provenance_refuses_equal_length_download_replacement_and_removes_archive(self):
        with self.temporary_directory() as temp, self.offline_packaging_fixture(Path(temp)) as (args, candidate):
            target = args.acquisition / candidate["source"]["files"][0]["path"]
            original = target.read_bytes()
            validate = provision.validate_provenance_negative_report

            def validate_then_replace(*positional, **keywords):
                result = validate(*positional, **keywords)
                target.write_bytes(b"x" * len(original))
                return result

            with mock.patch.object(provision, "validate_provenance_negative_report", side_effect=validate_then_replace):
                with self.assertRaisesRegex(provision.ProvisionError, "changed while packaging"):
                    provision._package_provenance_unqualified(args)
            self.assertFalse(args.output.exists())

    def test_provenance_stream_detects_in_place_changes_growth_and_truncation(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            # Write beyond BufferedReader's prefetch: changing bytes already
            # buffered is allowed when the archive still contains the original.
            original = b"a" * (3 * 1024 * 1024)
            source = base / "download"
            for kind in ("changed", "grown", "truncated"):
                source.write_bytes(original)
                output = base / (kind + ".tar")
                actual_add = tarfile.TarFile.addfile

                def mutate_while_reading(archive, info, fileobj):
                    class MutatingReader:
                        calls = 0
                        def read(self, size):
                            block = fileobj.read(size)
                            self.calls += 1
                            if self.calls == 1:
                                with source.open("r+b", buffering=0) as writer:
                                    if kind == "truncated":
                                        writer.truncate(16 * 1024)
                                    elif kind == "grown":
                                        writer.seek(0, os.SEEK_END)
                                        writer.write(b"extra")
                                    else:
                                        writer.seek(2 * 1024 * 1024)
                                        writer.write(b"x" * (1024 * 1024))
                            return block
                    return actual_add(archive, info, MutatingReader())

                with self.subTest(kind=kind), tarfile.open(output, "w") as archive, \
                        mock.patch.object(tarfile.TarFile, "addfile", new=mutate_while_reading):
                    with self.assertRaises((provision.ProvisionError, OSError)):
                        provision._add_provenance_file(archive, source, "download", 0,
                            expected_sha256=provision.sha256(original), expected_bytes=len(original))


    def test_packaging_refuses_synthesized_negative_report_without_retained_compiler(self):
        execute = provision.execute_locked_negative_comparator
        with self.temporary_directory() as temp, self.offline_packaging_fixture(Path(temp)) as (args, _):
            # Every public lock/fixture field passes the metadata validator;
            # actual replay must still require the retained native executable.
            with mock.patch.object(provision, "execute_locked_negative_comparator", side_effect=execute):
                with self.assertRaisesRegex(provision.ProvisionError, "immutable negative comparator"):
                    provision._package_provenance_unqualified(args)
            self.assertFalse(args.output.exists())

    def test_packaging_refuses_failed_comparator_execution_and_report_drift(self):
        for kind in ("failed-execution", "report-drift"):
            with self.subTest(kind=kind), self.temporary_directory() as temp, \
                    self.offline_packaging_fixture(Path(temp)) as (args, _):
                actual_report = json.loads(args.negative_report.read_bytes())
                actual_report["compilerVersionOutput"] += "actual replay output differs\n"
                kwargs = ({"side_effect": provision.ProvisionError("real syntax-only execution failed")}
                          if kind == "failed-execution" else {"return_value": actual_report})
                with mock.patch.object(provision, "execute_locked_negative_comparator", **kwargs) as execute:
                    with self.assertRaisesRegex(provision.ProvisionError, "execution failed|actual locked comparator replay"):
                        provision._package_provenance_unqualified(args)
                    execute.assert_called_once_with(args.negative_compiler,
                        ROOT / self.contract["negativeControl"]["fixture"], self.contract,
                        ROOT / self.contract["negativeControl"]["artifactLock"], captured=mock.ANY)
                self.assertFalse(args.output.exists())


    def test_record_commands_hash_the_raw_contract_snapshot_used_for_parsing(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            selected, record_path = base / "contract.json", base / "record.json"
            original = json.dumps(self.contract, indent=2).encode() + b"\n \n"
            read_contract, validate = provision.read_contract, provision.validate_build_record
            for command in (provision.command_verify_record, provision.command_write_loader_input,
                            provision.command_verify_image, provision._package_provenance_unqualified):
                selected.write_bytes(original)
                record = self.valid_build_record()
                record["recipe"] = provision.recipe_identity(selected)
                record_path.write_bytes(provision.canonical_json(record))
                snapshots = []
                def read_then_replace(path, **kwargs):
                    parsed = read_contract(path, **kwargs)
                    snapshots.append(kwargs.get("captured"))
                    replacement = selected.with_suffix(".replacement")
                    replacement.write_bytes(b'{"replacement":true}\n')
                    replacement.replace(selected)
                    return parsed
                def validate_snapshot(value, contract, path, **kwargs):
                    self.assertIs(kwargs.get("captured"), snapshots[0])
                    self.assertEqual(kwargs["captured"][selected], original)
                    validate(value, contract, path, **kwargs)
                    self.assertEqual(value["recipe"]["contractSha256"], provision.sha256(original))
                    raise provision.ProvisionError("captured validation complete")
                args = provision.argparse.Namespace(contract=selected, record=record_path)
                with self.subTest(command=command.__name__), mock.patch.object(
                        provision, "read_contract", side_effect=read_then_replace), mock.patch.object(
                        provision, "validate_build_record", side_effect=validate_snapshot):
                    with self.assertRaisesRegex(provision.ProvisionError, "captured validation complete"):
                        command(args)

    def test_compare_and_snapshot_metadata_keep_selected_raw_contract_after_replacement(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            selected = base / "contract.json"
            original = json.dumps(self.contract, indent=2).encode() + b" \n"
            selected.write_bytes(original)
            record = self.valid_build_record()
            record["recipe"] = provision.recipe_identity(selected)
            first, second, output = base / "first.json", base / "second.json", base / "final.json"
            first.write_bytes(provision.canonical_json(record))
            second.write_bytes(provision.canonical_json(record))
            read_contract = provision.read_contract
            snapshots = []
            def read_then_replace(path, **kwargs):
                parsed = read_contract(path, **kwargs)
                snapshots.append(kwargs["captured"])
                selected.write_bytes(b'{"replacement":true}\n')
                return parsed
            args = provision.argparse.Namespace(contract=selected, first=first, second=second, output=output)
            with mock.patch.object(provision, "read_contract", side_effect=read_then_replace):
                self.assertEqual(provision.command_compare_runs(args), 0)
            self.assertEqual(json.loads(output.read_bytes())["recipe"]["contractSha256"], provision.sha256(original))
            keyring = base / "keyring"
            keyring.write_bytes(b"inert keyring fixture")
            report = provision.snapshot_metadata_selection(self.contract, self.contract["profile"],
                [], [], [], [], 0, keyring, selected, captured=snapshots[0])
            self.assertEqual(report["contractSha256"], provision.sha256(original))
            self.assertEqual(report["recipe"], record["recipe"])

    def test_record_commands_refuse_digest_from_replacement_contract_semantics(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            selected, record_path = base / "contract.json", base / "record.json"
            original = json.loads(json.dumps(self.contract))
            original["environment"]["PATH"] = "/custom/bin"
            replacement = provision.canonical_json(self.contract)
            read_contract, validate = provision.read_contract, provision.validate_build_record
            for command in (provision.command_verify_record, provision.command_write_loader_input,
                            provision.command_verify_image, provision._package_provenance_unqualified):
                selected.write_bytes(provision.canonical_json(original))
                record = self.valid_build_record()
                record["environment"] = original["environment"]
                record["commands"] = provision.canonical_commands(original, record["acquisition"]["ubuntuKeyring"]["sha256"])
                record["recipe"]["contractSha256"] = provision.sha256(replacement)
                record_path.write_bytes(provision.canonical_json(record))
                def read_then_replace(path, **kwargs):
                    parsed = read_contract(path, **kwargs)
                    selected.write_bytes(replacement)
                    return parsed
                def validate_then_stop(*args, **kwargs):
                    validate(*args, **kwargs)
                    raise provision.ProvisionError("unsafe replacement digest accepted")
                args = provision.argparse.Namespace(contract=selected, record=record_path)
                with self.subTest(command=command.__name__), mock.patch.object(
                        provision, "read_contract", side_effect=read_then_replace), mock.patch.object(
                        provision, "validate_build_record", side_effect=validate_then_stop):
                    with self.assertRaisesRegex(provision.ProvisionError, "recipe hashes"):
                        command(args)

    def test_direct_record_and_metadata_consumers_refuse_unbound_parsed_contract(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            selected, keyring = base / "contract.json", base / "keyring"
            changed = json.loads(json.dumps(self.contract))
            changed["environment"]["PATH"] = "/custom/bin"
            selected.write_bytes(provision.canonical_json(changed))
            admitted = provision.read_contract(selected)
            selected.write_bytes(provision.canonical_json(self.contract))
            record = self.valid_build_record()
            record["environment"] = admitted["environment"]
            record["commands"] = provision.canonical_commands(admitted, record["acquisition"]["ubuntuKeyring"]["sha256"])
            keyring.write_bytes(b"inert keyring")
            with self.assertRaisesRegex(provision.ProvisionError, "contract snapshot"):
                provision.validate_build_record(record, admitted, selected)
            with self.assertRaisesRegex(provision.ProvisionError, "contract snapshot"):
                provision.snapshot_metadata_selection(admitted, admitted["profile"], [], [], [], [], 0,
                                                     keyring, selected)


class ConsumerReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = provision.read_contract()
        (ROOT / "build").mkdir(exist_ok=True)
        cls.temp_root = Path(tempfile.mkdtemp(prefix="clang1813-consumer-replay-tests-", dir=ROOT / "build"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_root, ignore_errors=True)

    def temporary_directory(self):
        return tempfile.TemporaryDirectory(dir=self.temp_root)

    def image_fixture(self, base, reverse=False, padding=0):
        payload = b"offline OCI consumer canary; not a qualified native image"
        rootfs = base / "rootfs.tar"
        rootfs.write_bytes(payload)
        layout = base / "layout"
        image = provision.create_oci_layout(rootfs, layout, "fixture", self.contract["environment"])
        path = base / "image.tar"
        with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
            for source in sorted((p for p in layout.rglob("*") if p.is_file()), reverse=reverse):
                data = source.read_bytes()
                info = tarfile.TarInfo(source.relative_to(layout).as_posix())
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        if padding:
            with path.open("ab") as stream:
                stream.write(b"\0" * padding)
        record = {"profile": {"id": "fixture"}, "environment": self.contract["environment"],
            "rootfs": {"bytes": len(payload), "sha256": provision.sha256(payload)}, "image": image,
            "imageArtifact": {"bytes": path.stat().st_size, "sha256": provision.sha256_file(path)}}
        return path, record

    def test_oci_reordered_regular_members_are_accepted(self):
        with self.temporary_directory() as temp:
            path, record = self.image_fixture(Path(temp), reverse=True)
            provision.verify_oci_archive(path, record, 4 * 1024 * 1024)

    def test_oci_path_swap_after_authentication_rejects_semantically_identical_tar(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            path, record = self.image_fixture(base)
            original = path.read_bytes()
            header = tarfile.TarInfo.frombuf(original[:512], "utf-8", "strict")
            header.uid = 42
            replacement = base / "replacement.tar"
            replacement.write_bytes(header.tobuf(format=tarfile.USTAR_FORMAT) + original[512:])
            self.assertNotEqual(provision.sha256_file(replacement), record["imageArtifact"]["sha256"])
            actual_open = tarfile.open
            def swap(*args, **kwargs):
                self.assertIsInstance(kwargs.get("fileobj"), provision.AuthenticatedOCIReader)
                replacement.replace(path)
                return actual_open(*args, **kwargs)
            with mock.patch.object(provision.tarfile, "open", side_effect=swap):
                with self.assertRaisesRegex(provision.ProvisionError, "retained path changed"):
                    provision.verify_oci_archive(path, record, 4 * 1024 * 1024)

    def test_oci_transient_inplace_header_mutation_is_refused_before_consumption(self):
        with self.temporary_directory() as temp:
            path, record = self.image_fixture(Path(temp))
            original = path.read_bytes()
            header = tarfile.TarInfo.frombuf(original[:512], "utf-8", "strict")
            header.uid = 42
            changed_header = header.tobuf(format=tarfile.USTAR_FORMAT)
            actual_read = provision.AuthenticatedOCIReader.read
            def mutate(reader, size=-1):
                with path.open("r+b", buffering=0) as writer:
                    writer.write(changed_header)
                    try:
                        return actual_read(reader, size)
                    finally:
                        writer.seek(0)
                        writer.write(original[:512])
            with mock.patch.object(provision.AuthenticatedOCIReader, "read", new=mutate):
                with self.assertRaisesRegex(provision.ProvisionError, "authenticated consumer read"):
                    provision.verify_oci_archive(path, record, 4 * 1024 * 1024)
            self.assertEqual(path.read_bytes(), original)

    def test_oci_growth_truncation_and_unconsumed_padding_mutations_are_refused(self):
        for kind in ("growth", "truncation", "padding"):
            with self.subTest(kind=kind), self.temporary_directory() as temp:
                path, record = self.image_fixture(Path(temp), padding=2 * 1024 * 1024)
                actual_open = tarfile.open
                def mutate(*args, **kwargs):
                    archive = actual_open(*args, **kwargs)
                    with path.open("r+b", buffering=0) as writer:
                        if kind == "growth":
                            writer.seek(0, os.SEEK_END)
                            writer.write(b"extra")
                        elif kind == "truncation":
                            writer.truncate(record["imageArtifact"]["bytes"] - 512)
                        else:
                            writer.seek(-1, os.SEEK_END)
                            writer.write(b"x")
                    return archive
                with mock.patch.object(provision.tarfile, "open", side_effect=mutate):
                    with self.assertRaisesRegex(provision.ProvisionError, "artifact identity|truncated"):
                        provision.verify_oci_archive(path, record, 4 * 1024 * 1024)

    def test_oci_symlink_fifo_and_sparse_extended_metadata_are_refused(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            path, record = self.image_fixture(base)
            for kind in ("symlink", "fifo"):
                alias = base / kind
                alias.symlink_to(path) if kind == "symlink" else os.mkfifo(alias)
                with self.subTest(kind=kind), self.assertRaisesRegex(provision.ProvisionError, "regular|verify OCI"):
                    provision.verify_oci_archive(alias, record, 4 * 1024 * 1024)
            for kind in ("pax-budget", "gnu-sparse", "pax-sparse"):
                info = tarfile.TarInfo("canary")
                if kind == "pax-budget":
                    info.type, info.size = tarfile.XHDTYPE, 64 * 1024 + 1
                    payload = info.tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * (info.size + 1024)
                elif kind == "gnu-sparse":
                    info.type, info.size = tarfile.GNUTYPE_SPARSE, 1
                    payload = info.tobuf(format=tarfile.GNU_FORMAT) + b"\0" * 1024
                else:
                    output = io.BytesIO()
                    info.pax_headers = {"GNU.sparse.map": "0,1", "GNU.sparse.size": str(2 ** 40)}
                    info.size = 1
                    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
                        archive.addfile(info, io.BytesIO(b"x"))
                    payload = output.getvalue()
                malformed = base / (kind + ".tar")
                malformed.write_bytes(payload)
                record["imageArtifact"] = {"bytes": len(payload), "sha256": provision.sha256(payload)}
                with self.subTest(kind=kind), self.assertRaisesRegex(provision.ProvisionError, "metadata|sparse"):
                    provision.verify_oci_archive(malformed, record, 4 * 1024 * 1024)

    def test_negative_comparator_requires_locked_regular_bytes_before_execution(self):
        with self.temporary_directory() as temp:
            base = Path(temp)
            compiler = base / "compiler"
            compiler.write_bytes(b"unlocked executable")
            for kind in ("changed", "symlink", "fifo"):
                selected = compiler
                if kind != "changed":
                    selected = base / kind
                    selected.symlink_to(compiler) if kind == "symlink" else os.mkfifo(selected)
                with self.subTest(kind=kind), mock.patch.object(provision, "run_checked") as execute:
                    with self.assertRaises(provision.ProvisionError):
                        provision.execute_locked_negative_comparator(selected,
                            ROOT / self.contract["negativeControl"]["fixture"], self.contract,
                            ROOT / self.contract["negativeControl"]["artifactLock"])
                    execute.assert_not_called()

    def test_real_elf_comparator_and_fixture_use_sealed_snapshots_despite_path_replacement(self):
        """Real host ELF execution with a test lock; never claims the actual LLVM artifact ran."""
        with self.temporary_directory() as temp:
            base = Path(temp)
            fixture_bytes = (ROOT / self.contract["negativeControl"]["fixture"]).read_bytes()
            fixture = base / "fixture.cpp"
            fixture.write_bytes(fixture_bytes)
            source = base / "consumer.c"
            source.write_text(r'''
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static const unsigned char fixture[] = {''' + ",".join(str(b) for b in fixture_bytes) + r'''};
int main(int argc, char **argv) {
    int fd = atoi(strrchr(argv[0], '/') + 1);
    struct stat st;
    int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (fstat(fd, &st) || st.st_uid != getuid() || (st.st_mode & 0777) != 0555 ||
        (fcntl(fd, F_GET_SEALS) & seals) != seals) return 11;
    if (argc == 2 && !strcmp(argv[1], "--version")) { puts("clang version 22.1.6"); return 0; }
    if (argc != 8 || strcmp(argv[1], "--no-default-config") ||
        strcmp(argv[2], "--target=x86_64-pc-linux-gnu") || strcmp(argv[3], "-std=c++14") ||
        strcmp(argv[4], "-fsyntax-only") || strcmp(argv[5], "-x") || strcmp(argv[6], "c++")) return 12;
    FILE *input = fopen(argv[7], "rb");
    unsigned char data[sizeof(fixture) + 1];
    if (!input || fread(data, 1, sizeof(data), input) != sizeof(fixture) ||
        memcmp(data, fixture, sizeof(fixture))) return 13;
    fclose(input);
    fd = atoi(strrchr(argv[7], '/') + 1);
    return (fcntl(fd, F_GET_SEALS) & seals) == seals ? 0 : 14;
}
''', encoding="utf-8")
            compiler = base / "consumer"
            subprocess.run(["/usr/bin/cc", str(source), "-o", str(compiler)], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                           env={**os.environ, "TMPDIR": str(base)})
            expected = {"bytes": compiler.stat().st_size, "sha256": provision.sha256_file(compiler)}
            lock = base / "offline-lock.json"
            lock.write_bytes(b'{"scope":"offline ELF canary only"}\n')
            actual_run = provision.run_checked
            calls = []
            def replace_then_run(command, **kwargs):
                calls.append(command)
                compiler.write_bytes(b"replacement must never execute")
                fixture.write_bytes(b"replacement fixture must never be consumed")
                return actual_run(command, **kwargs)
            with mock.patch.object(provision, "validate_locked_comparator_manifest",
                                   return_value=({}, lock, provision.sha256_file(lock), expected)), \
                    mock.patch.object(provision, "run_checked", side_effect=replace_then_run):
                report = provision.execute_locked_negative_comparator(compiler, fixture, self.contract, lock)
            self.assertEqual(len(calls), 2)
            self.assertTrue(all(command[0].startswith("/proc/self/fd/") for command in calls))
            self.assertEqual(report["compilerSha256"], expected["sha256"])
            self.assertEqual(report["fixtureSha256"], provision.sha256(fixture_bytes))
            self.assertTrue(report["fixtureAcceptedByClang22"])
            self.assertEqual(report["compiler18GateRejected"], "probe compiler version or target mismatch")


class HostWorkerProtocolTests(unittest.TestCase):
    """Inert approvals/runtime fixtures; none authorize a production environment."""
    def setUp(self):
        self.worker = provision.host_worker
        self.temporary = tempfile.TemporaryDirectory(prefix="clang1813-host-protocol-", dir=ROOT / "build")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.store = self.base / "approved"
        self.store.mkdir()
        self.source = self.base / "source.cpp"
        self.source.write_bytes(b"synthetic approved source; never a production approval\n")
        self.input_fd = os.open(self.source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.addCleanup(os.close, self.input_fd)
        self.manifest = {
            "formatVersion": 1, "action": "provision-rootfs-v1",
            "inputs": [{"name": "source.cpp", "bytes": self.source.stat().st_size,
                        "sha256": self.worker.digest(self.source.read_bytes())}],
            "argv": ["/usr/bin/true"],
            "environment": {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "7"},
            "limits": {"seconds": 30, "memoryBytes": 64 * 1024**2, "cpus": 1, "pids": 16,
                       "diskBytes": 1024**2, "outputBytes": 1024},
        }
        fixture_digest = lambda label: "sha256:" + self.worker.digest(label.encode())
        self.lock = {"formatVersion": 1, "manifestDigest": fixture_digest("inert OCI manifest"),
                     "configDigest": fixture_digest("inert OCI config"), "rootfsDiffIds": [fixture_digest("inert layer")],
                     "platform": {"os": "linux", "architecture": "amd64"},
                     "inputRecipeSha256": self.worker.digest(self.worker.canonical(self.manifest)),
                     "packageManifestSha256": self.worker.digest(b"inert package manifest"),
                     "runtimeCli": {"path": "/usr/bin/docker", "bytes": 10,
                                    "sha256": self.worker.digest(b"inert CLI")}}
        self.lock_sha = self.write_approved(self.lock, ".lock.json")
        self.write_approved(self.manifest, ".action.json")
        self.index = {"formatVersion": 1, "actions": {"provision-rootfs-v1": self.lock_sha}}
        index_sha = self.write_approved(self.index, ".index.json")
        self.anchor = {"formatVersion": 1, "authorityKeyFingerprint": "A" * 40,
                       "approvedIndexSha256": index_sha, "launcherSha256": self.worker.digest(b"inert installed launcher")}
        (self.store / "approval-anchor.json").write_bytes(self.worker.canonical(self.anchor))
        store_patch = mock.patch.object(self.worker, "APPROVAL_STORE", self.store)
        store_patch.start()
        self.addCleanup(store_patch.stop)
        original_check = self.worker.root_owned
        def simulated_root(metadata, *, directory=False):
            fields = list(metadata)
            fields[stat.ST_UID] = 0
            return original_check(os.stat_result(fields), directory=directory)
        owner_patch = mock.patch.object(self.worker, "root_owned", side_effect=simulated_root)
        owner_patch.start()
        self.addCleanup(owner_patch.stop)
        worker = self.worker
        class InertRuntime:
            calls = 0
            snapshots = []
            def inspect_image(runtime, lock):
                return json.loads(json.dumps(worker.expected_image(lock)))
            def execute(runtime, spec, inputs):
                runtime.calls += 1
                runtime.snapshots = list(inputs.values())
                for descriptor in inputs.values():
                    self.assertEqual(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & worker.SEALS, worker.SEALS)
                    with self.assertRaises(OSError) as caught:
                        os.pwrite(descriptor, b"tamper", 0)
                    self.assertEqual(caught.exception.errno, errno.EPERM)
                runtime.payloads = {name: worker.read_descriptor(fd, worker.MAX_INPUT) for name, fd in inputs.items()}
                runtime.spec = spec
                return {"executionSha256": worker.digest(worker.canonical(spec)), "image": spec["image"],
                        "exitCode": 0, "stdout": b"inert execution output"}
        self.backend = InertRuntime()

    def write_approved(self, value, suffix):
        payload = self.worker.canonical(value)
        identity = self.worker.digest(payload)
        (self.store / (identity + suffix)).write_bytes(payload)
        return identity

    def execute(self, backend=None, lock_sha=None, input_fds=None):
        return self.worker._execute_approved_protocol(
            "provision-rootfs-v1", lock_sha or self.lock_sha,
            {"source.cpp": self.input_fd} if input_fds is None else input_fds,
            self.backend if backend is None else backend)

    def test_approved_store_and_exact_closure_succeed_with_sealed_input_cleanup(self):
        result = self.execute()
        self.assertEqual(result.stdout, b"inert execution output")
        self.assertEqual(result.lock_sha256, self.lock_sha)
        self.assertEqual(result.action_sha256, self.lock["inputRecipeSha256"])
        self.assertEqual(self.backend.calls, 1)
        for descriptor in self.backend.snapshots:
            with self.assertRaises(OSError) as caught:
                os.fstat(descriptor)
            self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_forged_self_consistent_lock_image_and_recipe_cannot_authorize_action(self):
        forged = json.loads(json.dumps(self.lock))
        forged["configDigest"] = "sha256:" + self.worker.digest(b"attacker config")
        forged_sha = self.write_approved(forged, ".lock.json")
        with self.assertRaisesRegex(self.worker.WorkerRefusal, "not independently approved"):
            self.execute(lock_sha=forged_sha)
        self.assertEqual(self.backend.calls, 0)

    def test_approved_environment_refuses_attacker_source_and_missing_or_extra_closure(self):
        self.source.write_bytes(b"attacker supplies its own self-consistent source/recipe")
        with self.assertRaisesRegex(self.worker.WorkerRefusal, "not independently approved|changed length|bounded regular"):
            self.execute()
        for inputs in ({}, {"unapproved.cpp": self.input_fd}, {"source.cpp": self.input_fd, "extra": self.input_fd}):
            with self.subTest(inputs=list(inputs)), self.assertRaisesRegex(self.worker.WorkerRefusal, "complete approved source closure"):
                self.execute(input_fds=inputs)
        self.assertEqual(self.backend.calls, 0)

    def test_approved_lock_refuses_modified_action_or_approval_index_before_execution(self):
        for identity, suffix in ((self.lock["inputRecipeSha256"], ".action.json"),
                                 (self.anchor["approvedIndexSha256"], ".index.json")):
            path = self.store / (identity + suffix)
            original = path.read_bytes()
            path.write_bytes(original + b" ")
            with self.subTest(suffix=suffix), self.assertRaisesRegex(self.worker.WorkerRefusal, "metadata digest mismatch"):
                self.execute()
            path.write_bytes(original)
        self.assertEqual(self.backend.calls, 0)

    def test_approval_store_refuses_symlinks_and_caller_writable_metadata(self):
        anchor = self.store / "approval-anchor.json"
        original = anchor.read_bytes()
        anchor.chmod(0o666)
        with self.assertRaisesRegex(self.worker.WorkerRefusal, "root-owned and protected"):
            self.execute()
        anchor.chmod(0o644)
        anchor.unlink()
        target = self.base / "caller-anchor"
        target.write_bytes(original)
        anchor.symlink_to(target)
        with self.assertRaisesRegex(self.worker.WorkerRefusal, "approval store is unavailable"):
            self.execute()
        self.assertEqual(self.backend.calls, 0)

    def test_transient_checkout_source_swap_cannot_change_consumed_sealed_bytes(self):
        original = self.source.read_bytes()
        execute = self.backend.execute
        def swap_then_execute(spec, inputs):
            self.source.write_bytes(b"transient unchecked checkout replacement")
            try:
                return execute(spec, inputs)
            finally:
                self.source.write_bytes(original)
        self.backend.execute = swap_then_execute
        self.execute()
        self.assertEqual(self.backend.payloads["source.cpp"], original)

    def test_runtime_image_and_post_create_execution_identity_are_independently_checked(self):
        original_inspect = self.backend.inspect_image
        self.backend.inspect_image = lambda lock: {**original_inspect(lock), "configDigest": "sha256:" + "f" * 64}
        with self.assertRaisesRegex(self.worker.WorkerRefusal, "actual runtime-selected image"):
            self.execute()
        self.assertEqual(self.backend.calls, 0)
        self.backend.inspect_image = original_inspect
        execute = self.backend.execute
        def changed_receipt(spec, inputs):
            return {**execute(spec, inputs), "executionSha256": "f" * 64}
        self.backend.execute = changed_receipt
        with self.assertRaisesRegex(self.worker.WorkerRefusal, "execution identity changed"):
            self.execute()

    def test_failed_backend_closes_real_sealed_descriptors(self):
        observed = []
        def failed(spec, inputs):
            observed.extend(inputs.values())
            raise self.worker.WorkerRefusal("injected runtime refusal")
        self.backend.execute = failed
        with self.assertRaisesRegex(self.worker.WorkerRefusal, "runtime refusal"):
            self.execute()
        self.assertTrue(observed)
        for descriptor in observed:
            with self.assertRaises(OSError) as caught:
                os.fstat(descriptor)
            self.assertEqual(caught.exception.errno, errno.EBADF)

    def daemon_container_fixture(self, spec, source):
        limits = spec["limits"]
        return {"Image": spec["image"]["configDigest"],
                "Config": {"User": "65532:65532", "Entrypoint": ["/usr/bin/env"], "WorkingDir": "/work",
                           "Env": [f"{k}={v}" for k, v in sorted(self.worker.DockerBackend.container_environment(spec).items())],
                           "Cmd": ["-i", *[f"{k}={v}" for k, v in sorted(spec["environment"].items())], *spec["argv"]]},
                "HostConfig": {"ReadonlyRootfs": True, "Privileged": False, "NetworkMode": "none", "CapDrop": ["ALL"],
                               "SecurityOpt": ["no-new-privileges=true"], "Memory": limits["memoryBytes"],
                               "MemorySwap": limits["memoryBytes"], "NanoCpus": limits["cpus"] * 1_000_000_000,
                               "PidsLimit": limits["pids"], "IpcMode": "private",
                               "Ulimits": [{"Name": "core", "Soft": 0, "Hard": 0},
                                           {"Name": "fsize", "Soft": limits["diskBytes"], "Hard": limits["diskBytes"]}],
                               "Tmpfs": {"/work": f"rw,noexec,nosuid,nodev,size={limits['diskBytes']},uid=65532,gid=65532,mode=0700"}},
                "Mounts": [{"Type": "bind", "Source": source, "Destination": "/inputs", "RW": False, "Propagation": "rprivate"}],
                "State": {"Running": False, "OOMKilled": False, "ExitCode": 0}}

    def test_held_stage_preserves_snapshots_and_refuses_foreign_name_cleanup(self):
        stage_parent = self.base / "stage-parent"
        stage_parent.mkdir()
        parent_fd = os.open(stage_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, parent_fd)
        backend = self.worker.DockerBackend(self.lock, parent_fd)
        with self.worker.sealed_snapshot(self.source.read_bytes()) as source_fd:
            with self.assertRaisesRegex(self.worker.WorkerRefusal, "foreign cleanup"):
                with backend.stage_inputs({"nested/source.cpp": source_fd}) as held_path:
                    self.assertEqual((Path(held_path) / "nested/source.cpp").read_bytes(), self.source.read_bytes())
                    held_fd = int(Path(held_path).name)
                    original = Path(os.readlink(held_path))
                    original.rename(stage_parent / "retained")
                    original.mkdir()
                    (original / "foreign-canary").write_bytes(b"must not be removed")
        self.assertEqual((original / "foreign-canary").read_bytes(), b"must not be removed")
        self.assertEqual(list((stage_parent / "retained").iterdir()), [])
        with self.assertRaises(OSError) as caught:
            os.fstat(held_fd)
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_held_stage_file_and_directory_modes_ignore_restrictive_umask(self):
        parent = self.base / "mode-stage-parent"
        parent.mkdir()
        descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, descriptor)
        backend = self.worker.DockerBackend(self.lock, descriptor)
        with self.worker.sealed_snapshot(self.source.read_bytes()) as source:
            for mask in (0o022, 0o077, 0o777):
                previous = os.umask(mask)
                try:
                    with backend.stage_inputs({"top.cpp": source, "nested/deep/source.cpp": source,
                                               "nested/other.cpp": source}) as held:
                        root = Path(held)
                        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o555)
                        for relative in ("nested", "nested/deep"):
                            self.assertEqual(stat.S_IMODE((root / relative).stat().st_mode), 0o755)
                        for relative in ("top.cpp", "nested/deep/source.cpp", "nested/other.cpp"):
                            path = root / relative
                            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
                            self.assertEqual(path.read_bytes(), self.source.read_bytes())
                finally:
                    os.umask(previous)
                self.assertEqual(list(parent.iterdir()), [])

    def test_concrete_backend_checks_daemon_isolation_and_fixed_arguments(self):
        self.execute()
        spec = self.backend.spec
        source = "/proc/123/fd/456"
        args = self.worker.DockerBackend.create_arguments(spec, source)
        for required in ("--pull=never", "--read-only", "--network=none", "--cap-drop=ALL", "--user=65532:65532"):
            self.assertIn(required, args)
        raw = self.daemon_container_fixture(spec, source)
        self.worker.DockerBackend.verify_container(raw, spec, source)
        for field, value in (("ReadonlyRootfs", False), ("Privileged", True), ("NetworkMode", "host"),
                             ("CapDrop", []), ("SecurityOpt", []), ("PidsLimit", 0), ("Ulimits", []), ("IpcMode", "host")):
            changed = json.loads(json.dumps(raw))
            changed["HostConfig"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(self.worker.WorkerRefusal, "daemon-measured container"):
                self.worker.DockerBackend.verify_container(changed, spec, source)
        changed = json.loads(json.dumps(raw))
        changed["Config"]["Env"].append("LD_PRELOAD=/unchecked/injection.so")
        with self.assertRaisesRegex(self.worker.WorkerRefusal, "daemon-measured container"):
            self.worker.DockerBackend.verify_container(changed, spec, source)
        changed = json.loads(json.dumps(raw))
        changed["Mounts"][0]["RW"] = True
        with self.assertRaises(self.worker.WorkerRefusal):
            self.worker.DockerBackend.verify_container(changed, spec, source)

    def test_concrete_backend_measures_before_and_after_run_and_cleans_container(self):
        self.execute()
        spec = self.backend.spec
        source = "/proc/123/fd/456"
        @contextlib.contextmanager
        def staged(inputs):
            yield source
        for malformed in (False, True):
            backend = self.worker.DockerBackend(self.lock, None)
            raw = self.daemon_container_fixture(spec, source)
            def daemon(arguments, **kwargs):
                if arguments[0] == "create":
                    name = next(item.removeprefix("--name=") for item in arguments if item.startswith("--name="))
                    token = next(item.split("=", 2)[2] for item in arguments if item.startswith("--label="))
                    raw.update(Id="a" * 64, Name="/" + name)
                    raw["Config"]["Labels"] = {self.worker.ATTEMPT_LABEL: token}
                    if malformed:
                        raw["Image"] = "sha256:" + "f" * 64
                    return b"a" * 64 + b"\n"
                if arguments[:2] == ["container", "inspect"]:
                    return self.worker.canonical(raw)
                return b"inert output" if arguments[0] == "start" else b""
            with self.subTest(malformed=malformed), mock.patch.object(backend, "stage_inputs", side_effect=staged), \
                    mock.patch.object(backend, "command", side_effect=daemon) as command:
                if malformed:
                    with self.assertRaisesRegex(self.worker.WorkerRefusal, "daemon-measured container"):
                        backend.execute(spec, {})
                    self.assertFalse(any(call.args[0][0] == "start" for call in command.call_args_list))
                else:
                    self.assertEqual(backend.execute(spec, {})["stdout"], b"inert output")
            self.assertEqual(command.call_args_list[-1].args[0], ["rm", "--force", "a" * 64])
            self.assertEqual(backend.pending_attempts, {})

    def test_create_result_loss_reconciles_owned_attempt_without_deleting_collisions(self):
        self.execute()
        spec = self.backend.spec
        source = "/proc/123/fd/456"
        @contextlib.contextmanager
        def staged(inputs):
            yield source
        for failure in ("timeout", "overflow", "disconnect", "malformed", "collision", "unavailable"):
            backend = self.worker.DockerBackend(self.lock, None)
            objects = {}
            observed = []
            def daemon(arguments, **kwargs):
                observed.append(arguments)
                if arguments[0] == "create":
                    name = next(item.removeprefix("--name=") for item in arguments if item.startswith("--name="))
                    token = next(item.split("=", 2)[2] for item in arguments if item.startswith("--label="))
                    self.assertEqual(backend.pending_attempts, {name: token})
                    raw = self.daemon_container_fixture(spec, source)
                    raw.update(Id="b" * 64, Name="/" + name)
                    raw["Config"]["Labels"] = {self.worker.ATTEMPT_LABEL: "foreign-token" if failure == "collision" else token}
                    objects[name] = raw  # Daemon committed before CLI reply failed.
                    if failure == "malformed":
                        return b"not a container identity"
                    raise self.worker.WorkerRefusal("create result lost: " + failure)
                if arguments[:2] == ["container", "inspect"]:
                    if failure == "unavailable":
                        raise self.worker.WorkerRefusal("daemon unavailable during reconciliation")
                    self.assertIn(arguments[2], objects)
                    return self.worker.canonical(objects[arguments[2]])
                if arguments[0] == "rm":
                    self.assertEqual(arguments, ["rm", "--force", "b" * 64])
                    objects.clear()
                    return b""
                self.fail("unexpected runtime operation after failed create: " + repr(arguments))
            with self.subTest(failure=failure), mock.patch.object(backend, "stage_inputs", side_effect=staged), \
                    mock.patch.object(backend, "command", side_effect=daemon):
                with self.assertRaises(self.worker.WorkerRefusal):
                    backend.execute(spec, {})
            self.assertTrue(any(args[:2] == ["container", "inspect"] for args in observed))
            if failure in ("collision", "unavailable"):
                self.assertFalse(any(args[0] == "rm" for args in observed))
                self.assertTrue(objects)
                self.assertTrue(backend.pending_attempts)
            else:
                self.assertEqual(objects, {})
                self.assertEqual(backend.pending_attempts, {})

    def test_concrete_cli_io_enforces_output_and_time_budgets_on_real_process(self):
        backend = self.worker.DockerBackend(self.lock, None)
        config = os.open(self.store, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            backend.config_fd = config
            for code, maximum, seconds, expected in (
                    ("print('inert')", 1024, 2, b"inert\n"),
                    ("import os; os.write(1,b'x'*4096)", 16, 2, "output limit"),
                    ("import time; time.sleep(10)", 1024, 0.05, "wall-time limit")):
                script = ("#!/usr/bin/python3\n" + code + "\n").encode()
                with self.worker.sealed_snapshot(script, executable=True) as descriptor:
                    backend.cli_fd = descriptor
                    if isinstance(expected, bytes):
                        self.assertEqual(backend.command(["inert"], maximum=maximum, seconds=seconds), expected)
                    else:
                        with self.assertRaisesRegex(self.worker.WorkerRefusal, expected):
                            backend.command(["inert"], maximum=maximum, seconds=seconds)
        finally:
            os.close(config)

    def test_concrete_backend_executes_sealed_approved_cli_after_transient_path_swap(self):
        script = b"#!/usr/bin/python3\nprint('approved inert CLI bytes')\n"
        cli_dir, config_dir, socket_dir = self.base / "bin", self.base / "docker", self.base / "socket"
        for directory in (cli_dir, config_dir, socket_dir):
            directory.mkdir()
        cli = cli_dir / "docker"
        cli.write_bytes(script)
        cli.chmod(0o755)
        (config_dir / "config.json").write_bytes(b"{}\n")
        lock = {**self.lock, "runtimeCli": {"path": "/usr/bin/docker", "bytes": len(script), "sha256": self.worker.digest(script)}}
        @contextlib.contextmanager
        def inert_protected(path):
            mapping = {Path("/usr/bin"): cli_dir, self.store / "docker": config_dir,
                       self.worker.RUNTIME_SOCKET.parent: socket_dir}
            descriptor = os.open(mapping[path], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                yield descriptor
            finally:
                os.close(descriptor)
        original_stat = os.stat
        def inert_socket_stat(path, *args, **kwargs):
            if path == self.worker.RUNTIME_SOCKET.name:
                fields = list(original_stat(socket_dir))
                fields[stat.ST_MODE] = stat.S_IFSOCK | 0o600
                fields[stat.ST_UID], fields[stat.ST_GID] = 0, 0
                return os.stat_result(fields)
            return original_stat(path, *args, **kwargs)
        with mock.patch.object(self.worker, "protected_directory", side_effect=inert_protected), \
                mock.patch.object(os, "geteuid", return_value=0), \
                mock.patch.object(os, "stat", side_effect=inert_socket_stat):
            with self.worker.DockerBackend(lock, None) as backend:
                cli.write_bytes(b"#!/usr/bin/python3\nprint('unchecked replacement')\n")
                self.assertEqual(backend.command(["inert"]), b"approved inert CLI bytes\n")
                self.assertEqual(fcntl.fcntl(backend.cli_fd, fcntl.F_GET_SEALS) & self.worker.SEALS, self.worker.SEALS)
            with self.assertRaisesRegex(self.worker.WorkerRefusal, "runtime CLI differs"):
                with self.worker.DockerBackend(lock, None):
                    self.fail("mutated CLI initialized")

    def test_production_gate_has_no_record_env_or_mutable_host_fallback(self):
        with mock.patch.dict(os.environ, {"CLANG_APPROVED_IMAGE": self.lock["configDigest"], "CLANG_HOST_QUALIFIED": "1"}), \
                mock.patch.object(self.worker, "APPROVAL_STORE", self.base / "missing"), \
                mock.patch.object(provision, "run_checked") as command, \
                mock.patch.object(provision, "_provision_rootfs_unqualified") as provision_old, \
                mock.patch.object(provision, "_package_provenance_unqualified") as package_old:
            for public in (provision.provision_rootfs, provision.command_package_provenance, provision.command_check_host_execution):
                with self.subTest(public=public.__name__), self.assertRaisesRegex(provision.ProvisionError, "immutable host execution unavailable"):
                    public(provision.argparse.Namespace())
            command.assert_not_called()
            provision_old.assert_not_called()
            package_old.assert_not_called()
        with mock.patch.object(self.worker, "require_production_worker", return_value=None):
            with self.assertRaisesRegex(provision.ProvisionError, "artifact transport is unfinished"):
                provision.require_immutable_host_execution("provision-rootfs-v1")
        with self.assertRaisesRegex(self.worker.WorkerRefusal, "installed root launcher"):
            self.worker.execute_installed_action("provision-rootfs-v1", self.lock_sha, {"source.cpp": self.input_fd}, -1)

    def test_host_worker_policy_and_environment_recipe_are_bound_and_workflow_refuses_mutable_install(self):
        recipe = provision.recipe_identity()
        for key in ("hostWorkerSha256", "hostPolicySha256", "hostEnvironmentRecipeSha256"):
            self.assertEqual(recipe[key], self.worker.digest(provision.RECIPE_FILES[key].read_bytes()))
        policy = json.loads(provision.RECIPE_FILES["hostPolicySha256"].read_bytes())
        self.assertFalse(policy["qualificationEnabled"])
        self.assertIsNone(policy["environmentManifestDigest"])
        workflow = (ROOT / ".github/workflows/generic-template-toolchain.yml").read_text()
        self.assertIn("check-host-execution", workflow)
        for event, following in (("pull_request:", "  push:"), ("push:", "\npermissions:")):
            section = workflow.split("  " + event, 1)[1].split(following, 1)[0]
            self.assertIn("'scripts/oracle/clang_18_1_3_worker.py'", section)
        self.assertNotIn("debootstrap dpkg-dev gpgv gnupg ubuntu-keyring python3", workflow)
        args = provision.build_parser().parse_args(["check-host-execution"])
        self.assertEqual(args.run, provision.command_check_host_execution)



def run_rootfs_privilege_smoke(privilege: str) -> None:
    """Exercise only inert repository-local files; never acquire or qualify a toolchain."""
    if privilege not in ("sudo", "doas"):
        raise ValueError("unsupported smoke privilege command")
    workdir = ROOT / "build/clang1813-privilege-smoke"
    workdir.mkdir(parents=True, exist_ok=True)
    original_execute = provision.run_checked
    budget = 256 * 1024
    setup_code = r"""
import os, socket, sys
from pathlib import Path
private = Path(sys.argv[1])
mode = sys.argv[2]
budget = int(sys.argv[3])
private.mkdir(mode=0o700, exist_ok=True)
private.chmod(0o700)
(private / "payload").write_bytes(b"x" * (budget + 1 if mode == "oversized" else 1024))
if mode == "socket":
    os.chdir(private)
    handle = socket.socket(socket.AF_UNIX)
    handle.bind("unsupported.sock")
    handle.close()
"""
    with tempfile.TemporaryDirectory(prefix="inert-", dir=workdir) as temporary:
        base = Path(temporary)
        rootfs = base / "rootfs"
        rootfs.mkdir()
        private = rootfs / "private"
        observed = []

        def fixture_execute(command, *, timeout=900, **kwargs):
            observed.append(list(command))
            if command[:2] == ["sudo", "-n"]:
                assert command == provision.rootfs_tar_budget_command(rootfs, budget)
                assert timeout == provision.ROOTFS_TAR_BUDGET_TIMEOUT_SECONDS
                actual = [privilege, "-n", *command[2:]]
            else:
                assert command[:4] == ["sudo", "env", "LC_ALL=C", "tar"]
                actual = [privilege, "-n", *command[1:]]
            return original_execute(actual, timeout=timeout, **kwargs)

        try:
            original_execute([privilege, "-n", "/usr/bin/python3", "-I", "-B", "-c", setup_code,
                              str(private), "normal", str(budget)], timeout=30)
            metadata = private.stat()
            assert metadata.st_uid == 0 and metadata.st_mode & 0o777 == 0o700
            if os.geteuid() != 0:
                try:
                    (private / "payload").read_bytes()
                except PermissionError:
                    pass
                else:
                    raise AssertionError("ordinary user unexpectedly read the private fixture")
            archive = base / "normal.tar"
            with mock.patch.object(provision, "run_checked", side_effect=fixture_execute):
                provision.deterministic_rootfs_tar(rootfs, archive, 0, normalize=False, max_bytes=budget)
            assert len(observed) == 2 and observed[0][7] == "check-rootfs-tar-budget"
            with tarfile.open(archive) as content:
                assert content.getmember("./private/payload").uid == 0
                assert content.getmember("./private").mode == 0o700
            canary = base / "root-owned-canary"
            canary_payload = b"root-owned canary must remain unchanged"
            original_execute([privilege, "-n", "/usr/bin/python3", "-I", "-B", "-c",
                "from pathlib import Path; import sys; p=Path(sys.argv[1]); p.write_bytes(bytes.fromhex(sys.argv[2])); p.chmod(0o600)",
                str(canary), canary_payload.hex()], timeout=30)
            assert canary.stat().st_uid == 0 and canary.stat().st_mode & 0o777 == 0o600
            replacement = base / "unchecked-provisioner.py"
            replacement.write_text("from pathlib import Path; Path(" + repr(str(canary)) + ").write_bytes(b'compromised')\n")
            with mock.patch.dict(provision.RECIPE_FILES, provisionerSha256=replacement):
                helper = provision.rootfs_tar_budget_command(rootfs, budget)
                assert str(replacement) not in helper and helper[6] == provision.ROOTFS_TAR_BUDGET_PROGRAM
                original_execute([privilege, "-n", *helper[2:]], timeout=30)
            original_execute([privilege, "-n", "/usr/bin/python3", "-I", "-B", "-c",
                "from pathlib import Path; import sys; assert Path(sys.argv[1]).read_bytes() == bytes.fromhex(sys.argv[2])",
                str(canary), canary_payload.hex()], timeout=30)
            planted_archive = base / "planted.tar"
            planted_archive.symlink_to(canary)
            observed.clear()
            with mock.patch.object(provision, "run_checked", side_effect=fixture_execute):
                try:
                    provision.deterministic_rootfs_tar(rootfs, planted_archive, 0,
                                                      normalize=False, max_bytes=budget)
                except provision.ProvisionError as error:
                    assert "exclusively create" in str(error)
                else:
                    raise AssertionError("planted privileged tar output symlink was accepted")
            assert not observed, "existing destination must refuse before privileged preflight/tar"
            assert planted_archive.is_symlink()
            original_execute([privilege, "-n", "/usr/bin/python3", "-I", "-B", "-c",
                "from pathlib import Path; import sys; assert Path(sys.argv[1]).read_bytes() == bytes.fromhex(sys.argv[2])",
                str(canary), canary_payload.hex()], timeout=30)
            for mode, diagnostic in (("oversized", "archive byte budget"), ("socket", "unsupported filesystem entry")):
                original_execute([privilege, "-n", "/usr/bin/python3", "-I", "-B", "-c", setup_code,
                                  str(private), mode, str(budget)], timeout=30)
                observed.clear()
                rejected_archive = base / (mode + ".tar")
                with mock.patch.object(provision, "run_checked", side_effect=fixture_execute):
                    try:
                        provision.deterministic_rootfs_tar(rootfs, rejected_archive, 0,
                                                          normalize=False, max_bytes=budget)
                    except provision.ProvisionError as error:
                        assert diagnostic in str(error)
                    else:
                        raise AssertionError(mode + " preflight unexpectedly succeeded")
                assert len(observed) == 1 and observed[0][7] == "check-rootfs-tar-budget"
                assert not rejected_archive.exists()
        finally:
            original_execute([privilege, "-n", "/usr/bin/rm", "-rf", "--", str(rootfs)], timeout=30)
    assert not base.exists()
    print("inert root-owned 0700 preflight/tar passed; replacement helper and planted output symlink preserved root-owned canary; oversized/socket refused; cleanup passed")
    print("scope=offline-privilege-smoke; nativeQualification=not-run; qualified=false")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--privilege-smoke":
        run_rootfs_privilege_smoke(sys.argv[2])
    else:
        unittest.main()
