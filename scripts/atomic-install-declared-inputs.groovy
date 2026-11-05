import java.nio.file.Path
import java.nio.file.Files
import java.security.MessageDigest
import java.lang.reflect.Array
import org.gradle.api.provider.Provider
import org.gradle.api.file.RegularFile
import org.gradle.api.file.Directory
import org.gradle.jvm.toolchain.JavaLanguageVersion
import org.gradle.internal.snapshot.impl.ImplementationValue

class AtomicDeclaredInputFailure extends IllegalArgumentException {
    AtomicDeclaredInputFailure(String message) { super(message) }
}

/** Configured values only. No generic bean/deferred-code introspection or value.toString fallback. */
class AtomicDeclaredInputs {
    static final String FORMAT = 'declared-inputs-v1'
    static final int MAX_NODES = 131072, MAX_DEPTH = 128, MAX_STRING = 1048576, MAX_BYTES = 33554432
    static final Map REGISTRY = [
        'javaLauncher': 'org.gradle.jvm.toolchain.internal.DefaultToolchainJavaLauncher',
        'javaLauncher.metadata': 'org.gradle.jvm.toolchain.internal.JavaToolchain',
        'javaLauncher.metadata.taskInputs': 'org.gradle.jvm.toolchain.internal.JavaToolchainInput',
        'modularity': 'org.gradle.internal.jvm.DefaultModularitySpec',
        'debugOptions': 'org.gradle.process.internal.DefaultJavaDebugOptions']
    static final Map CHILDREN = [
        'javaLauncher': ['metadata'],
        'javaLauncher.metadata': ['languageVersion', 'taskInputs'],
        'javaLauncher.metadata.taskInputs': ['implementation', 'languageVersion', 'vendor'],
        'modularity': ['inferModulePath'],
        'debugOptions': ['enabled', 'host', 'port', 'server', 'suspend']]
    // Pinned primary-source classes from publisher ZIP 9c0f7fae...; generated decorations bind their base.
    static final Map PINS = [
        'org.gradle.util.GradleVersion': [baseClass: 'org.gradle.util.GradleVersion', classSha256: 'f8b046750dd085d0db47e1303427d9a785e1c98f545b2097bc677f9a3a890515', jar: 'lib/gradle-base-services-9.6.1.jar', jarSha256: 'c20955edf041e4b7fc6b811dcd51572396b8a6bb593758daa5b1486c7ff43c74'],
        'org.gradle.jvm.toolchain.internal.JavaToolchainInput': [baseClass: 'org.gradle.jvm.toolchain.internal.JavaToolchainInput', classSha256: '890498733ffc37e9f7b0c7da59c80da0f900ab4affa1432af3b032fc11cb4049', jar: 'lib/gradle-toolchains-jvm-shared-9.6.1.jar', jarSha256: '1a94c0a887759e4de0439b6733603660a923821eec8aa5b9d824dc74588771fd'],
        'org.gradle.jvm.toolchain.internal.JavaToolchain': [baseClass: 'org.gradle.jvm.toolchain.internal.JavaToolchain', classSha256: 'f76c8a9033b64d172c89461bf6baeb791e87d17672a7b1b61ba0ff9ec70ffc39', jar: 'lib/gradle-toolchains-jvm-shared-9.6.1.jar', jarSha256: '1a94c0a887759e4de0439b6733603660a923821eec8aa5b9d824dc74588771fd'],
        'org.gradle.process.internal.DefaultJavaDebugOptions': [baseClass: 'org.gradle.process.internal.DefaultJavaDebugOptions', classSha256: 'ae5c4a7daf98189ae2e133838bc2c5b906b7ec45601410a38a5c7c4235c22d2b', jar: 'lib/gradle-process-services-9.6.1.jar', jarSha256: 'b7c04a9f1dacdd9230dbf58177d8195a3e9d61ed5b59d0c8eb64fb3aa0db226d'],
        'org.gradle.internal.jvm.DefaultModularitySpec': [baseClass: 'org.gradle.internal.jvm.DefaultModularitySpec', classSha256: 'baad8b87d5baa266d400abb67d52a10ab1c4afe8f9ef1eb721e9538128756348', jar: 'lib/gradle-process-services-9.6.1.jar', jarSha256: 'b7c04a9f1dacdd9230dbf58177d8195a3e9d61ed5b59d0c8eb64fb3aa0db226d'],
        'org.gradle.jvm.toolchain.internal.DefaultToolchainJavaLauncher': [baseClass: 'org.gradle.jvm.toolchain.internal.DefaultToolchainJavaLauncher', classSha256: '7673c65551445a806c89e2ac6dac36b337a684ff89865c3e8ec830819f5baf7b', jar: 'lib/plugins/gradle-toolchains-jvm-9.6.1.jar', jarSha256: '255cb2dabf5b6df503aff83ac88baefa0e0680cab056f550eb545f93f5e79605'],
        'org.gradle.api.tasks.PathSensitivity': [baseClass: 'org.gradle.api.tasks.PathSensitivity', classSha256: '60aa3071ec614c01902f9eff7896a784e139fb1cb991cb0aea613a3089133b59', jar: 'lib/gradle-core-api-9.6.1.jar', jarSha256: '5291bad2382019eced03c7c519322e976b651b568c3a9ed6d7ccd02a2d75e6a1'],
        'org.gradle.jvm.toolchain.internal.DefaultJavaLanguageVersion': [baseClass: 'org.gradle.jvm.toolchain.internal.DefaultJavaLanguageVersion', classSha256: 'a6982e245b66b92f839fb18dd05bab3188f7deefec97759bd178ea59451dac21', jar: 'lib/gradle-jvm-services-9.6.1.jar', jarSha256: '7d00ee5e46a5244c1058d1a6798215053e3ce1147c764b4b1b927fa7c4948cfe'],
        'org.gradle.internal.snapshot.impl.ImplementationValue': [baseClass: 'org.gradle.internal.snapshot.impl.ImplementationValue', classSha256: '1ac7e7273587977c70abf462d7de881190c1dc18d8f4ea36190bf0af47d891d1', jar: 'lib/gradle-model-core-9.6.1.jar', jarSha256: '2dc56b19198a4994d90e948a283f9e18c43e88ba35774f50421179f6585e1820']
    ]
    final Path gradleHome
    long deadline = System.nanoTime() + 120000000000L
    int nodes = 0
    long bytes = 0
    long scratch = 0
    String task = '<none>', property = '<none>', phase = 'snapshot', currentType = 'null'
    final IdentityHashMap<Object,Boolean> active = new IdentityHashMap<>()
    final IdentityHashMap<Object,Object> providers = new IdentityHashMap<>()
    final Map<String,Map> bindings = [:]
    final Map<String,Object> beans = [:]
    AtomicDeclaredInputs(File home) {
        gradleHome = home.toPath().toAbsolutePath().normalize()
        binding(org.gradle.util.GradleVersion)
        if (org.gradle.util.GradleVersion.current().getVersion() != '9.6.1') fail('unpinned running Gradle version')
    }
    void fail(String reason, Object value = null) {
        String type = value == null ? currentType : value.getClass().name
        // Property text is bounded independently; never include arbitrary exception/value rendering.
        throw new AtomicDeclaredInputFailure(('declared-inputs task=' + task.take(160) + ' property=' + property.take(160) +
            ' type=' + type.take(160) + ' phase=' + phase + ' reason=' + reason).take(500))
    }
    void check() {
        if (Thread.currentThread().isInterrupted()) fail('cancelled')
        if (System.nanoTime() > deadline) fail('time bound')
    }
    void node(int depth) {
        check()
        if (depth > MAX_DEPTH || ++nodes > MAX_NODES) fail('node/depth bound')
    }
    String string(Object value) {
        if (value == null || value.getClass() != String) fail('String required', value)
        String s = (String)value
        if (s.length() > MAX_STRING) fail('string bound')
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i)
            if (Character.isHighSurrogate(c)) {
                if (++i >= s.length() || !Character.isLowSurrogate(s.charAt(i))) fail('unpaired surrogate')
            } else if (Character.isLowSurrogate(c)) fail('unpaired surrogate')
        }
        int n = s.getBytes('UTF-8').length
        if (n > MAX_STRING) fail('string bound')
        return s
    }
    static int compareBytes(byte[] a, byte[] b) { Arrays.compareUnsigned(a, b) }
    int compareKeys(String a, String b) {
        int i = 0, j = 0
        while (i < a.length() && j < b.length()) {
            if ((i & 4095) == 0) check()
            int left = a.codePointAt(i), right = b.codePointAt(j)
            if (left != right) return Integer.compare(left, right)
            i += Character.charCount(left); j += Character.charCount(right)
        }
        return Integer.compare(a.length() - i, b.length() - j)
    }
    void arrayComponent(Class component, int depth = 0) {
        check()
        if (depth > MAX_DEPTH) fail('array component depth')
        if (component.isArray()) { arrayComponent(component.componentType, depth + 1); return }
        if (component.isPrimitive() && component != Void.TYPE) return
        if (!(component.name in ['java.lang.Object', 'java.lang.String', 'java.lang.Boolean', 'java.lang.Character', 'java.lang.Byte', 'java.lang.Short', 'java.lang.Integer', 'java.lang.Long', 'java.math.BigInteger', 'java.math.BigDecimal', 'java.lang.Float', 'java.lang.Double', 'java.io.File', 'java.nio.file.Path', 'org.gradle.api.file.RegularFile', 'org.gradle.api.file.Directory', 'org.gradle.api.provider.Provider', 'org.gradle.jvm.toolchain.JavaLanguageVersion', 'java.util.List', 'java.util.Set', 'java.util.Map', 'java.util.ArrayList', 'java.util.LinkedList', 'java.util.HashSet', 'java.util.LinkedHashSet', 'java.util.TreeSet', 'java.util.HashMap', 'java.util.LinkedHashMap', 'java.util.TreeMap', 'org.gradle.api.tasks.PathSensitivity'])) fail('unsupported array component')
    }
    String numericText(Object number) {
        if (number == null || !(number.getClass() in [Byte, Short, Integer, Long, BigInteger])) fail('unsupported numeric class', number)
        if (number.getClass() == BigInteger) {
            long estimate = (((BigInteger)number).bitLength() * 30103L / 100000L) + 3L
            if (estimate > MAX_STRING + 4L || bytes + scratch + estimate * 4L > MAX_BYTES) fail('numeric byte bound')
        }
        String result = string(number.toString()) // Only exact numeric classes reach this method.
        bytes += result.length()
        if (bytes + scratch > MAX_BYTES) fail('numeric plan bound')
        return result
    }
    String lexical(Path p) {
        if (!p.isAbsolute() || p.normalize() != p) fail('relative/escaped path')
        String result = string(p.toString())
        bytes += 2L + 6L * result.getBytes('UTF-8').length
        if (bytes + scratch > MAX_BYTES) fail('path byte bound')
        return result
    }
    String filePath(File file) {
        node(0)
        String path = lexical(file.toPath())
        bytes += 2L + 6L * path.getBytes('UTF-8').length
        if (bytes + scratch > MAX_BYTES) fail('path/plan byte bound')
        return path
    }
    Map binding(Class type) {
        String name = type.name
        boolean decorated = name in [REGISTRY.modularity + '_Decorated', REGISTRY.debugOptions + '_Decorated']
        Class base = decorated ? type.superclass : type
        if (!PINS.containsKey(base.name) || (decorated && name != base.name + '_Decorated') || !(base.superclass in [Object, Enum])) fail('unreviewed class/ancestry')
        if (!Class.forName(base.name, false, getClass().classLoader).is(base)) fail('unreviewed base class loader')
        if (decorated && (!type.classLoader.is(base.classLoader) || !Class.forName(name, false, base.classLoader).is(type))) fail('unreviewed decoration loader')
        Map pin = PINS[base.name]
        Path expected = gradleHome.resolve((String)pin.jar)
        for (Class c : decorated ? [type, base] : [base]) {
            def uri = c.protectionDomain?.codeSource?.location?.toURI()
            if (uri == null || uri.scheme != 'file' || Path.of(uri) != expected) fail('unreviewed class origin')
        }
        if (!bindings.containsKey(base.name)) {
            byte[] data
            base.getResourceAsStream('/' + base.name.replace('.', '/') + '.class').withCloseable { stream ->
                if (stream == null) fail('missing class resource')
                data = stream.readNBytes(MAX_STRING + 1)
            }
            if (data.length > MAX_STRING || MessageDigest.getInstance('SHA-256').digest(data).encodeHex().toString() != pin.classSha256) fail('class bytes changed')
            bindings[base.name] = [baseClass: base.name, classSha256: pin.classSha256, jarPath: lexical(expected), jarSha256: pin.jarSha256]
        }
        return bindings[base.name]
    }
    Object resolved(Provider provider) {
        check()
        if (!providers.containsKey(provider)) {
            // Memoize NULL too; only getOrNull, once per residual identity in this entire walk.
            providers.put(provider, provider.getOrNull())
            check()
        }
        return providers.get(provider)
    }
    Object required(Provider provider, Class type, boolean nullable = false) {
        Object v = resolved(provider)
        if (!(nullable && v == null) && (v == null || v.getClass() != type)) fail('missing/wrong bean field', v)
        return v
    }
    Map metadata(Object bean, int depth) {
        if (bean.getClass().name != REGISTRY['javaLauncher.metadata']) fail('metadata class', bean)
        binding(bean.getClass())
        def version = bean.getLanguageVersion()
        if (!(version instanceof JavaLanguageVersion) || version.asInt() <= 0) fail('unknown selected Java language')
        Path home = bean.getInstallationPath().getAsFile().toPath()
        return [languageVersion: encode(version, depth + 1), javaRuntimeVersion: encode(string(bean.getJavaRuntimeVersion()), depth + 1),
            jvmVersion: encode(string(bean.getJvmVersion()), depth + 1), vendor: encode(string(bean.getVendor()), depth + 1),
            installationPath: lexical(home), installationRealPath: lexical(home.toRealPath()),
            currentJvm: encode(bean.isCurrentJvm(), depth + 1), fallback: encode(bean.isFallbackToolchain(), depth + 1)]
    }
    Map implementation(Object wrapper, int depth) {
        Object bean = wrapper.getValue()
        String identifier = string(wrapper.getImplementationClassIdentifier())
        String expected = REGISTRY[property]
        if (expected == null || bean == null) fail('unknown nested property', bean)
        String observed = bean.getClass().name
        if (!(observed == expected || (property in ['modularity', 'debugOptions'] && observed == expected + '_Decorated')) || identifier != observed) fail('implementation identifier/class', bean)
        Map bound = binding(bean.getClass())
        Map semantic
        switch (property) {
            case 'javaLauncher':
                Path exe = bean.getExecutablePath().getAsFile().toPath()
                semantic = [executablePath: lexical(exe), executableRealPath: lexical(exe.toRealPath()), metadata: metadata(bean.getMetadata(), depth + 1)]
                beans['launcherMetadata'] = bean.getMetadata()
                break
            case 'javaLauncher.metadata':
                semantic = metadata(bean, depth + 1); beans['metadata'] = bean
                break
            case 'javaLauncher.metadata.taskInputs':
                semantic = [:]
                [languageVersion: JavaLanguageVersion, vendor: String, implementation: String].each { k, type ->
                    def method = bean.getClass().getDeclaredMethod('get' + k.capitalize())
                    if (method.returnType != type || method.parameterCount != 0 || !method.trySetAccessible()) fail('toolchain getter signature/access')
                    Object value = method.invoke(bean)
                    if (k != 'languageVersion') string(value)
                    else if (value != null && !(value instanceof JavaLanguageVersion)) fail('requested language class')
                    semantic[k] = encode(value, depth + 1)
                }
                break
            case 'modularity': semantic = [inferModulePath: encode(required(bean.getInferModulePath(), Boolean), depth + 1)]; break
            case 'debugOptions':
                semantic = [enabled: encode(required(bean.getEnabled(), Boolean), depth + 1), host: encode(required(bean.getHost(), String, true), depth + 1),
                    port: encode(required(bean.getPort(), Integer), depth + 1), server: encode(required(bean.getServer(), Boolean), depth + 1), suspend: encode(required(bean.getSuspend(), Boolean), depth + 1)]
                break
            default: fail('unsupported nested adapter')
        }
        return [identifier:identifier, bound:bound, semantic:semantic]
    }
    Object encode(Object value, int depth = 0) {
        currentType = value == null ? 'null' : value.getClass().name
        node(depth)
        bytes += 32
        if (bytes + scratch > MAX_BYTES) fail('wire node byte bound')
        if (value instanceof String) { bytes += string(value).getBytes('UTF-8').length; if (bytes + scratch > MAX_BYTES) fail('wire String byte bound') }
        if (value == null) return ['null']
        Class c = value.getClass()
        if (c == String) return ['string', string(value)]
        if (c == Boolean) return ['boolean', value]
        if (c == Character) return ['char', String.format('%04x', (int)(char)value)]
        if (c in [Byte, Short, Integer, Long, BigInteger]) return ['integer', c.name, numericText(value)]
        if (c == BigDecimal) return ['decimal', numericText(value.unscaledValue()), value.scale()]
        if (c == Float) return ['ieee', c.name, String.format('%08x', Float.floatToRawIntBits((Float)value))]
        if (c == Double) return ['ieee', c.name, String.format('%016x', Double.doubleToRawLongBits((Double)value))]
        if (value instanceof JavaLanguageVersion) {
            if (c.name != 'org.gradle.jvm.toolchain.internal.DefaultJavaLanguageVersion' || value.asInt() <= 0) fail('Java language implementation', value)
            binding(c)
            return ['java-language', value.asInt()]
        }
        if (value instanceof Enum) {
            // Enum origin binding is supplied by the pinned declaring class, never a name alone.
            binding(value.getDeclaringClass())
            return ['enum', value.getDeclaringClass().name, string(value.name())]
        }
        if (value instanceof RegularFile) return ['regular-file', lexical(value.getAsFile().toPath())]
        if (value instanceof Directory) return ['directory', lexical(value.getAsFile().toPath())]
        if (c == File) return ['file', lexical(value.toPath())]
        if (value instanceof Path) return ['path', lexical(value)]
        if (active.containsKey(value)) fail('identity cycle', value)
        active.put(value, true)
        try {
            if (value instanceof Provider) {
                Object v = resolved(value)
                return ['provider', v == null ? ['absent'] : ['present', encode(v, depth + 1)]]
            }
            if (c == ImplementationValue) {
                binding(c)
                def item = implementation(value, depth + 1)
                return ['implementation', item.identifier, item.bound, item.semantic]
            }
            if (c.isArray()) {
                arrayComponent(c.componentType)
                int size = Array.getLength(value)
                if (size > MAX_NODES - nodes) fail('array node bound')
                List result = []
                for (int i = 0; i < size; i++) result.add(encode(Array.get(value, i), depth + 1))
                return ['array', c.componentType.name, result]
            }
            if (value instanceof List || value instanceof Set) {
                List result = []
                for (Object v : value) { check(); result.add(encode(v, depth + 1)) }
                if (value instanceof List) return ['list', result]
                List keyed = []
                for (def v: result) {
                    byte[] key = canonical(v)
                    scratch += key.length
                    if (bytes + scratch > MAX_BYTES) fail('set canonical scratch bound')
                    keyed.add([key:key, value:v])
                }
                keyed.sort { a,b -> compareBytes(a.key, b.key) }
                for (int i=1;i<keyed.size();i++) if (Arrays.equals(keyed[i-1].key, keyed[i].key)) fail('set encoding collision')
                List sorted = keyed.collect { it.value }
                keyed.each { scratch -= it.key.length }
                return value instanceof LinkedHashSet ? ['ordered-set', sorted, result] : ['set', sorted]
            }
            if (value instanceof Map) {
                List entries = []; Set seen = new HashSet()
                for (def entry : value.entrySet()) {
                    node(depth + 1); String key = string(entry.key)
                    if (!seen.add(key)) fail('duplicate map key')
                    entries.add([key, encode(entry.value, depth + 1)])
                }
                entries.sort { a,b -> compareKeys(a[0], b[0]) }
                return ['map', entries]
            }
            fail('unsupported class', value)
        } finally { active.remove(value) }
    }
    // Same canonical writer for sorting and final byte accounting. Control escapes are always \u00xx.
    byte[] canonical(Object value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream()
        Closure emit = { String s ->
            check(); byte[] b = s.getBytes('UTF-8')
            if (bytes + scratch + 65536L + 4L * (out.size() + b.length) > MAX_BYTES) fail('plan/canonical scratch bound')
            out.write(b)
        }
        Closure write
        write = { Object v ->
            check()
            if (v == null) emit('null')
            else if (v instanceof String) {
                string(v); emit('"')
                String s = v
                StringBuilder chunk = new StringBuilder(8192)
                for (int i=0;i<s.length();i++) {
                    if ((i & 4095) == 0) check()
                    char ch=s.charAt(i)
                    if (ch == (char)34 || ch == (char)92) { chunk.append((char)92); chunk.append(ch) }
                    else if ((int)ch < 32) chunk.append(String.format('\\u%04x',(int)ch))
                    else if (Character.isHighSurrogate(ch)) { chunk.append(ch);chunk.append(s.charAt(++i)) }
                    else chunk.append(ch)
                    if (chunk.length() >= 4096) { emit(chunk.toString());chunk.setLength(0) }
                }
                if (chunk.length() != 0) emit(chunk.toString())
                emit('"')
            } else if (v instanceof Boolean) emit(v ? 'true' : 'false')
            else if (v.getClass() in [Integer, Long, BigInteger]) emit(v.toString())
            else if (v instanceof List) {
                emit('['); boolean first=true
                for (Object x:v) { if (!first) emit(',');first=false;write(x) };emit(']')
            } else if (v instanceof Map) {
                emit('{');boolean first=true
                v.keySet().toList().sort { a,b -> compareKeys(string(a), string(b)) }.each { k ->
                    if (!first) emit(',');first=false;write(k);emit(':');write(v[k])
                };emit('}')
            } else fail('non-wire value',v)
        }
        write(value)
        return out.toByteArray()
    }
    static Object freeze(Object value) {
        if (value instanceof Map) { Map out=[:];value.each { k,v -> out[k]=freeze(v) };return Collections.unmodifiableMap(out) }
        if (value instanceof List) return Collections.unmodifiableList(value.collect { freeze(it) })
        return value
    }
    Map snapshot(String name, Map properties) {
        task=name;beans.clear()
        property='compiler';string(properties['compiler'])
        property='hostArchitecture';string(properties['hostArchitecture'])
        Map result=[:]
        List keys=[]
        for (Object key:properties.keySet()) { node(0);keys.add(string(key)) }
        if (!keys.containsAll(['args', 'compiler', 'debug', 'defaultCharacterEncoding', 'enableAssertions', 'hostArchitecture', 'ignoreExitValue', 'jvmArgs', 'mainClass', 'mainModule', 'maxHeapSize', 'minHeapSize', 'systemProperties'])) fail('missing declared JavaExec/source input')
        Set nestedKeys = new HashSet(REGISTRY.keySet())
        CHILDREN.each { prefix, children -> children.each { child -> nestedKeys.add(prefix + '.' + child) } }
        if (keys.any { key -> ['javaLauncher.', 'modularity.', 'debugOptions.'].any { key.startsWith(it) } && !nestedKeys.contains(key) }) fail('unknown nested descendant')
        if (keys.any { it == 'argumentProviders' || it.startsWith('argumentProviders.') || it == 'jvmArgumentProviders' || it.startsWith('jvmArgumentProviders.') }) fail('expanded argument-provider schema')
        keys.sort { a,b -> compareKeys(a, b) }
        try {
            for (String key:keys) { property=key;result[key]=encode(properties[key]) }
            for (def entry:CHILDREN.entrySet()) {
                String prefix=entry.key
                List actual=keys.findAll { it.startsWith(prefix+'.') }.collect { it.substring(prefix.length()+1).split('\\.')[0] }.unique().sort()
                if (!result.containsKey(prefix) || actual != entry.value.toList().sort()) fail('nested child schema')
            }
            if (!beans['launcherMetadata'].is(beans['metadata'])) fail('launcher/metadata identity disagreement')
            if (result.javaLauncher[3].metadata != result['javaLauncher.metadata'][3]) fail('metadata semantic disagreement')
            for (String prefix:['javaLauncher.metadata','javaLauncher.metadata.taskInputs','modularity','debugOptions']) {
                Map semantic=result[prefix][3]
                for (String child:CHILDREN[prefix]) {
                    if (child=='taskInputs') continue
                    if (result[prefix+'.'+child] != semantic[child]) fail('nested leaf disagreement')
                }
            }
            int size=canonical(result).length
                if (bytes*2 > MAX_BYTES) fail('plan/canonical scratch bound')
            return freeze(result)
        } catch (Throwable failure) {
            if (failure instanceof ThreadDeath || failure instanceof VirtualMachineError || failure instanceof AtomicDeclaredInputFailure) throw failure
            fail('snapshot rejected: '+failure.getClass().name)
        } finally { beans.clear();property='<none>' }
    }
}
return AtomicDeclaredInputs
