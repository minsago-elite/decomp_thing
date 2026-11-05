"""Bounded prepared-input receipts for the test-only installed replay.

No build or native execution. The CLI is called by the immutable Gradle test init
before Sync. Receipts establish consistency, not compiler/toolchain authenticity.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import time
import zipfile
from contextlib import contextmanager

BUILD_CONTROLS = (".github/workflows/ci.yml", "gradlew", "gradlew.bat",
                  "gradle/wrapper/gradle-wrapper.jar", "gradle/wrapper/gradle-wrapper.properties",
                  "gradle/libs.versions.toml", ".node-version", "settings.gradle.kts", "build.gradle.kts")
PRODUCERS = ("buildAnalysisIoHelper", "buildLlvmBehaviorHelper")
EXCLUSIONS = ["-x", ":buildAnalysisIoHelper", "-x", ":buildLlvmBehaviorHelper"]
REFERENCES = {"generateKotlinBootClasspathReference": "kotlin-boot-classpath-reference-v1.json",
              "generateGccBundledGhidraReference": "gcc-bundled-ghidra-reference-v1.json",
              "generateLlvmHostedWorkerClasspathReference": "llvm-behavior-hosted-worker-classpath-reference-v1.json"}
HELPER_OUTPUTS = {
    "buildAnalysisIoHelper": ("analysis", {"decomp-analysis-io-helper", "decomp-analysis-io-helper.sha256",
        "analysis-native-io/source.c", "analysis-native-io/build-policy.txt", "analysis-native-io/build-v1.json",
        "analysis-native-io/decomp-analysis-io-helper-v1.properties"}),
    "buildLlvmBehaviorHelper": ("behavior", {"decomp-llvm-behavior-helper", "decomp-llvm-behavior-helper.sha256",
        "decomp_llvm_behavior_helper.c", "decomp-llvm-behavior-helper-build-v2.json",
        "llvm-behavior-native-helper-deployment-reference-v1.json"}),
}
EMBEDDED_RESOURCES = {"analysis-native-io/" + name for name in
    ("source.c", "build-policy.txt", "build-v1.json", "decomp-analysis-io-helper-v1.properties")} | {
    "oracle/native-helper/" + name for name in ("decomp_llvm_behavior_helper.c", "decomp-llvm-behavior-helper-build-v2.json",
        "llvm-behavior-native-helper-deployment-reference-v1.json")}
MAX_FILE = 512 * 1024**2
MAX_INPUT_BYTES = 8 * 1024**3
MAX_INPUT_ENTRIES = 131072
MAX_JSON = 32 * 1024**2
MAX_PROTECTED_ENTRIES = 4096
MAX_PROTECTED_BYTES = 4 * 1024**3


def require(value, message):
    if not value:
        raise RuntimeError(message)


# Exact declared-inputs-v1 decoder. No coercion, legacy upgrade or producer encoder calls.
DECLARED_FORMAT = 'declared-inputs-v1'
DECLARED_MAX_DEPTH = 128
DECLARED_MAX_NODES = 131072
DECLARED_MAX_STRING = 1024**2
GRADLE_VERSION = '9.6.1'
GRADLE_COMMIT = '309d128bd9fe8c0b71311878fc660b9cbaa07c51'
GRADLE_ZIP_SHA256 = '9c0f7faeeb306cb14e4279a3e084ca6b596894089a0638e68a07c945a32c9e14'
GRADLE_JARS = {'lib/agents/gradle-instrumentation-agent-9.6.1.jar': 'cd8dc868a0ef742eecac0f16fa5d3041f17a1d32c9bcc807f4be158aece4918c',
 'lib/annotations-24.0.1.jar': '61666dbce7e42e6c85b43c04fcfb8293a21dcb55b3c80e869270ce42c01a6b35',
 'lib/ant-1.10.17.jar': '8be692e02837f41a47a3d21cde6655792142fdf42fe23bcb16d7129cad9b2284',
 'lib/ant-antlr-1.10.15.jar': '619e361609d446fe6ab67d1d45b8656e68644cbd7c45bbed5c2c8816408d8dd5',
 'lib/ant-launcher-1.10.17.jar': 'f6e3de06dc0ea396638004f1a003f55fdbd20c3e7ccfb9b7a524f49fd0ae8568',
 'lib/antlr4-runtime-4.7.2.jar': '4c518b87d4bdff8b44cd8cbc1af816e944b62a3fe5b80b781501cf1f4759bbc4',
 'lib/asm-9.9.jar': '03d99a74ad1ee5c71334ef67437f4ef4fe3488caa7c96d8645abc73c8e2017d4',
 'lib/asm-commons-9.9.jar': 'db2f6f26150bbe7c126606b4a1151836bcc22a1e05a423b3585698bece995ff8',
 'lib/asm-tree-9.9.jar': '42178f3775c9c63f9e5e1446747d29b4eca4d91bd6e75e5c43cfa372a47d38c6',
 'lib/commons-codec-1.18.0.jar': 'ba005f304cef92a3dede24a38ad5ac9b8afccf0d8f75839d6c1338634cf7f6e4',
 'lib/commons-compress-1.26.1.jar': '27bb5d40f37c3bb7205b4a0540247df057715e9f6cbbd97d626ab8b50318bb04',
 'lib/commons-io-2.15.1.jar': 'a58af12ee1b68cfd2ebb0c27caef164f084381a00ec81a48cc275fd7ea54e154',
 'lib/commons-lang3-3.20.0.jar': '69e5c9fa35da7a51a5fd2099dfe56a2d8d32cf233e2f6d770e796146440263f4',
 'lib/error_prone_annotations-2.42.0.jar': 'f282a6488838986b8033bd51888928cff6a59c1050426476553ed2622b89e510',
 'lib/failureaccess-1.0.3.jar': 'cbfc3906b19b8f55dd7cfd6dfe0aa4532e834250d7f080bd8d211a3e246b59cb',
 'lib/fastutil-8.5.2-min.jar': '63dff0e355eaec20c883db0a6bdf1c8298c7072b46609aad5a0753a02ac3638b',
 'lib/gradle-ant-9.6.1.jar': '6c3fffbb947902970845a16471a6c6b80b98dc55a854b66d0d33547b47df73bf',
 'lib/gradle-ant-api-9.6.1.jar': '2931a7a4f5271488ead7e13d79eaa7551999b2bfab8057c501b81e3045fd2244',
 'lib/gradle-api-metadata-9.6.1.jar': 'f7bc50745ab824f91afb9a8dd889cf9c047e8b7b53d0b564025b543b95a31a4b',
 'lib/gradle-base-asm-9.6.1.jar': '501e664c15aec5091311543cb6a143289ce50aa78bf87b6f762bb8a7919033ac',
 'lib/gradle-base-diagnostics-9.6.1.jar': 'f1a348ab45d0904457c553a29f04bd1f23f8740d25c696c9c9dcba0537b803ad',
 'lib/gradle-base-services-9.6.1.jar': 'c20955edf041e4b7fc6b811dcd51572396b8a6bb593758daa5b1486c7ff43c74',
 'lib/gradle-base-services-groovy-9.6.1.jar': '2b7238760d5000e6b00d4ea9c91967c84ded84cd66ae407222fc579cb2a10ebb',
 'lib/gradle-build-cache-9.6.1.jar': 'acaba35a3f4440843ee42925abd178804daf3b14276a6e7ad12f3eda1d94a05e',
 'lib/gradle-build-cache-base-9.6.1.jar': 'eb5e7fbd18fa4d8fa1e943967d5b1e0415e46a0948db6f3f6230509afb357f2f',
 'lib/gradle-build-cache-core-9.6.1.jar': '7c4be7344b7592ed12b606e48eefefbc33b467410f1ed806c9c2b3457ba18c6b',
 'lib/gradle-build-cache-local-9.6.1.jar': 'a36f6e353d6a6a933281b73d42855200d146bc804b2180d498580200148d261e',
 'lib/gradle-build-cache-packaging-9.6.1.jar': '76c23b7ca939c7173f783361ab28be5e2565d496ee7d15ca97f4ad441869d2c6',
 'lib/gradle-build-cache-spi-9.6.1.jar': '6b1a293d2d132eb055ba035dc0fbdc234524788f815ec2c8f30fa6c322362702',
 'lib/gradle-build-configuration-9.6.1.jar': '2a2564c880761f3a088c55e7937d5db93f6a426090094e2c37b278c23ac716bb',
 'lib/gradle-build-discovery-9.6.1.jar': '0a6cf1e6af1c90e582ed3f7056536cb5e77d381cafc69bfd59cb6b211c3f8a9b',
 'lib/gradle-build-discovery-impl-9.6.1.jar': '9ee075bd9100481d58e154d8e44e7aeeb9c3c3503f53d614e7f7c21109681201',
 'lib/gradle-build-discovery-reporting-9.6.1.jar': '426551f8d7460bf2277dfc76a9a5b1c0a4f9bee810d64e55978d67e1e231528f',
 'lib/gradle-build-init-specs-9.6.1.jar': 'c22c6e9564827929dcf1254edf3ee3277cb8902ecff492921e8dbab14faaac7f',
 'lib/gradle-build-init-specs-api-9.6.1.jar': 'af7c6fca8664ae75939bae8ad756162fa228b5208bd25ac2e12c03c4019c7c5c',
 'lib/gradle-build-operations-9.6.1.jar': '32e3812f7ded81680c512b8ed63b1f83b3c95bf3960e8359740646cbcbec3ec6',
 'lib/gradle-build-operations-trace-9.6.1.jar': '78dc50224caa2662c57fa64785fface1030f5d0833c91e0352f6560f231ecd4f',
 'lib/gradle-build-option-9.6.1.jar': 'b5bca4cd5270b78abf4666183c3f7d007234ab9ef956996f424c55960eb38108',
 'lib/gradle-build-process-services-9.6.1.jar': 'ecbbd43689d725e3dd94f308b9e344686671e5194b3277d02890bdaa68717ece',
 'lib/gradle-build-state-9.6.1.jar': '3a9a5d07f6aa8965b14fddb524040762a3b227a80bba23d0b41de9732a2c5005',
 'lib/gradle-classloaders-9.6.1.jar': '52ddbc336b5d171f37d3a814b93a84af9ecfb56c761017c97e80dab344af500b',
 'lib/gradle-classpath-9.6.1.jar': '03bf92bd5f3e52151e86c1d22195a721017a2a94708295783fa7f269306e96d2',
 'lib/gradle-cli-9.6.1.jar': 'efdfccfa2c25c1a83269b741182c52814ca8aa553274f4a9a70061994738cf9d',
 'lib/gradle-client-services-9.6.1.jar': 'c827a6eff38fd0f8feb9a0c85d20624bf5d11451114bcbecc52747fcbdeb8ccb',
 'lib/gradle-collections-9.6.1.jar': 'a84d8b87380f8b6f75d3f61528076265f7662dfc3e530ea2ede357b9b60c67b1',
 'lib/gradle-concurrent-9.6.1.jar': 'ff10f4f16686c1925057afcc3a25d2d0683561293403475e60597c7643d28cbe',
 'lib/gradle-configuration-problems-base-9.6.1.jar': 'cdbfa40dad735ee3a7bb52155df51423326cf4cc2022f9b3a7db194e33a264df',
 'lib/gradle-core-9.6.1.jar': 'c352d684342fd477131368e6bc2149caf9ba2fd5fca975fc4b8678a549f0d16c',
 'lib/gradle-core-api-9.6.1.jar': '5291bad2382019eced03c7c519322e976b651b568c3a9ed6d7ccd02a2d75e6a1',
 'lib/gradle-core-flow-services-api-9.6.1.jar': 'da1aab6580f35cf1cbc5c7d8176a37cf593af6978a72e55cd62356e99b8449d1',
 'lib/gradle-core-kotlin-extensions-9.6.1.jar': '22aab4965a0d02e860ecbec034661ff60b79f333c229b045baa628005b97303e',
 'lib/gradle-credentials-9.6.1.jar': 'ab21abf222e30083f3175c1a3c246ba556c373c31ae589a5961c566a8d91f54b',
 'lib/gradle-credentials-api-9.6.1.jar': '4a6d06d393df406d5dd9be8ad852a1c4748609f22cb57acc1576e67bd89ac9a5',
 'lib/gradle-daemon-logging-9.6.1.jar': '2fb4d8abfb0f21dc2876670076eb9c129310ba330b3c0212b7cffe066192e149',
 'lib/gradle-daemon-main-9.6.1.jar': 'aaca5b187832ee5b1a9a4d194573034aa37d58edae1d9f1844f2d8ebaeca3f59',
 'lib/gradle-daemon-messaging-9.6.1.jar': 'ba0598f917a08b1832a0f805ef2d80bbed4872f650fb00f3288a8d6908bda8bc',
 'lib/gradle-daemon-protocol-9.6.1.jar': '613e3d65c2807c499af74b5a3e39a279285c6c582c4c2387bf690b37ecb97c98',
 'lib/gradle-daemon-server-9.6.1.jar': 'f5b2585b91e9904a89db844d15e848b215d2de3633459b3f1da83778317d02a7',
 'lib/gradle-daemon-services-9.6.1.jar': '181794f0e1f84e491aea0913724b151a37c235b238a7296cc49c31faf0f0ca05',
 'lib/gradle-declarative-dsl-api-9.6.1.jar': 'd50c469ad6ab50c0e5955e60f40a1dfa94798936ca50d58426e4490aff7d1e3e',
 'lib/gradle-declarative-dsl-core-9.6.1.jar': '0de0cf5af0eb1076f8e1b3dd69d96906919ba6ae401b3eaa86896cb6d114266c',
 'lib/gradle-declarative-dsl-evaluator-9.6.1.jar': 'eca98496916c49b781817f7bcc153079774bd2a855d9d3df88bd4a6a844df719',
 'lib/gradle-declarative-dsl-provider-9.6.1.jar': '693188f0824ae2a5deb4dbf11b9e691d0a84d4816072bd64fe627e709ccc3d48',
 'lib/gradle-declarative-dsl-tooling-models-9.6.1.jar': '94c6908a33c7c271410102927d49078c2ec7e8127be343c992bc542eda8e8660',
 'lib/gradle-domain-object-collections-9.6.1.jar': 'b2b3b473beb925a5fac4c8386c3d163f532cb4d5672a65c1debb688346a67a36',
 'lib/gradle-enterprise-logging-9.6.1.jar': '9f4329fe36b31b9917087563f939ca68f19f93a6f65e29b1fc3dfd6feaacbe4f',
 'lib/gradle-enterprise-operations-9.6.1.jar': '642c5e6893ecb0d2562533c21b5d7257b931dcbcd737f6eff3fa65c66baa347a',
 'lib/gradle-enterprise-workers-9.6.1.jar': '6204378c10f634697a19f5f99e8213849d96f1d894db0a0abd5443f26553ec07',
 'lib/gradle-execution-9.6.1.jar': '82823a1780af7e84d8f1201e3130bf22241a0aa53b46b0cd635f8ee4417844dd',
 'lib/gradle-file-collections-9.6.1.jar': '17534338709d60291e748b3d1eb42160eaaf2ed6520f197fe13715ad68511a7e',
 'lib/gradle-file-operations-9.6.1.jar': 'c8072365d3ee656e5665f4b975cc705660a1944366f6f9dc4ed400e6e8f94f40',
 'lib/gradle-file-temp-9.6.1.jar': 'dc625eea9beab68624b535ecb7089a7eb1ff99ed8c12db3049ead7458114fe51',
 'lib/gradle-file-watching-9.6.1.jar': '3bbd62343080e132be505c1bfd5fd9a6df18b28e1fdfb15bfb664feef6132842',
 'lib/gradle-fileevents-0.2.8.jar': '3c3bf574fb524f083d5f402e0765cf10022e1b5b8909668ef8cac55f10dd1fef',
 'lib/gradle-files-9.6.1.jar': '9c64a84e0f1196b3218d37188cd2ce30a41287729a8a978d41d80b0fd521d4a8',
 'lib/gradle-functional-9.6.1.jar': 'c191a51d8915eadc365e543ce6c6b47b1bb574eaaa2a50d6c89854b78a7b08ec',
 'lib/gradle-gradle-cli-9.6.1.jar': '48959c13fff1b0b218ff2aeb9d816e4b2d50d42c325e3f6ddf9ba2fe75935c21',
 'lib/gradle-gradle-cli-main-9.6.1.jar': '4bf15cccfc3ac4830daef8aa75ef96f34677f040a2fc0e51e581db76e795d64b',
 'lib/gradle-groovy-loader-9.6.1.jar': '3cbf49e0a9b7bab01723a6d66f680a921afbea382fbef84f51ea46e22b2f2a05',
 'lib/gradle-hashing-9.6.1.jar': 'fe99ffa8b7c1381fe95098c61662ee4ef6943fb59babb6f709c341731c900d9f',
 'lib/gradle-hashing-services-9.6.1.jar': '04f10e6d60b688cc959a76816277f00473ee76415aa4e2d4791e1d906a1c9b89',
 'lib/gradle-input-tracking-9.6.1.jar': 'bc110640ddc9aae7b9fa36c90cad57f219353f615e3ef127d811db6034790374',
 'lib/gradle-installation-beacon-9.6.1.jar': '7ccb4e325f92eac4fd5bf53213366f6a05728a810017d1fb6c207517daa7ec71',
 'lib/gradle-instrumentation-agent-services-9.6.1.jar': '291619b9d04f384d376d16de16f078a3ba9f70cd8b232df2608f528cf2a531f0',
 'lib/gradle-instrumentation-reporting-9.6.1.jar': '249116657e263422aa2dae7320ae3fd2da8f871cdc1217a580961e4dbb999f55',
 'lib/gradle-internal-instrumentation-api-9.6.1.jar': 'af03d9d3f24ba82c642cc763e7618dc7c3c3e0df00471746c180c43bde6afc68',
 'lib/gradle-io-9.6.1.jar': 'b61ba19bd71710b8f6e28139832665b665673706add837b5e93c036baed67259',
 'lib/gradle-java-api-extractor-9.6.1.jar': '0c9b04ca6eb347e4377c81bf61cd4ef017eb90bbec177e61eb8af583a6dc2525',
 'lib/gradle-jvm-services-9.6.1.jar': '7d00ee5e46a5244c1058d1a6798215053e3ce1147c764b4b1b927fa7c4948cfe',
 'lib/gradle-kotlin-dsl-9.6.1.jar': '010d7bd67c4a65707e386d7172318fd526d784957b7c0e289ce8e26a5bee6885',
 'lib/gradle-kotlin-dsl-extensions-9.6.1.jar': '3149be6575a2a3b5644dfdf8d23a11fbc85b03e60b984aabfa9b7bd1dcce7b9f',
 'lib/gradle-kotlin-dsl-shared-runtime-9.6.1.jar': '01c2d2a9b4419d6fb3cf14c76a67bb40d1d845644bdcb7c0f9f5dada5c4bd292',
 'lib/gradle-kotlin-dsl-tooling-models-9.6.1.jar': '21cff1c2543bac97af89c38ed0ffd6fbc6490046ff04edf0d04423e5c6d754fd',
 'lib/gradle-launcher-9.6.1.jar': 'd20e0cee243419ef001d2c3646acfc603447d2ce585b03f204afaa6caa898acd',
 'lib/gradle-logging-9.6.1.jar': '9189c2e21ed768606084e01f3d832b498a9953eb04a3bc9c434a908f9076146d',
 'lib/gradle-logging-api-9.6.1.jar': 'b4cfe1d5225ae66a5e0856b103de6ece65c8c70ac6244d289e5851251b639529',
 'lib/gradle-messaging-9.6.1.jar': '0c899a5d96a37b6d79a178cb0dc524125e757104f2afd2d155d9652b8e8cb591',
 'lib/gradle-model-core-9.6.1.jar': '2dc56b19198a4994d90e948a283f9e18c43e88ba35774f50421179f6585e1820',
 'lib/gradle-model-groovy-9.6.1.jar': '87695bdc7e527f6d7f518ef7d95ba83cfaab026f8e7b21b9d1146b18118427c6',
 'lib/gradle-model-reflect-9.6.1.jar': '7ab6e73668270efb3c16fea4116c7ecdc307526d1675310e3efd60411b711922',
 'lib/gradle-native-9.6.1.jar': '3fd91103e9d7b63d24946cb88979a2783181ba2812df7facb1b850a23fee6c76',
 'lib/gradle-normalization-9.6.1.jar': 'd297e5cd4f84bd0e12124c560a6f314f5030363f14f3c32783812a951b4806be',
 'lib/gradle-normalization-api-9.6.1.jar': '3944f8a6ca485bbda048c7f915e4c89e855b919dbf573efd0290646e2dc2d355',
 'lib/gradle-normalization-java-9.6.1.jar': 'c2d1b53734ad076bd044f55e70d866b43e08a897669cd255f7f118b4b153b679',
 'lib/gradle-persistent-cache-9.6.1.jar': 'f6bf566853fcb277e0f6503bb84e11a13cc36542cb972a87084fa8f2ae8a6f03',
 'lib/gradle-problems-9.6.1.jar': '617edd962f63c590125f9458fe508cdabd1c60b6543ea9ce8cf6e47f179e78fe',
 'lib/gradle-problems-api-9.6.1.jar': 'a405cbb265b80856b795d24e87a14314bf182ac3071683d45f33282367a0e01c',
 'lib/gradle-problems-rendering-9.6.1.jar': 'b7933d05869829553d6c591ffe4af1aeebc36c9eb9eed07dd403831bbda76d8c',
 'lib/gradle-process-memory-services-9.6.1.jar': 'bda1ce16be0ce4d70040f8a9ace60c7988638c6fa22b32507051362a05f510f3',
 'lib/gradle-process-services-9.6.1.jar': 'b7c04a9f1dacdd9230dbf58177d8195a3e9d61ed5b59d0c8eb64fb3aa0db226d',
 'lib/gradle-process-services-api-9.6.1.jar': 'fe5fe958ede794e34366b6ee846f6b3872ee7a4f42a493d8b98671d99d62058f',
 'lib/gradle-process-services-base-9.6.1.jar': '58163f4a00c61531b95ea5c0e7d44b8892bd0012d9a5a3e48ec28f5e0a96bf0e',
 'lib/gradle-project-features-9.6.1.jar': '628bc22866d490b7407a9849a4aa7c940c006e611e4f0b7ba4fffb31ac7cbba4',
 'lib/gradle-project-features-api-9.6.1.jar': 'f439f42f5b781b4651ddabbd0e111517bfe6d25ccddb88d64bda5904fa1aad49',
 'lib/gradle-report-rendering-9.6.1.jar': '6b37c613188570c8f16f0ee8017a0d776df4d5476f3cf245933eb8baf373bc72',
 'lib/gradle-request-handler-worker-9.6.1.jar': '6b96a00f33e9aea924d3c831d9f667f2a56e1addabcee4a745bf2e0c6995148d',
 'lib/gradle-resources-9.6.1.jar': '21d7bba26a0faafd8f8d37440b86cf36943782ad1d6ccb8f28f7d7433acc3779',
 'lib/gradle-resources-http-9.6.1.jar': 'c90a15f17d682eb63a8776d56aa55fbe9ddffcf0ae40645143dad22bb53b901d',
 'lib/gradle-runtime-api-info-9.6.1.jar': '4c2df33b58b399ee7aeb23915f819a96931fdb1b4824dee549fe77e1f5aea62c',
 'lib/gradle-scoped-persistent-cache-9.6.1.jar': '3fab2e82affc252b04da1ab40fca8563dc63ecf3cd01fdf40820491ef07347e2',
 'lib/gradle-serialization-9.6.1.jar': '13475e13e25c111a5cedb40822f77c9ed03763504ac7eed298ad738e76a4abcd',
 'lib/gradle-service-lookup-9.6.1.jar': 'ef1675f53191a80152a64736326e9748639a10162ed9f25b88830a493b286c38',
 'lib/gradle-service-provider-9.6.1.jar': '1c59c9fe4d86c89755f78a2d484f73bab0c1aefbcce6e0c2044b4a4a264bc77e',
 'lib/gradle-service-registry-builder-9.6.1.jar': 'ff45954afa3cb01071a0cd2ee3c4dda77cc981ae6a26c33f3d165cfe614532ae',
 'lib/gradle-service-registry-impl-9.6.1.jar': '92688fd379872cf08a43d1436736bc1a7492005a10d75f4fa33170cb0171bd80',
 'lib/gradle-snapshots-9.6.1.jar': '21bf01e6a37d10112e913091335ef11df9ba155f0eb598ea5618c5ff4281da9c',
 'lib/gradle-start-parameter-9.6.1.jar': '0099af9c676950ba6ebf0e8a16debb3a1e985f7a2a52177238c6d2807bdf0a7a',
 'lib/gradle-stdlib-java-extensions-9.6.1.jar': '8fe024282e602c73f6a22e4956c809ca5288f77cf33198df0c86086b9ec4c330',
 'lib/gradle-stdlib-kotlin-extensions-9.6.1.jar': '2075d03fc72f59f6bb5183b61572fbb5213457bb4bfbd2bf7cf2b6b597fb06a1',
 'lib/gradle-time-9.6.1.jar': '3aa73bb6a297919a9b3a45ddaf291de1041b61bd579cebc385fb10c03ed306c7',
 'lib/gradle-toolchains-jvm-shared-9.6.1.jar': '1a94c0a887759e4de0439b6733603660a923821eec8aa5b9d824dc74588771fd',
 'lib/gradle-tooling-api-9.6.1.jar': '2a33de2ad09e22fe8ecaa9babdf5c0488e7ff838f039f45ebb779d9cf796260e',
 'lib/gradle-tooling-api-provider-9.6.1.jar': 'd762220f7b9959d62194f103b9158f816118347763717a611a8b615438c5879d',
 'lib/gradle-versioned-cache-9.6.1.jar': 'e1d67366a8b55133cb560e81ff2ab84b2bfbfe6037e0a74649fdbfa02f8aeb2c',
 'lib/gradle-worker-main-9.6.1.jar': '8dbd27ea7f931ba6bd5e54dd5e1ad0727eb64e52e9d22ac62d2d2ff239bbd994',
 'lib/gradle-worker-process-services-9.6.1.jar': 'd7cce127cf105199db9006c5b03f65608c03b6c00ee4cc233f38465b1c0b00e9',
 'lib/gradle-wrapper-shared-9.6.1.jar': '276376714c41b814a38d064dbe8331eee33880b9f9ea8e1ceb32abbefb839996',
 'lib/groovy-4.0.32.jar': 'd77815c8f31d503bc50129f28892e60b64e339b490f7babf9df70848ce465698',
 'lib/groovy-ant-4.0.32.jar': 'f54b6f3b28f636981c1eaaa66338c0a73fa8be8376ebc8e33962e7212c30e810',
 'lib/groovy-astbuilder-4.0.32.jar': '13112ce414fe528671f044591143739a1cd842b6aceb77264ab006e8a44351c1',
 'lib/groovy-datetime-4.0.32.jar': '0b49c79ff340b5dc85364cac12198131f8ac924e6be03edd00929a7c79642579',
 'lib/groovy-dateutil-4.0.32.jar': '6c6b068813b3a412464e67998e61adb9f3128531c06704e938618612d9f17391',
 'lib/groovy-docgenerator-4.0.32.jar': '08ed0ebbae9d9ad7891fc813ce518ce2e828d2c44bb1e3bfe37c9ec3f466d6c0',
 'lib/groovy-groovydoc-4.0.32.jar': '2174f7f4341b19f8f8b7f3598f3cb6ab92d4e0c21d85b3c56edc1895bd966e23',
 'lib/groovy-json-4.0.32.jar': '4e57a3b28e40e646746063e8deb8863a7672f07d3e3fcbb7b408e0962905000c',
 'lib/groovy-nio-4.0.32.jar': '5f74f8f8bb390744887334d3c0803007d7bac224003e03ba1658f2c1c794e4d9',
 'lib/groovy-templates-4.0.32.jar': '45c1f9c4030c3d3feb3767202e2c0c2c996ce1afc6e3b27eb441545565d0d8c1',
 'lib/groovy-xml-4.0.32.jar': 'ac4b2dbdad90c07db7565770a0749982df04af39c33e11b7f2330aa8a9cb56e2',
 'lib/gson-2.13.1.jar': '94855942d4992f112946d3de1c334e709237b8126d8130bf07807c018a4a2120',
 'lib/guava-33.4.6-jre.jar': '958a035b74ff6c7d0cdff9c384524b645eb618f7117b60e1ee915f9cffd0e716',
 'lib/httpclient-4.5.14.jar': 'c8bc7e1c51a6d4ce72f40d2ebbabf1c4b68bfe76e732104b04381b493478e9d6',
 'lib/httpcore-4.4.14.jar': 'f956209e450cb1d0c51776dfbd23e53e9dd8db9a1298ed62b70bf0944ba63b28',
 'lib/jackson-annotations-2.18.6.jar': 'face5c37bee1f0768f5f198d077fc29d163becca95de9e0f13962c84d1047662',
 'lib/jackson-core-2.18.6.jar': 'e7e1bfa50f0a79db37e6aa37db111cf03aebf4a484b359d21127ab43ab2398c6',
 'lib/jackson-databind-2.18.6.jar': '45d124736ea29dc374171fc1a8a9958e0f44407c1e0aae0297d8eee267fb592e',
 'lib/jackson-datatype-jdk8-2.18.6.jar': 'b3287d74a95741b95295922f64e35e9204825fdd950606613a706d045bdc7443',
 'lib/jackson-datatype-jsr310-2.18.6.jar': 'd600821e90b08353425d3fa31d6a5e08f38b190be93ed284097e6fa66cac1bb4',
 'lib/jansi-2.4.2.jar': '0b7b8b003a90ea491579b62f5118828e45112914c65589b00faa49d6ec785839',
 'lib/javaparser-core-3.27.1.jar': '7ae10d11c5388060a7bf93b721600b951f5585f3782778b6d0555160680d35f8',
 'lib/javax.inject-1.jar': '91c77044a50c481636c32d916fd89c9118a72195390452c81065080f957de7ff',
 'lib/jcifs-1.3.17.jar': '12603c9dfe7a3d16b2d7f1df8bf5b0168728b15be441382cb1a2b209fde0c553',
 'lib/jcl-over-slf4j-2.0.17.jar': 'affd06771589ebfe454bb11315a4f466ecaa135b95f3e7939534cf1d2fd7064c',
 'lib/jctools-core-4.0.5.jar': 'd65e5f38bcd0984e26f87187687f1f70dd52740c4d5e046f8d104e01ab5db95f',
 'lib/jnr-constants-0.10.4-min.jar': '4243da75cad467d1bc6f20dbe21df23f276e62531d07dca31ebf0ef6b7e76dfc',
 'lib/jsoup-1.15.3.jar': 'e20a5e78b1372f2a4e620832db4442d5077e5cbde280b24c666a3770844999bc',
 'lib/jspecify-1.0.0-no-module-annotation.jar': '4b39157abe93213bebf9ea8ef1b2d92147afff6b016a17c86814cc5135000184',
 'lib/jsr305-3.0.2.jar': '766ad2a0783f2687962c8ad74ceecc38a28b9f72a2d085ee438b7813e928d0c7',
 'lib/jul-to-slf4j-2.0.17.jar': 'a7afcd23b9cfd1475e55c94f943b808c5922035e7e2c2a5c65a487a4106bc538',
 'lib/kotlin-assignment-compiler-plugin-embeddable-2.3.21.jar': '5beac8d042a90f17b732e23fe3a164a2f159e7d61c40b462064c720bb638ac0b',
 'lib/kotlin-build-tools-impl-2.3.21.jar': '2cd70396404a0e43c05aaf79a8b35ff3a8ff2e296aedf770f6e5923fbfacae3b',
 'lib/kotlin-compiler-embeddable-2.3.21.jar': 'd3e70fb011675e77ef00f1a68918d3cd91eed26058977d1e3ea2a37a293233af',
 'lib/kotlin-daemon-embeddable-2.3.21.jar': '222fc10a3c22e74d30369bf8a0ca6c4f9372eac7d4a0081e290c256fa4d30fb2',
 'lib/kotlin-reflect-2.3.21.jar': '33e37d9dfa86c7a29ab34e975b5f4a1287b458878611051f3485652220c1a2cb',
 'lib/kotlin-sam-with-receiver-compiler-plugin-2.3.21.jar': '8e9eb418d5ddae8c24ee79da1d5394636dc256defc62a3ea347bd59aca8592fd',
 'lib/kotlin-script-runtime-2.3.21.jar': 'ec61bf1229c837fa9f4255f34ca69816138b73158e7ae9b8d964cf92ca6dfd2e',
 'lib/kotlin-scripting-common-2.3.21.jar': '69885751bdce7d4e1d1b9758baf4bc0fe03b24827abd7b7687e5a7c0b4d029ed',
 'lib/kotlin-scripting-compiler-embeddable-2.3.21.jar': 'a04ff06efb4a5ae07a928da94f9b5d061230c96d7febdaeb8bc7438e1aa31811',
 'lib/kotlin-scripting-compiler-impl-embeddable-2.3.21.jar': '89e78a3326e1205a9420a19441a4f382f7a72241d52c96425e89e5b130387286',
 'lib/kotlin-scripting-jvm-2.3.21.jar': '8cb637132fc7fa511c700ee7f2b63b282630167f5ebd699a263a0b67b5d486ab',
 'lib/kotlin-scripting-jvm-host-2.3.21.jar': '7dec2924a9055d45ddc0fd837312b14355988e07161f086a8d3017995dcb6e07',
 'lib/kotlin-stdlib-2.3.21.jar': '6f64eac736db9434dd6925b4a518b9d1d17177652320c37916cf9ba3ce7d7d7a',
 'lib/kotlinx-coroutines-core-jvm-1.10.2.jar': '5ca175b38df331fd64155b35cd8cae1251fa9ee369709b36d42e0a288ccce3fd',
 'lib/kotlinx-serialization-core-jvm-1.11.0.jar': 'f4a801c647d4351327cd9e1ac4113e2be9ea37a64ab0abae269c25a52e28f35d',
 'lib/kotlinx-serialization-json-jvm-1.11.0.jar': '563a25b4eb5c9128ae9c2479f3d1a5c44dcd176112b91cf03682e906eba5c935',
 'lib/kryo-2.24.0.jar': '7e56b32c635058f9aa2820f88919ab702d029cbcd15285da9992e36cc0ae52f2',
 'lib/log4j-over-slf4j-2.0.17.jar': 'cbf30eaf95357ab7babf9be123da9cc702f0fe83b23392b7a62589d60b5862d1',
 'lib/minlog-1.2.jar': 'a678cb1aa8f5d03d901c992c75741841d98a9bc3d55dad02e84d65315c4e60f2',
 'lib/native-platform-0.22-milestone-29.jar': 'e276d15c665280391f17720031680e16c42e0ae2ec1b57b1e89cca5ced10d12b',
 'lib/native-platform-freebsd-amd64-libcpp-0.22-milestone-29.jar': 'b25f0e064f304e795c35f50fbfe2e24d3f130ae7d0328dd5c6aa95ad02b46e01',
 'lib/native-platform-linux-aarch64-0.22-milestone-29.jar': '36c639a85999ec84f43cbf29e8585e597650d0407b992c172c0d04e77ad320c8',
 'lib/native-platform-linux-aarch64-ncurses5-0.22-milestone-29.jar': 'f3c62295a86f3a9b04a9fe2e056e7ed4b5e5417e20c248c24e790290df859108',
 'lib/native-platform-linux-aarch64-ncurses6-0.22-milestone-29.jar': '474ffd844ccc0e9b4dc2a63c0bf7e9d3736951d59912c0ac04a6ceab8e46689f',
 'lib/native-platform-linux-amd64-0.22-milestone-29.jar': 'acf10546afe29dab7ad9cc5867c805e31b7222ce2ee4e4bcce3f4641af2a10ce',
 'lib/native-platform-linux-amd64-ncurses5-0.22-milestone-29.jar': 'd3d02109182d8601892ea1a2dacfce3ebadb9b21cfa1263b7355f477a9751cbb',
 'lib/native-platform-linux-amd64-ncurses6-0.22-milestone-29.jar': '0586745b24bd189cecc5b54b706056c61aa3d7477fdd1dcdcbfe7bdb4275f16e',
 'lib/native-platform-osx-aarch64-0.22-milestone-29.jar': 'e7259970d9acc0115e5a6e3d6bf3e39b2930f043e50c145dc364420e8a706906',
 'lib/native-platform-osx-amd64-0.22-milestone-29.jar': '956f1370e77c7d238aa12d5b5e0f7730abbe4c443b951221e12c0af37d297913',
 'lib/native-platform-windows-aarch64-0.22-milestone-29.jar': 'ab7149a4dfd072464af5abc60a3dd83032466e1a85d4af0524eb6c79475b9ff9',
 'lib/native-platform-windows-aarch64-min-0.22-milestone-29.jar': 'be2556702a1fc477c7ebee3c01d0c834a488318477c212be0d874a99ddc9795a',
 'lib/native-platform-windows-amd64-0.22-milestone-29.jar': 'fac04afce80d47fecfc540a7ebcd89dcd6fc1804a5097b5c1e4dae5cf427f95f',
 'lib/native-platform-windows-amd64-min-0.22-milestone-29.jar': '032dd5c74eeb7720b3d149ad961d89afa2e15f1f838300602c6fde815fdd0f0b',
 'lib/native-platform-windows-i386-0.22-milestone-29.jar': '5d3fcd7f5d81bac216ab016a9edbf4f2fd34380243b2f52aa3b93138ad73ca44',
 'lib/native-platform-windows-i386-min-0.22-milestone-29.jar': 'd1f17ae3ce78b16cca6b1340bb9aad5b0a59ad4f8f9fa6a3325ef609e8454b8a',
 'lib/objenesis-2.6.jar': '5e168368fbc250af3c79aa5fef0c3467a2d64e5a7bd74005f25d8399aeb0708d',
 'lib/plugins/aws-java-sdk-core-1.12.780.jar': 'a1a381d1ff1674119b8602bde2dc1bc05a7bc5cd130cc985a2639765ba0216ce',
 'lib/plugins/aws-java-sdk-kms-1.12.780.jar': '34cdd2c3e40f833d844d191054a30e308f380d23fee7185d7efef6aa85b48742',
 'lib/plugins/aws-java-sdk-s3-1.12.780.jar': 'aa3cacf1d904db8b08e3a20909e662e277e1846a05a31e98b79aeda4aa731cfe',
 'lib/plugins/aws-java-sdk-sts-1.12.780.jar': '5798fb45896db0eebbdd18d8376b2a362d7c0ba12324bf4a796849a6b91ae83a',
 'lib/plugins/bcpg-jdk18on-1.84.jar': 'c0e6303a0d7589040f400950ecee87a14b81312e84ed15e5390ebb0c4566ddab',
 'lib/plugins/bcprov-jdk18on-1.84.jar': '64d6c5a6121fcd927152dd182cbed39afe0fda641a970d9bcc0c9cb1858b2731',
 'lib/plugins/bcutil-jdk18on-1.84.jar': 'b374e16963421fb9cfb01cc20d7ad8fd2f8b8188e3eef0ec0a8965e245f7619a',
 'lib/plugins/dd-plist-1.27.jar': 'c9e29ebaada73dcf744687c3e75157b1cdfea8c09622720373b719594aac65c1',
 'lib/plugins/google-api-client-1.34.0.jar': '40cfc42643746f8ca3c42911e17c4048dc080a2f12a79c927297b50665de7140',
 'lib/plugins/google-api-services-storage-v1-rev20220705-1.32.1.jar': '51446cf0373f19afc1b07b9dd75f254dfca917a4833dfb3bac61b2cad54c3400',
 'lib/plugins/google-http-client-1.42.2.jar': '97544ad0b0ae39b6ac14b1bcacc0f6c20c46c07ca05b9362ceb38f216c51e049',
 'lib/plugins/google-http-client-apache-v2-1.42.2.jar': '949ae5257aa1774b00f4bff1e81fe7c6b8985aba390cccd0abeb79a8d290ab75',
 'lib/plugins/google-http-client-gson-1.42.2.jar': '4fbeaf39f4fc12c10f45f1d4b8e45db6a0de4452d75da81f94926985b98f9637',
 'lib/plugins/google-oauth-client-1.34.1.jar': '193edf97aefa28b93c5892bdc598bac34fa4c396588030084f290b1440e8b98a',
 'lib/plugins/gradle-ant-impl-9.6.1.jar': '26002d35793c871576fdb41281dee67246fee423629afb5eb2fea872c1897793',
 'lib/plugins/gradle-ant-worker-9.6.1.jar': '4af4999dd316a36e0cdcff3c5b1411b59b0080746443493710d7f455dcea57f5',
 'lib/plugins/gradle-antlr-9.6.1.jar': 'ecff2d5d60c9d1c5d931aadc9b2bf2fcc0d0bcc5f892f83338c291a0fa2006ac',
 'lib/plugins/gradle-base-compiler-worker-9.6.1.jar': '3f736cd4a59ddff70cb5002446b18a911d6b93da8084248bde5180243ff86b77',
 'lib/plugins/gradle-base-ide-plugins-9.6.1.jar': 'e0be3a2630e660e7ce2b7beabac3916f307e60624eecbe772c431217a20ab3c3',
 'lib/plugins/gradle-bean-serialization-services-9.6.1.jar': 'e3094434107b221f4e9b38f6c1f7fe01e6c5b0727b54c8944a20874013e6853a',
 'lib/plugins/gradle-build-cache-http-9.6.1.jar': '14ce9090e5e42b3fddb2d96b73659d14131561ef51ff5f551f7d735c808914e7',
 'lib/plugins/gradle-build-init-9.6.1.jar': '4c8808fb9c675850cb38dd84817aa743968e4e5b5f35618ab440fdc685227f41',
 'lib/plugins/gradle-build-profile-9.6.1.jar': 'c35efcbc7b8cd620475dc91076c94b16434cf43d8cce5e76313cd54a5ee1d3f6',
 'lib/plugins/gradle-code-quality-9.6.1.jar': 'a18fa40ee1f412bf102dfeb8ef5eec001f4346d748ccc185049a34858cea45d3',
 'lib/plugins/gradle-code-quality-workers-9.6.1.jar': 'd8cc0d2ba7f8a7700f2fa1925f13c4bc1cc5b4c6d29ce29598ce7333f381416d',
 'lib/plugins/gradle-composite-builds-9.6.1.jar': '75e09e8cf4fee9b879ff24e82f6b6ee18e4550d6fdbec760aff353e35f6d557d',
 'lib/plugins/gradle-configuration-cache-9.6.1.jar': '599951eeeea7ad70c9079286fb9fdbf72d2aba04772f4bcecde30f812218837c',
 'lib/plugins/gradle-configuration-cache-base-9.6.1.jar': '7eb37287fae6dc58435526bc5f9e3b59362a6f2f33dbe1033a1435fbb448b318',
 'lib/plugins/gradle-core-serialization-codecs-9.6.1.jar': '6342107359b00c29cdd7f7119cde2b1f52ed69f668c23a03b15e9d649604d983',
 'lib/plugins/gradle-credentials-impl-9.6.1.jar': '11741a14e6c83ecfb271b13b71bfe5608968044acf9aa44f6bcdb3ba251ef7ec',
 'lib/plugins/gradle-daemon-server-worker-9.6.1.jar': '1d8c13e68d8ad52e060d12fc4a209fa37776948af836b9e87aa3e8b31c1af95b',
 'lib/plugins/gradle-declarative-dsl-tooling-builders-9.6.1.jar': 'fe1a1b4f207e34fc5ae7d354e01b43b9e2070e0c1104f0ee633e1d70df60c6bc',
 'lib/plugins/gradle-dependency-management-9.6.1.jar': 'b0f4d246f85d30159e77178f123614f4fdf8c64279c6bb2a14c603ea21126259',
 'lib/plugins/gradle-dependency-management-serialization-codecs-9.6.1.jar': 'aee751e15d85c7c667f7d7914d18ca72c675742db87c361776383924488b385a',
 'lib/plugins/gradle-ear-9.6.1.jar': '0a2e2f4218dad49c393aef616ca6976f01e3e4274dad3b49f1f431e4c5e7fe1c',
 'lib/plugins/gradle-encryption-services-9.6.1.jar': 'cdf087542a46dac6170d4f74248eca5c7355f75b54603dd200755b50cea6acb6',
 'lib/plugins/gradle-enterprise-9.6.1.jar': '744807ce2346a65c7a05c7a68096f1839725f89c92da90614711f9e6331b8e51',
 'lib/plugins/gradle-flow-services-9.6.1.jar': '3b299a2aabbc7cb693a5b6e18509734f383dd8ac61cf564a0393562e87a4124e',
 'lib/plugins/gradle-graph-isolation-9.6.1.jar': 'c45e78cef4a43010776cadc5b068820986c75091a7b9db36c6896cef3d8b2990',
 'lib/plugins/gradle-graph-serialization-9.6.1.jar': '270163f5104af8386463ee5fad8431f8071a33cdb532466402a9f52dd66862ca',
 'lib/plugins/gradle-groovy-compiler-worker-9.6.1.jar': '775a14e778d34764f06605d5f7850f6da158a008353f97784b451cf68d4ad205',
 'lib/plugins/gradle-groovydoc-worker-9.6.1.jar': 'aaee8845dca1a8e7c70f852e188c0773b4d5250a4d01d3ec2f45298731b0f250',
 'lib/plugins/gradle-guava-serialization-codecs-9.6.1.jar': 'c76f94d6fc4702d6dacf40cb7a864498b18477bb0e56ad43cca63d94d3aa5f24',
 'lib/plugins/gradle-ide-9.6.1.jar': '30821c16cda74dbd6e751c649f6458905f9cdd446d25b32209ee19f8e46799a5',
 'lib/plugins/gradle-ide-model-impls-9.6.1.jar': 'e08366afd0d76fbf006294ce3401a7186f91fcbee5397879c09c6b2cf6688bf8',
 'lib/plugins/gradle-ide-native-9.6.1.jar': '6020339b4d2fe0c2dee568bf251094d098dcea7dffe011094de6661196229ba9',
 'lib/plugins/gradle-ide-plugins-9.6.1.jar': 'bed46c171de0da88101606fce0cf5a7ca618570f63f3d5fb326ffe812d4ca195',
 'lib/plugins/gradle-instrumentation-declarations-9.6.1.jar': '6d5ee19b76368b817d626fa5ef5ce480585fda34c18d997bb27bd4f6db07c4e3',
 'lib/plugins/gradle-isolated-action-services-9.6.1.jar': '7badbd2efa71cf94627bcc7650d3a25101dc59fcf4cc0f02f91788b317c6e2ab',
 'lib/plugins/gradle-ivy-9.6.1.jar': 'e5cd67170480db6b77f2e8ab14325ac70888a52420a0a9fb30b8a668b3391426',
 'lib/plugins/gradle-jacoco-9.6.1.jar': 'dcf752a6543f5e1b2daa03819456989e6b459d415d0828fb313280ea8dc15aa0',
 'lib/plugins/gradle-jacoco-workers-9.6.1.jar': '6137d54150154ced648f1ddb111a3901574e2960f16418ab6ba60c6ba0ceefa9',
 'lib/plugins/gradle-java-compiler-plugin-9.6.1.jar': 'a6f39f59e2cfd17d1eb3794a48d3822fec38937c70cc8195a502f8de6c478180',
 'lib/plugins/gradle-java-compiler-worker-9.6.1.jar': '3668faa71d5469577dee5c819b8126ae9c069d496526b69face115506c6af42f',
 'lib/plugins/gradle-java-platform-9.6.1.jar': 'a82c9a3dc2db029ecad7739df48d6dcce5005eafa7f0aa78e0af32a3338d5a63',
 'lib/plugins/gradle-javadoc-9.6.1.jar': '49e5719cc4ec2999356ee73e009892f124bf13efa895e4dfaace2f258644fa6c',
 'lib/plugins/gradle-jvm-compiler-worker-9.6.1.jar': 'dc6908cf759920e05332ed01980114af151726963b0054d6303f853cdba74314',
 'lib/plugins/gradle-kotlin-dsl-provider-plugins-9.6.1.jar': '414fb35f106555a33c86604ac7f16e4e534897b711b16a740ce1d17d4daf26b0',
 'lib/plugins/gradle-kotlin-dsl-tooling-builders-9.6.1.jar': '12d24c9255d9243f98b74e5b473c8ff661c294ce4654aa49b95d1d7e1630c51c',
 'lib/plugins/gradle-kotlin-dsl-tooling-model-impls-9.6.1.jar': '9f6aa5c3856e39575d2baee88c7b545d88aa7601ed9a3f004d5bdf87561a3ee9',
 'lib/plugins/gradle-language-groovy-9.6.1.jar': 'de387f97b25debfaeb8e7a9f31c91f80fbfaa3269f84faa8d73d36841fd93bee',
 'lib/plugins/gradle-language-java-9.6.1.jar': 'f4377da0cb002bdb2a059ba8ed8e10fafe602572103d71c1f553823099e1ab3b',
 'lib/plugins/gradle-language-jvm-9.6.1.jar': '7519c6228b6eec5e07c4db4640508584712ae2c482ea719fa5185b8570a1ed6f',
 'lib/plugins/gradle-language-native-9.6.1.jar': '99e6627bd23e070bac4574588952a0e39c86cce31408949e6d80b0d9913fb238',
 'lib/plugins/gradle-maven-9.6.1.jar': 'd4384548e03203944120f2db24acb699f8e321c015a4d271abce419deb23fb47',
 'lib/plugins/gradle-platform-base-9.6.1.jar': '246602b814db46d51e5f6fb32dcbd88af4d4f94aa1c54feeb227e69cec3083cb',
 'lib/plugins/gradle-platform-jvm-9.6.1.jar': '4d6ddeac2b6dec081419c634b41418674e7a7b49441dca9169650ad11438f7e8',
 'lib/plugins/gradle-platform-native-9.6.1.jar': 'f78b185be7abaa3ecbabef45be72df3e332d6a1871ac2202b851c885162a83f1',
 'lib/plugins/gradle-plugin-development-9.6.1.jar': '02901ac5b0807b30ded67ef76febc5b0342cc17282e385b78461514005879862',
 'lib/plugins/gradle-plugin-use-9.6.1.jar': '5cc7eed01588c294c0df8177ae486c3ed136f584b7ee594bd19c688e155cb110',
 'lib/plugins/gradle-plugins-application-9.6.1.jar': '08f853d289d376e80e34b2930af25a7114ab39d765b8a4f6ecd99b2f51a7d6b7',
 'lib/plugins/gradle-plugins-distribution-9.6.1.jar': '2a0654ee8be84c0c54448e5916bc7d2be8581dc8432bbc41f240ee3dd9c3a16f',
 'lib/plugins/gradle-plugins-groovy-9.6.1.jar': '853349b111196646a65c8def167bc524f1d702d1214c6f9ae2b565d71dccb962',
 'lib/plugins/gradle-plugins-java-9.6.1.jar': '77242fefc76cf9d2562a007c26eca8f70d75be0008048b24a2ef2619254da933',
 'lib/plugins/gradle-plugins-java-base-9.6.1.jar': '4ee12e0077222947d6c950d68e8d07bb10718959c52966b0d4f68e457edb5ff2',
 'lib/plugins/gradle-plugins-java-library-9.6.1.jar': '828241574ef85ef413d6cd1c416123124a606cd9eb98ca613a9af0623a25de51',
 'lib/plugins/gradle-plugins-jvm-test-fixtures-9.6.1.jar': '6cf5ef6ad2cc160975f0b298a1f1490d1aaa256b05aac06a2289d89527096f2a',
 'lib/plugins/gradle-plugins-jvm-test-suite-9.6.1.jar': 'f894009791236c5efe48916d670755be3e08261dd529f98c1b41e1507f156c6b',
 'lib/plugins/gradle-plugins-model-native-9.6.1.jar': 'ac5183fcbcd9871c87252eebaf12dd941c125781500d39aa935d4e58a7cc6470',
 'lib/plugins/gradle-plugins-test-report-aggregation-9.6.1.jar': '5bb076fd31aff48cf0bf4569ad7e711a828dcc275f7e60b5f3fc5bd268bcd2e0',
 'lib/plugins/gradle-plugins-version-catalog-9.6.1.jar': 'a107149895af4f055977788b4729f158b511d6ed840a0c57ee096d1c41847405',
 'lib/plugins/gradle-publish-9.6.1.jar': 'ba69d033e9536ac517267e20120ea63aff4555a550bb79d0870788efc3a07024',
 'lib/plugins/gradle-reporting-9.6.1.jar': 'f30a636bb30e9cfb338157f1b693c5fcf68133130f709b712d8e19ae9ead674b',
 'lib/plugins/gradle-resources-gcs-9.6.1.jar': '8eec2152e4b4f532ac5bfab16816b013f4e1c39e7f7720c784fb9e80835060aa',
 'lib/plugins/gradle-resources-s3-9.6.1.jar': 'caeb899d738c79595cfdb1051b6536f032681e5cb4cc9e6135aafd560a62f3c3',
 'lib/plugins/gradle-resources-sftp-9.6.1.jar': '7e3294174db74eb87d14206a7363ac890ab0398d45c47987d5cc14fc9c398432',
 'lib/plugins/gradle-scala-9.6.1.jar': '232c98e8d107724b4c5b76326c94725855eb2d96079b9234e14e116abe92fbc0',
 'lib/plugins/gradle-scala-compiler-worker-9.6.1.jar': '0b7ddbf6e4f92d30a0fd21fbe94dc32906b1dc37ee9ea70cd0efbbce7ef35d5f',
 'lib/plugins/gradle-scaladoc-worker-9.6.1.jar': '45a62febf9d8df6ce884090ef6bc77ad1b5b909ba252f637d49c4e4983bb80e5',
 'lib/plugins/gradle-security-9.6.1.jar': '99778d38b3076739752542dded7ba72d7cf3fdb0ce1eacdad74782090aea17ce',
 'lib/plugins/gradle-signing-9.6.1.jar': '74bc79f58cb1c68d58a3215f44ead9798ae65909e254625460ffc8d50b402e60',
 'lib/plugins/gradle-software-diagnostics-9.6.1.jar': '321b1fb1db5d8e2e85f466c3936b51be2589a8c674a0de5a1bc1e8e7d242745f',
 'lib/plugins/gradle-stdlib-serialization-codecs-9.6.1.jar': 'fdc34c2d0951f91736d2fae95aff98333d3a0e94a1e8ff86928a2ce7192ed0d8',
 'lib/plugins/gradle-test-kit-9.6.1.jar': 'e9de27b7e391683c01bd5bea777e4edb03299c4dba2fe2b845b3c9f2fbd3e769',
 'lib/plugins/gradle-test-suites-base-9.6.1.jar': 'b831fb9a8cc2ea9c47efbe73e4c3d8f014599d38954d59a14bd6500c218d5c4a',
 'lib/plugins/gradle-testing-base-9.6.1.jar': 'd76d8b104b7867e3ffd1428a359decaf368881452051d60c37c6fc0450c3f055',
 'lib/plugins/gradle-testing-base-infrastructure-9.6.1.jar': '75d30b2c8eb908634dc74bb12144d58dee66d96ddd0a18c1727eacbc32ebd2c9',
 'lib/plugins/gradle-testing-jvm-9.6.1.jar': '4ac8bd1f897dd4d35bc19fdd8a77dc2178d303a05a6ce42adb850ddf13e966aa',
 'lib/plugins/gradle-testing-jvm-infrastructure-9.6.1.jar': 'd476e676a9319fb38825ec829254518343b71267c5c929ed903dd23e980c8d14',
 'lib/plugins/gradle-testing-native-9.6.1.jar': '94a85503cde7576c7f17a6ec536ff5d1acf53e5fd888f14015dabf63260b7f05',
 'lib/plugins/gradle-toolchains-jvm-9.6.1.jar': '255cb2dabf5b6df503aff83ac88baefa0e0680cab056f550eb545f93f5e79605',
 'lib/plugins/gradle-tooling-api-builders-9.6.1.jar': 'b4bb86b5df6452fd2f329f05e70fa3874b71cc4948c04c01c2031fb598b1bd93',
 'lib/plugins/gradle-tooling-native-9.6.1.jar': 'bb699686feb1d2fc4a835cb0913c522e63fb769d42bdff899a720acfaff3b2f2',
 'lib/plugins/gradle-tooling-native-model-impls-9.6.1.jar': 'f4bfddcc5b076a09e41b8716e71df587487d14e99fc78dd5beb86ea2e65b8951',
 'lib/plugins/gradle-unit-test-fixtures-9.6.1.jar': 'a74c016c75f102ba4967d37b5c1edb11e04a7578fbb2dac370390b0ef50cf911',
 'lib/plugins/gradle-version-control-9.6.1.jar': 'ff2c66d1a5515d0c8855d73f304b6171f31977cf59e339eeb8f1f585e4f7a5ad',
 'lib/plugins/gradle-war-9.6.1.jar': '223bc57418d2259ac78572340a17e348785ed5e04a07063a04667a35e49287bd',
 'lib/plugins/gradle-workers-9.6.1.jar': 'be2ba2f4977b7fcd2c73b1ad9f374b013814506f3f4f8d8c97464f2fa91e4bf5',
 'lib/plugins/gradle-wrapper-main-9.6.1.jar': 'd60451d25bc1908d8c64ba2e998db5b7d7ec7fb029ab51d6ae665ab79f5cd893',
 'lib/plugins/grpc-context-1.27.2.jar': 'bcbf9055dff453fd6508bd7cca2a0aa2d5f059a9c94beed1f5fda1dc015607b8',
 'lib/plugins/ivy-2.5.3.jar': '9502aa5aabf0b1484924a13ef4b5d24f121f7f91aab6768f11cc9d0906c0803b',
 'lib/plugins/jatl-0.2.3.jar': '93ee3810f7275244f5f6311d50c587d8fe43ab5047dfa3291aa96fe50587501c',
 'lib/plugins/jmespath-java-1.12.780.jar': 'd5f0f1a8873eb81c3be49603dab3f0aeaf08dc47319b513f64e63ce635e8efc1',
 'lib/plugins/jna-5.17.0.jar': 'b3a9408e7c51e08ef0e3bfcc08f443f6ec0f6191ba8cd7c18d53d2b22e5bdbc0',
 'lib/plugins/jna-platform-5.17.0.jar': 'b7e3d46c87bad2eb409b0e704916bcd81206168e357312dfddd0e253679cd9e0',
 'lib/plugins/joda-time-2.14.0.jar': '1e2da6f9eb65f20a25d9a3186831ed2b3fb14f7a48e1ef8206135ee58cb143d3',
 'lib/plugins/jsch-0.2.16.jar': '562165c28741df479de96fc492d66a7f33cd403d179df21d81734e93aa0942f1',
 'lib/plugins/maven-builder-support-3.9.5.jar': '88abb6ca39b12caefadcf0ce9f3f9bc8516cfe01fa46039228e1047ccfd018a9',
 'lib/plugins/maven-model-3.9.5.jar': '27a79004cae6d0f894489a8e48559c76ed197cf543ce07b24f25d26f4b8bf2fb',
 'lib/plugins/maven-repository-metadata-3.9.5.jar': 'bbddcd62140628a967f0cf795ff8516b430867c0e82bc789912c14166295707a',
 'lib/plugins/maven-settings-3.9.5.jar': 'cdf3d94994a5c0f4f7adccabdc4bc47aebdc1e705d42279d60ddaec367d43528',
 'lib/plugins/maven-settings-builder-3.9.5.jar': 'cb19f199d7f629b6c265b726221b7a5a47297d1bf47f5455870b46352d07dda3',
 'lib/plugins/opencensus-api-0.31.1.jar': 'f1474d47f4b6b001558ad27b952e35eda5cc7146788877fc52938c6eba24b382',
 'lib/plugins/opencensus-contrib-http-util-0.31.1.jar': '3ea995b55a4068be22989b70cc29a4d788c2d328d1d50613a7a9afd13fdd2d0a',
 'lib/plugins/org.eclipse.jgit-7.2.1.202505142326-r.jar': '9f3b69423f695abd21ad2cca0e8caf108444750c32486bfafc1c101671ecd944',
 'lib/plugins/org.eclipse.jgit.ssh.apache-7.2.1.202505142326-r.jar': '23fa7cd41bde9adbc926350671105972094f5977e0ec9b90896149ec3cc69ce5',
 'lib/plugins/org.eclipse.jgit.ssh.apache.agent-7.2.1.202505142326-r.jar': '3bc32b8b337b09289ea8b5e3d4403313658ab0df5ff1f4551892566d5f31a941',
 'lib/plugins/plexus-cipher-2.0.jar': '9a7f1b5c5a9effd61eadfd8731452a2f76a8e79111fac391ef75ea801bea203a',
 'lib/plugins/plexus-interpolation-1.26.jar': 'b3b5412ce17889103ea564bcdfcf9fb3dfa540344ffeac6b538a73c9d7182662',
 'lib/plugins/plexus-sec-dispatcher-2.0.jar': '873139960c4c780176dda580b003a2c4bf82188bdce5bb99234e224ef7acfceb',
 'lib/plugins/plexus-utils-3.6.1.jar': '05a63effd67e2d6b9d610cc82e2bd7473289d34802e57a529b28110f28af5679',
 'lib/plugins/snakeyaml-2.0.jar': '880c9d896e4b74a06c549c15ca496450165d6909fa15d7e662bee8f6a66d7afa',
 'lib/plugins/sshd-osgi-2.15.0.jar': '3c8a183f81e176d9c452c9bb94007574bc8188446b4fc98b527aa79074cd0dda',
 'lib/plugins/sshd-sftp-2.15.0.jar': '4dcf4f8cc123dca9802fa993b754308be388f13daa6d59148e38cf8d0673962b',
 'lib/qdox-1.12.1.jar': '21fba22f830e9268f07cf4ab2d99e8181abbdcb0cb91ee0228eb3cb918dcdd1d',
 'lib/slf4j-api-2.0.17.jar': '7b751d952061954d5abfed7181c1f645d336091b679891591d63329c622eb832',
 'lib/tomlj-1.0.0.jar': '32697c7567b2921c473678a820b13fc64700aa87bb14576eeb48d0ed5847cfd4'}
DECLARED_CLASSES = {'org.gradle.internal.jvm.DefaultModularitySpec': {'baseClass': 'org.gradle.internal.jvm.DefaultModularitySpec',
                                                   'classSha256': 'baad8b87d5baa266d400abb67d52a10ab1c4afe8f9ef1eb721e9538128756348',
                                                   'jar': 'lib/gradle-process-services-9.6.1.jar',
                                                   'jarSha256': 'b7c04a9f1dacdd9230dbf58177d8195a3e9d61ed5b59d0c8eb64fb3aa0db226d'},
 'org.gradle.jvm.toolchain.internal.DefaultToolchainJavaLauncher': {'baseClass': 'org.gradle.jvm.toolchain.internal.DefaultToolchainJavaLauncher',
                                                                    'classSha256': '7673c65551445a806c89e2ac6dac36b337a684ff89865c3e8ec830819f5baf7b',
                                                                    'jar': 'lib/plugins/gradle-toolchains-jvm-9.6.1.jar',
                                                                    'jarSha256': '255cb2dabf5b6df503aff83ac88baefa0e0680cab056f550eb545f93f5e79605'},
 'org.gradle.jvm.toolchain.internal.JavaToolchain': {'baseClass': 'org.gradle.jvm.toolchain.internal.JavaToolchain',
                                                     'classSha256': 'f76c8a9033b64d172c89461bf6baeb791e87d17672a7b1b61ba0ff9ec70ffc39',
                                                     'jar': 'lib/gradle-toolchains-jvm-shared-9.6.1.jar',
                                                     'jarSha256': '1a94c0a887759e4de0439b6733603660a923821eec8aa5b9d824dc74588771fd'},
 'org.gradle.jvm.toolchain.internal.JavaToolchainInput': {'baseClass': 'org.gradle.jvm.toolchain.internal.JavaToolchainInput',
                                                          'classSha256': '890498733ffc37e9f7b0c7da59c80da0f900ab4affa1432af3b032fc11cb4049',
                                                          'jar': 'lib/gradle-toolchains-jvm-shared-9.6.1.jar',
                                                          'jarSha256': '1a94c0a887759e4de0439b6733603660a923821eec8aa5b9d824dc74588771fd'},
 'org.gradle.process.internal.DefaultJavaDebugOptions': {'baseClass': 'org.gradle.process.internal.DefaultJavaDebugOptions',
                                                         'classSha256': 'ae5c4a7daf98189ae2e133838bc2c5b906b7ec45601410a38a5c7c4235c22d2b',
                                                         'jar': 'lib/gradle-process-services-9.6.1.jar',
                                                         'jarSha256': 'b7c04a9f1dacdd9230dbf58177d8195a3e9d61ed5b59d0c8eb64fb3aa0db226d'}}
DECLARED_REGISTRY = {
    'javaLauncher': 'org.gradle.jvm.toolchain.internal.DefaultToolchainJavaLauncher',
    'javaLauncher.metadata': 'org.gradle.jvm.toolchain.internal.JavaToolchain',
    'javaLauncher.metadata.taskInputs': 'org.gradle.jvm.toolchain.internal.JavaToolchainInput',
    'modularity': 'org.gradle.internal.jvm.DefaultModularitySpec',
    'debugOptions': 'org.gradle.process.internal.DefaultJavaDebugOptions',
}
DECLARED_CHILDREN = {
    'javaLauncher': {'metadata'},
    'javaLauncher.metadata': {'languageVersion', 'taskInputs'},
    'javaLauncher.metadata.taskInputs': {'languageVersion', 'vendor', 'implementation'},
    'modularity': {'inferModulePath'},
    'debugOptions': {'enabled', 'host', 'port', 'server', 'suspend'},
}


def declared_string(value):
    require(type(value) is str and len(value) <= DECLARED_MAX_STRING, 'declared String required/bound')
    try:
        data = value.encode('utf-8')
    except UnicodeEncodeError as error:
        raise RuntimeError('declared unpaired surrogate') from error
    require(len(data) <= DECLARED_MAX_STRING, 'declared String byte bound')
    return data


def declared_path(value):
    declared_string(value)
    require(value.startswith('/') and not value.startswith('//') and str(pathlib.PurePosixPath(value)) == value and
            '..' not in pathlib.PurePosixPath(value).parts and '\x00' not in value, 'declared lexical path')
    return value


def declared_canonical(value, deadline=None, limit=None):
    deadline = time.monotonic() + 120 if deadline is None else deadline
    limit = MAX_JSON if limit is None else min(limit, MAX_JSON)
    # json.dumps uses short control escapes; convert those to the required \u00xx form.
    output = io.BytesIO()
    used = 0
    def append(part):
        nonlocal used
        require(time.monotonic() <= deadline, 'canonical time bound')
        data = part.encode('utf-8')
        used += len(data)
        require(used * 2 <= limit, 'declared canonical scratch bound')
        output.write(data)
    def visit(item):
        if type(item) is str:
            declared_string(item)
            append('"')
            for char in item:
                code = ord(char)
                append('\\' + char if char in ('"', '\\') else f'\\u{code:04x}' if code < 32 else char)
            append('"')
        elif item is None: append('null')
        elif type(item) is bool: append('true' if item else 'false')
        elif type(item) is int: append(str(item))
        elif type(item) is list:
            append('[')
            for index, child in enumerate(item):
                if index: append(',')
                visit(child)
            append(']')
        elif type(item) is dict:
            append('{')
            for index, key in enumerate(sorted(item)):
                if index: append(',')
                visit(key); append(':'); visit(item[key])
            append('}')
        else: require(False, 'nonwire canonical value')
    visit(value)
    return output.getvalue()


def declared_array_component(name):
    declared_string(name)
    depth = len(name) - len(name.lstrip('['))
    require(depth <= 128, 'array component depth')
    if depth:
        tail = name[depth:]
        if tail in ('Z','B','C','S','I','J','F','D'): return
        require(tail.startswith('L') and tail.endswith(';'), 'array component descriptor')
        name = tail[1:-1]
    require(name in {'org.gradle.jvm.toolchain.JavaLanguageVersion', 'java.lang.Short', 'java.lang.Byte', 'java.lang.String', 'java.lang.Object', 'java.lang.Character', 'java.util.LinkedList', 'java.math.BigInteger', 'boolean', 'int', 'org.gradle.api.provider.Provider', 'char', 'java.lang.Boolean', 'java.util.LinkedHashSet', 'java.lang.Integer', 'java.util.TreeSet', 'java.util.List', 'java.util.Set', 'java.util.Map', 'org.gradle.api.file.Directory', 'long', 'java.lang.Double', 'java.nio.file.Path', 'short', 'java.io.File', 'java.util.HashSet', 'java.lang.Float', 'byte', 'java.lang.Long', 'org.gradle.api.file.RegularFile', 'java.util.HashMap', 'org.gradle.api.tasks.PathSensitivity', 'float', 'java.math.BigDecimal', 'java.util.TreeMap', 'double', 'java.util.LinkedHashMap', 'java.util.ArrayList'}, 'unsupported array component')


def declared_array_member(component, item):
    # Component identity is meaningful: a primitive/int array cannot carry String wire values.
    primitives = {'boolean': ('boolean', None), 'char': ('char', None),
        'byte': ('integer', 'java.lang.Byte'), 'short': ('integer', 'java.lang.Short'),
        'int': ('integer', 'java.lang.Integer'), 'long': ('integer', 'java.lang.Long'),
        'float': ('ieee', 'java.lang.Float'), 'double': ('ieee', 'java.lang.Double')}
    if item == ['null']:
        require(component not in primitives, 'null primitive array element'); return
    if component.startswith('['):
        require(item[0] == 'array', 'nested array element tag')
        inner = component[1:]
        if inner.startswith('L') and inner.endswith(';'): inner = inner[1:-1]
        inner = {'Z':'boolean','C':'char','B':'byte','S':'short','I':'int','J':'long','F':'float','D':'double'}.get(inner,inner)
        # Reference arrays are covariant only across reviewed component classes.
        def assignable(expected, actual):
            if expected == actual: return True
            if expected == 'java.lang.Object': return actual not in primitives
            bases = {'java.util.List': {'java.util.ArrayList','java.util.LinkedList'},
                'java.util.Set': {'java.util.HashSet','java.util.LinkedHashSet','java.util.TreeSet'},
                'java.util.HashSet': {'java.util.LinkedHashSet'},
                'java.util.Map': {'java.util.HashMap','java.util.LinkedHashMap','java.util.TreeMap'},
                'java.util.HashMap': {'java.util.LinkedHashMap'}}
            if expected.startswith('[') and actual.startswith('['):
                def decode(name):
                    name=name[1:]
                    if name.startswith('L') and name.endswith(';'): return name[1:-1]
                    return {'Z':'boolean','C':'char','B':'byte','S':'short','I':'int','J':'long','F':'float','D':'double'}.get(name,name)
                return assignable(decode(expected),decode(actual))
            return actual in bases.get(expected,set())
        require(assignable(inner,item[1]), 'nested array component mismatch'); return
    if component == 'java.lang.Object': return
    wrappers = {'java.lang.Boolean':'boolean','java.lang.Character':'char','java.lang.Byte':'byte',
        'java.lang.Short':'short','java.lang.Integer':'int','java.lang.Long':'long','java.lang.Float':'float','java.lang.Double':'double'}
    primitive = wrappers.get(component,component)
    if primitive in primitives:
        tag, exact = primitives[primitive]
        require(item[0] == tag and (exact is None or item[1] == exact), 'array scalar component mismatch'); return
    tags = {'java.lang.String': {'string'}, 'java.math.BigInteger': {'integer'}, 'java.math.BigDecimal': {'decimal'},
        'java.io.File': {'file'}, 'java.nio.file.Path': {'path'}, 'org.gradle.api.file.RegularFile': {'regular-file'},
        'org.gradle.api.file.Directory': {'directory'}, 'org.gradle.api.provider.Provider': {'provider'},
        'org.gradle.jvm.toolchain.JavaLanguageVersion': {'java-language'}, 'org.gradle.api.tasks.PathSensitivity': {'enum'},
        'java.util.List': {'list'}, 'java.util.ArrayList': {'list'}, 'java.util.LinkedList': {'list'},
        'java.util.Set': {'set','ordered-set'}, 'java.util.HashSet': {'set','ordered-set'},
        'java.util.LinkedHashSet': {'ordered-set'}, 'java.util.TreeSet': {'set'},
        'java.util.Map': {'map'}, 'java.util.HashMap': {'map'}, 'java.util.LinkedHashMap': {'map'}, 'java.util.TreeMap': {'map'}}
    require(item[0] in tags.get(component,set()), 'array reference component mismatch')
    if component == 'java.math.BigInteger': require(item[1] == component, 'BigInteger array component mismatch')


def validate_declared_properties(properties, gradle_binding, budget=None, deadline=None):
    deadline = time.monotonic() + 120 if deadline is None else deadline
    require(type(properties) is dict and {'mainClass', 'maxHeapSize', 'enableAssertions', 'ignoreExitValue', 'mainModule', 'hostArchitecture', 'debug', 'jvmArgs', 'minHeapSize', 'compiler', 'systemProperties', 'defaultCharacterEncoding', 'args'} <= set(properties), 'declared property map/required inputs')
    require(not any(k == prefix or k.startswith(prefix+'.') for k in properties for prefix in ('argumentProviders','jvmArgumentProviders')), 'expanded argument-provider schema')
    nested_keys = set(DECLARED_REGISTRY) | {prefix+'.'+child for prefix,children in DECLARED_CHILDREN.items() for child in children}
    require(all(key in nested_keys or not key.startswith(('javaLauncher.','modularity.','debugOptions.')) for key in properties), 'unknown nested descendant')
    budget = [DECLARED_MAX_NODES, MAX_JSON] if budget is None else budget
    def charge(depth):
        require(time.monotonic() <= deadline, 'declared time bound')
        budget[0] -= 1
        require(depth <= DECLARED_MAX_DEPTH and budget[0] >= 0, 'declared node/depth bound')
    def number(value, low=None, high=None):
        declared_string(value)
        require(re.fullmatch(r'0|-?[1-9][0-9]*', value) is not None, 'declared integer spelling')
        if low is not None:
            require(len(value) < 24 and low <= int(value) <= high, 'declared integer range')
    def bound(binding, identifier, path):
        require(type(binding) is dict and set(binding) == {'baseClass', 'classSha256', 'jarPath', 'jarSha256'}, 'implementation binding fields')
        base = DECLARED_REGISTRY[path]
        pin = DECLARED_CLASSES[base]
        expected = base + '_Decorated' if path in ('modularity', 'debugOptions') else base
        require(identifier in ({base, expected} if path in ('modularity', 'debugOptions') else {base}), 'implementation identifier')
        require(binding == {'baseClass': base, 'classSha256': pin['classSha256'],
                'jarPath': gradle_binding['root'] + '/' + pin['jar'], 'jarSha256': pin['jarSha256']}, 'implementation origin/pin')
    def metadata(bean, depth):
        require(type(bean) is dict and set(bean) == {'languageVersion', 'javaRuntimeVersion', 'jvmVersion', 'vendor',
            'installationPath', 'installationRealPath', 'currentJvm', 'fallback'}, 'metadata fields')
        for key in ('languageVersion', 'javaRuntimeVersion', 'jvmVersion', 'vendor', 'currentJvm', 'fallback'):
            visit(bean[key], depth + 1)
        require(bean['languageVersion'][0] == 'java-language', 'selected language tag')
        require(all(bean[k][0] == 'string' for k in ('javaRuntimeVersion', 'jvmVersion', 'vendor')), 'metadata String')
        require(all(bean[k][0] == 'boolean' for k in ('currentJvm', 'fallback')), 'metadata Boolean')
        for key in ('installationPath', 'installationRealPath'): declared_path(bean[key])
    def visit(value, depth, path=None):
        charge(depth)
        require(type(value) is list and value and type(value[0]) is str, 'declared tagged array')
        tag = value[0]
        arities = {'null': 1, 'string': 2, 'boolean': 2, 'char': 2, 'integer': 3, 'decimal': 3, 'ieee': 3,
                   'enum': 3, 'java-language': 2, 'list': 2, 'array': 3, 'set': 2, 'ordered-set': 3, 'map': 2,
                   'file': 2, 'path': 2, 'regular-file': 2, 'directory': 2, 'provider': 2, 'implementation': 4}
        require(tag in arities and len(value) == arities[tag], 'declared unknown tag/arity')
        if tag == 'null': return
        if tag == 'string': declared_string(value[1])
        elif tag == 'boolean': require(type(value[1]) is bool, 'declared Boolean')
        elif tag == 'char': require(type(value[1]) is str and re.fullmatch('[0-9a-f]{4}', value[1]), 'declared Character')
        elif tag == 'integer':
            limits = {'java.lang.Byte': (-128,127), 'java.lang.Short':(-32768,32767), 'java.lang.Integer':(-2**31,2**31-1),
                      'java.lang.Long':(-2**63,2**63-1), 'java.math.BigInteger':(None,None)}
            require(value[1] in limits, 'declared integer class'); number(value[2], *limits[value[1]])
        elif tag == 'decimal':
            number(value[1]); require(type(value[2]) is int and -2**31 <= value[2] < 2**31, 'declared decimal scale')
        elif tag == 'ieee':
            require(value[1] in ('java.lang.Float', 'java.lang.Double') and type(value[2]) is str and
                    re.fullmatch('[0-9a-f]{'+('8' if value[1] == 'java.lang.Float' else '16')+'}', value[2]), 'declared IEEE bits')
        elif tag == 'java-language': require(type(value[1]) is int and 0 < value[1] < 2**31, 'declared Java language')
        elif tag == 'enum':
            require(value[1] == 'org.gradle.api.tasks.PathSensitivity' and value[2] in ('ABSOLUTE','RELATIVE','NAME_ONLY','NONE'), 'unreviewed enum declaring class/member')
        elif tag in ('file', 'path', 'regular-file', 'directory'): declared_path(value[1])
        elif tag == 'provider':
            state = value[1]
            require(type(state) is list and state and (state == ['absent'] or len(state) == 2 and state[0] == 'present'), 'provider presence')
            if state[0] == 'present':
                require(state[1] != ['null'], 'Provider cannot be present with null getOrNull')
                visit(state[1], depth + 1)
        elif tag == 'map':
            pairs = value[1]; require(type(pairs) is list, 'declared map entries')
            previous = None
            for pair in pairs:
                charge(depth+1); require(type(pair) is list and len(pair) == 2, 'declared map pair')
                key = declared_string(pair[0]); require(previous is None or previous < key, 'declared map order/duplicate')
                previous = key; visit(pair[1], depth + 1)
        elif tag in ('list', 'array', 'set', 'ordered-set'):
            items = value[2] if tag == 'array' else value[1]
            require(type(items) is list, 'declared collection elements')
            if tag == 'array':
                declared_array_component(value[1])
            previous = None; canonical = []
            for item in items:
                visit(item, depth + 1)
                if tag == 'array': declared_array_member(value[1], item)
                if tag in ('set','ordered-set'):
                    key = declared_canonical(item, deadline, budget[1]); budget[1] -= len(key)
                    require(budget[1] >= 0 and (previous is None or previous < key), 'set order/collision/scratch')
                    previous = key; canonical.append(key)
            if tag == 'ordered-set':
                require(type(value[2]) is list and len(value[2]) == len(items), 'ordered-set encounter set')
                encounter = []
                for item in value[2]:
                    visit(item, depth + 1)
                    key = declared_canonical(item, deadline, budget[1])
                    budget[1] -= len(key)
                    require(budget[1] >= 0, 'ordered-set scratch bound')
                    encounter.append(key)
                require(sorted(encounter) == canonical, 'ordered-set encounter membership/collision')
        else:
            require(path in DECLARED_REGISTRY, 'unknown nested implementation')
            bound(value[2], value[1], path); bean = value[3]
            if path == 'javaLauncher':
                require(type(bean) is dict and set(bean) == {'executablePath','executableRealPath','metadata'}, 'launcher fields')
                declared_path(bean['executablePath']); declared_path(bean['executableRealPath']); metadata(bean['metadata'], depth+1)
            elif path == 'javaLauncher.metadata': metadata(bean, depth+1)
            else:
                require(type(bean) is dict and set(bean) == DECLARED_CHILDREN[path], 'nested semantic fields')
                for child, item in bean.items(): visit(item, depth + 1)
                if path == 'modularity': require(bean['inferModulePath'][0] == 'boolean', 'modularity Boolean')
                elif path == 'debugOptions':
                    require(all(bean[k][0] == 'boolean' for k in ('enabled','server','suspend')) and bean['host'][0] in ('null','string') and
                            bean['port'][:2] == ['integer','java.lang.Integer'], 'debug semantic types')
                else:
                    require(bean['languageVersion'][0] in ('null','java-language') and all(bean[k][0] == 'string' for k in ('vendor','implementation')), 'requested toolchain types')
    for key, value in properties.items(): declared_string(key); charge(0); visit(value, 0, key)
    for path, expected in DECLARED_CHILDREN.items():
        actual = {key[len(path)+1:].split('.')[0] for key in properties if key.startswith(path+'.')}
        require(path in properties and properties[path][0] == 'implementation' and actual == expected, 'nested child schema')
        if path != 'javaLauncher':
            for child in expected - {'taskInputs'}:
                require(properties[path+'.'+child] == properties[path][3][child], 'nested leaf consistency')
    require(properties['javaLauncher'][3]['metadata'] == properties['javaLauncher.metadata'][3], 'launcher metadata consistency')
    require(len(declared_canonical(properties, deadline)) * 2 <= MAX_JSON, 'declared plan/scratch bound')

class BindingBudget:
    """Shared JDK/distribution work; opaque Gradle getters remain outer-process bounded."""
    def __init__(self, seconds=120):
        require(type(seconds) in (int, float) and 0 < seconds <= 120, 'binding deadline allowance')
        self.deadline = time.monotonic() + seconds
        self.entries = MAX_INPUT_ENTRIES
        self.remaining = MAX_INPUT_BYTES
        self.wire_bytes = 0
    def check(self):
        require(time.monotonic() <= self.deadline, 'binding time bound')
    def entry(self):
        self.check(); self.entries -= 1
        require(self.entries >= 0, 'binding entry bound')
    def wire(self, *values):
        self.check()
        self.wire_bytes += 512 + 6 * sum(len(declared_string(value)) for value in values)
        require(self.wire_bytes * 2 <= MAX_JSON, 'binding wire/scratch bound')
    def file(self, path):
        self.entry(); h = hashlib.sha256()
        with regular(path) as (stream, info):
            require(info.st_size <= self.remaining, 'binding total byte bound')
            total = 0
            while True:
                self.check()
                block = stream.read(min(1024**2, info.st_size - total + 1))
                if not block: break
                total += len(block)
                require(total <= info.st_size and total <= self.remaining, 'binding file grew')
                h.update(block)
            require(total == info.st_size, 'binding file size changed')
        self.remaining -= total
        return {'type':'file', 'sha256':h.hexdigest(), 'bytes':total,
                'mode':stat.S_IMODE(info.st_mode), 'key':[info.st_dev,info.st_ino]}


def jdk_binding(root, budget=None):
    budget = BindingBudget() if budget is None else budget
    root = safe_path(pathlib.Path(declared_path(str(root))))
    require(root.resolve(strict=True) == root, 'JDK root must be canonical')
    entries = {}; edges = {}; files = {}; file_stats = {}; file_paths = {}; directory_paths = {}
    def ident(s): return (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    def resolve_link(path):
        """Inspect every edge before traversal, with a per-resolution hop/identity limit."""
        pending = list(path.relative_to(root).parts); current = root; seen = set(); hops = 0
        while pending:
            budget.check(); part = pending.pop(0)
            if part == '..':
                require(current != root, 'JDK symlink escape')
                current = current.parent
                continue
            if part == '.': continue
            current = current / part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode):
                hops += 1; require(hops <= 32 and current not in seen, 'JDK symlink cycle/hop bound')
                seen.add(current); text = os.readlink(current); declared_string(text)
                edge = pathlib.Path(os.path.normpath(str(current.parent / text)))
                require(edge.is_relative_to(root), 'JDK symlink escape')
                require(ident(info) == ident(current.lstat()) and os.readlink(current) == text, 'JDK link changed')
                old = edges.setdefault(str(current), (ident(info), text))
                require(old == (ident(info),text), 'JDK edge changed')
                raw = pathlib.PurePosixPath(text)
                if raw.is_absolute():
                    require(raw.is_relative_to(root), 'JDK absolute link escape')
                    pending = list(raw.relative_to(root).parts) + pending; current = root
                else:
                    pending = list(raw.parts) + pending; current = current.parent
            elif pending:
                require(stat.S_ISDIR(info.st_mode), 'JDK non-directory edge')
            else: require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'JDK special target')
        return current
    def visit(path):
        budget.entry(); name = str(path.relative_to(root)); declared_string(name); budget.wire(name)
        info = path.lstat()
        common = {'mode':stat.S_IMODE(info.st_mode),'key':[info.st_dev,info.st_ino]}
        if stat.S_ISDIR(info.st_mode):
            entries[name] = {'type':'directory', **common}
            directory_paths[str(path)] = ident(info)
            with os.scandir(path) as children:
                for child in children: visit(pathlib.Path(child.path))
            require(ident(info) == ident(path.lstat()), 'JDK directory changed')
        elif stat.S_ISREG(info.st_mode):
            key = (info.st_dev,info.st_ino)
            if key not in files:
                files[key] = budget.file(path); file_stats[key] = ident(info)
            require(file_stats[key] == ident(info), 'JDK hardlink identity changed')
            file_paths[str(path)] = file_stats[key]
            receipt = files[key]
            require(receipt['mode'] == common['mode'] and receipt['bytes'] == info.st_size and ident(info) == ident(path.lstat()), 'JDK alias changed')
            entries[name] = dict(receipt)
        elif stat.S_ISLNK(info.st_mode):
            text = os.readlink(path); edge = pathlib.Path(os.path.normpath(str(path.parent / text)))
            target = resolve_link(path)
            require(ident(info) == ident(path.lstat()) and text == os.readlink(path), 'JDK link changed')
            budget.wire(text,str(edge),str(target))
            entries[name] = {'type':'symlink', **common, 'text':text,'edge':str(edge),'target':str(target)}
        else: require(False, 'JDK special entry')
    visit(root)
    for name, identity in directory_paths.items():
        budget.check(); require(ident(pathlib.Path(name).lstat()) == identity, 'JDK directory changed after walk')
    for name, identity in file_paths.items():
        budget.check(); require(ident(pathlib.Path(name).lstat()) == identity, 'JDK file changed after walk')
    for name, (identity,text) in edges.items():
        budget.check(); p = pathlib.Path(name)
        require(ident(p.lstat()) == identity and os.readlink(p) == text, 'JDK edge changed after walk')
    for value in entries.values():
        if value['type'] == 'symlink':
            relative = str(pathlib.Path(value['target']).relative_to(root))
            require(relative in entries and entries[relative]['type'] in ('file','directory'), 'JDK target not inventoried')
    result = {'root':str(root),'entries':dict(sorted(entries.items(),key=lambda item:item[0].encode()))}
    require(len(declared_canonical(result, budget.deadline)) * 2 <= MAX_JSON, 'JDK plan byte bound')
    return result


def gradle_binding(root, budget=None):
    budget = BindingBudget() if budget is None else budget
    root = safe_path(pathlib.Path(declared_path(str(root))))
    require(root.resolve(strict=True) == root, 'Gradle root must be canonical')
    names = set()
    def walk(directory):
        budget.entry()
        with os.scandir(directory) as children:
            for child in children:
                budget.check(); path = pathlib.Path(child.path); info = path.lstat()
                require(not stat.S_ISLNK(info.st_mode), 'Gradle distribution symlink')
                if stat.S_ISDIR(info.st_mode): walk(path)
                elif path.suffix == '.jar':
                    require(stat.S_ISREG(info.st_mode), 'Gradle nonregular JAR')
                    names.add(str(path.relative_to(root)))
                    require(len(names) <= len(GRADLE_JARS), 'extra Gradle JAR')
    walk(root / 'lib')
    require(names == set(GRADLE_JARS), 'Gradle distribution JAR set')
    entries = {}
    for name in sorted(names):
        budget.wire(name)
        receipt = budget.file(root/name)
        require(receipt['sha256'] == GRADLE_JARS[name], 'Gradle publisher JAR bytes changed')
        entries[name] = receipt
    budget.check()
    receipt_bytes = entries['lib/gradle-base-services-9.6.1.jar']['bytes']
    require(receipt_bytes <= budget.remaining, 'Gradle receipt read budget')
    budget.remaining -= receipt_bytes
    receipt_name = 'org/gradle/build-receipt.properties'
    with regular(root/'lib/gradle-base-services-9.6.1.jar') as (stream,_), zipfile.ZipFile(stream) as archive:
        info = archive.getinfo(receipt_name); require(info.file_size <= 65536, 'Gradle receipt bound')
        receipt = archive.read(info)
    expected = (b'baseVersion=9.6.1\nbuildTimestamp=20260626142550+0000\n'
        b'buildTimestampIso=2026-06-26 14\\:25\\:50 UTC\ncommitId=309d128bd9fe8c0b71311878fc660b9cbaa07c51\n'
        b'isSnapshot=false\nscriptTemplateCommitId=3d91ce3b8caaf77ad09f381f43615b715b53f72c\nversionNumber=9.6.1\n')
    require(receipt == expected, 'Gradle build receipt')
    return {'root':str(root),'version':GRADLE_VERSION,'commit':GRADLE_COMMIT,'distributionSha256':GRADLE_ZIP_SHA256,
            'buildReceiptSha256':hashlib.sha256(receipt).hexdigest(),'entries':entries}


def validate_binding_receipts(jdk, gradle, deadline=None):
    deadline = time.monotonic() + 120 if deadline is None else deadline
    require(type(gradle) is dict and set(gradle) == {'root','version','commit','distributionSha256','buildReceiptSha256','entries'}, 'Gradle binding fields')
    declared_path(gradle['root'])
    require(gradle['buildReceiptSha256'] == 'f1ced844391f571370fe8d1606f665a6cd568b9a6e5793f954aabab7173f299a', 'Gradle build receipt hash')
    require(gradle['version'] == GRADLE_VERSION and gradle['commit'] == GRADLE_COMMIT and gradle['distributionSha256'] == GRADLE_ZIP_SHA256,
            'Gradle distribution identity')
    require(type(gradle['entries']) is dict and set(gradle['entries']) == set(GRADLE_JARS), 'Gradle JAR binding set')
    def receipt(value):
        require(time.monotonic() <= deadline, 'binding schema time bound')
        require(type(value) is dict and value.get('type') in ('directory','file','symlink'), 'binding entry type')
        fields = {'type','mode','key'} | ({'sha256','bytes'} if value['type'] == 'file' else {'text','edge','target'} if value['type'] == 'symlink' else set())
        require(set(value) == fields, 'binding entry fields')
        require(type(value['mode']) is int and 0 <= value['mode'] <= 0o7777, 'binding mode')
        require(type(value['key']) is list and len(value['key']) == 2 and all(type(n) is int and 0 <= n < 2**64 for n in value['key']), 'binding dev/inode')
        if value['type'] == 'file':
            require(type(value['bytes']) is int and 0 <= value['bytes'] <= MAX_FILE and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']), 'binding file size/hash')
    total = 0
    for name,value in gradle['entries'].items():
        receipt(value);require(value['type'] == 'file' and value['sha256'] == GRADLE_JARS[name], 'Gradle JAR pin');total += value['bytes']
    require(type(jdk) is dict and set(jdk) == {'root','entries'}, 'JDK binding fields'); root = pathlib.PurePosixPath(declared_path(jdk['root']))
    entries = jdk['entries'];require(type(entries) is dict and '.' in entries and entries['.']['type'] == 'directory', 'JDK root entry')
    require(len(entries)+len(gradle['entries']) <= MAX_INPUT_ENTRIES, 'binding entry bound')
    keys = {}
    for name,value in entries.items():
        declared_string(name);path = pathlib.PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts and '\x00' not in name and str(path) == name, 'JDK relative name')
        receipt(value)
        if name != '.': require(str(path.parent) in entries and entries[str(path.parent)]['type'] == 'directory', 'JDK missing parent')
        if value['type'] == 'file':
            key = tuple(value['key'])
            require(key not in keys or keys[key] == value, 'JDK hardlink receipt disagreement')
            if key not in keys: total += value['bytes']; keys[key] = value
        if value['type'] == 'symlink':
            text = value['text']; declared_string(text)
            edge = pathlib.PurePosixPath(declared_path(value['edge']));target = pathlib.PurePosixPath(declared_path(value['target']))
            require(edge.is_relative_to(root) and target.is_relative_to(root) and str(target.relative_to(root)) in entries, 'JDK link escape/missing target')
            require(str(edge) == os.path.normpath(str(root/path.parent/text)), 'JDK link lexical edge')
            current = root/path;seen = set();hops=0
            pending = list(current.relative_to(root).parts);current=root
            while pending:
                part = pending.pop(0)
                if part == '..':
                    require(current != root, 'JDK link escape')
                    current = current.parent
                    continue
                if part == '.': continue
                current /= part;rel=str(current.relative_to(root));require(rel in entries, 'JDK unresolved link')
                item=entries[rel]
                if item['type']=='symlink':
                    hops+=1;require(hops<=32 and rel not in seen,'JDK link cycle/hops');seen.add(rel)
                    edge=pathlib.PurePosixPath(declared_path(item['edge']));require(edge.is_relative_to(root),'JDK edge escape')
                    raw=pathlib.PurePosixPath(item['text'])
                    if raw.is_absolute():
                        require(raw.is_relative_to(root),'JDK absolute link escape')
                        pending=list(raw.relative_to(root).parts)+pending;current=root
                    else:
                        pending=list(raw.parts)+pending;current=current.parent
                elif pending:require(item['type']=='directory','JDK nondirectory edge')
            require(str(current)==value['target'] and entries[str(current.relative_to(root))]['type'] in ('file','directory'), 'JDK resolved target differs')
    require(total <= MAX_INPUT_BYTES, 'binding total byte bound')


def validate_semantic_plan(plan, tools=None, deadline=None):
    deadline = time.monotonic() + 120 if deadline is None else deadline
    require(type(plan) is dict and set(plan) == {'acp','runRoot','repoRoot','installInputs','producers','frontendNodeHome',
            'mappingRoots','originalJar','declaredInputsFormat','jdkBinding','gradleBinding'}, 'semantic plan fields')
    require(plan['declaredInputsFormat'] == DECLARED_FORMAT, 'old/unknown declared format')
    for name in ('runRoot','repoRoot','originalJar'): declared_path(plan[name])
    acp = plan['acp']
    require(type(acp) is dict and set(acp) == {'publicationScope','bindingEvidence','compiler','source','recipe','publication','output'}, 'semantic ACP fields')
    require(acp['publicationScope'] == 'cooperative-build-producer-v1' and acp['bindingEvidence'] == 'stable-namespace-path-observations-v1', 'semantic ACP scope')
    for name in ('compiler','source','recipe','publication','output'): declared_path(acp[name])
    require(type(plan['installInputs']) is list and len(plan['installInputs']) <= MAX_INPUT_ENTRIES and
            plan['installInputs'] == sorted(set(plan['installInputs'])), 'semantic install input set')
    for path in plan['installInputs']: declared_path(path)
    require(type(plan['mappingRoots']) is dict and set(plan['mappingRoots']) == {'stageKotlinBootRuntime','startScripts',
        'generateKotlinBootClasspathReference','generateGccBundledGhidraReference','generateLlvmHostedWorkerClasspathReference'}, 'semantic mapping fields')
    for path in plan['mappingRoots'].values(): declared_path(path)
    declared_string(plan['frontendNodeHome']); declared_string(plan['acp']['compiler'])
    validate_binding_receipts(plan['jdkBinding'],plan['gradleBinding'],deadline)
    selected = plan['jdkBinding']['entries']
    require(all(name in selected and selected[name]['type'] == 'file' for name in ('bin/java','release')) and
            selected['bin/java']['mode'] & 0o111 and selected['release']['bytes'] > 0, 'selected executable/release binding')
    require(type(plan['producers']) is dict and set(plan['producers']) == set(PRODUCERS), 'semantic producers')
    budget = [DECLARED_MAX_NODES, MAX_JSON]
    for producer in plan['producers'].values():
        require(type(producer) is dict and set(producer) == {'inputs','outputs','classpath','orderedClasspath','mainClass','properties'}, 'semantic producer fields')
        for name in ('inputs','outputs','classpath','orderedClasspath'):
            require(type(producer[name]) is list and len(producer[name]) <= MAX_INPUT_ENTRIES, 'semantic file vector')
            for path in producer[name]: declared_path(path)
            if name != 'orderedClasspath': require(producer[name] == sorted(set(producer[name])), 'semantic file membership order/duplicate')
        require(sorted(set(producer['orderedClasspath'])) == producer['classpath'], 'classpath membership/order vector')
        declared_string(producer['mainClass'])
        props = producer['properties'];validate_declared_properties(props,plan['gradleBinding'],budget,deadline)
        require(props['compiler'][0] == 'string' and props['hostArchitecture'][0] == 'string', 'compiler/architecture must be String')
        require(props['mainClass'] == ['string',producer['mainClass']], 'main class duplicate differs')
        require(all(props[k][0] == 'boolean' for k in ('debug','enableAssertions','ignoreExitValue')), 'JavaExec boolean fields')
        require(all(props[k][0] in ('null','string') for k in ('mainModule','minHeapSize','maxHeapSize','defaultCharacterEncoding')), 'JavaExec nullable String fields')
        require(props['args'][0] == props['jvmArgs'][0] == 'list' and props['systemProperties'][0] == 'map', 'JavaExec collection fields')
        launcher = props['javaLauncher'][3];meta=launcher['metadata'];root=plan['jdkBinding']['root']
        require(meta['languageVersion'] == ['java-language',21] and meta['installationRealPath'] == root and
                launcher['executableRealPath'] == root+'/bin/java', 'selected qualified Java21 launcher')
        if tools is not None:
            require(root == tools['java']['home'] and launcher['executableRealPath'] == tools['java']['path'] and
                    root+'/release' == tools['javaRelease']['path'], 'selected launcher/tools mismatch')
    require(len(declared_canonical(plan, deadline))*2 <= MAX_JSON, 'semantic plan/canonical scratch bound')


def safe_path(path, base=None):
    path = pathlib.Path(path)
    require(path.is_absolute() and ".." not in path.parts, "nonabsolute/escaped path")
    if base is not None:
        require(path.is_relative_to(base), "path escaped expected root")
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), f"symlink path: {parent}")
    return path


@contextmanager
def regular(path, limit=MAX_FILE, *, dir_fd=None):
    path = safe_path(path)
    fd = os.open(path if dir_fd is None else path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), f"nonregular file: {path}")
        require(before.st_size <= limit, f"file exceeds bound: {path}")
        yield stream, before
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat()) == identity(os.stat(path.name, dir_fd=dir_fd, follow_symlinks=False) if dir_fd is not None else path.lstat()),
                f"file changed during read: {path}")


def file_receipt(path, budget=None, copy_to=None, *, dir_fd=None):
    h = hashlib.sha256()
    with regular(path, dir_fd=dir_fd) as (stream, info):
        require(budget is None or info.st_size <= budget[0], "input byte bound exceeded")
        sink = None
        try:
            if copy_to is not None:
                safe_path(copy_to)
                sink = copy_to.open("xb")
            total = 0
            while block := stream.read(min(1024**2, MAX_FILE - total + 1)):
                total += len(block)
                require(total <= MAX_FILE, "input grew beyond bound")
                h.update(block)
                if sink is not None:
                    sink.write(block)
            require(total == info.st_size, "input size changed")
        finally:
            if sink is not None:
                sink.close()
        if budget is not None:
            budget[0] -= total
    return {"type": "file", "sha256": h.hexdigest(), "bytes": total,
            "mode": stat.S_IMODE(info.st_mode), "key": [info.st_dev, info.st_ino]}


def read_json(path):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    with regular(path, MAX_JSON) as (stream, _):
        data = stream.read(MAX_JSON + 1)
        require(len(data) <= MAX_JSON, "JSON exceeds bound")
        return json.loads(data, object_pairs_hook=pairs)


def write_json(path, value, *, immutable=False):
    safe_path(path)
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    require(len(data) <= MAX_JSON, "JSON exceeds bound")
    temporary = path.with_name(path.name + ".partial")
    with temporary.open("xb") as sink:
        sink.write(data)
    if immutable:
        # link + unlink gives atomic create-without-replacement.
        try:
            os.link(temporary, path)
        finally:
            temporary.unlink()
    else:
        temporary.replace(path)


def inventory(roots, *, max_entries=None, max_bytes=None):
    """Exact directories AND files; exceptions retain bounded partial evidence."""
    entries = {}
    remaining = [MAX_INPUT_BYTES if max_bytes is None else max_bytes]
    cap = MAX_INPUT_ENTRIES if max_entries is None else max_entries
    def visit(path):
        path = safe_path(path)
        name = str(path)
        if name in entries:
            return
        require(len(entries) < cap, "inventory entry bound exceeded")
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            entries[name] = {"type": "directory", "mode": stat.S_IMODE(info.st_mode),
                             "key": [info.st_dev, info.st_ino]}
            # Never materialize an unbounded directory listing, including duplicates.
            with os.scandir(path) as children:
                for child in children:
                    visit(pathlib.Path(child.path))
        else:
            entries[name] = file_receipt(path, remaining)
    try:
        require(len(roots) <= cap, "inventory root bound exceeded")
        for root in roots:
            visit(pathlib.Path(root))
        value = {"status": "passed", "entries": dict(sorted(entries.items()))}
        require(len(json.dumps(value).encode()) <= MAX_JSON, "inventory JSON bound exceeded")
        return value
    except Exception as failure:
        # No partial inventory can be used as a passing comparison.
        return {"status": "failed", "error": repr(failure)[:2048],
                "entries": dict(sorted(entries.items())) if len(json.dumps(entries).encode()) < MAX_JSON - 4096 else {},
                "observedEntries": len(entries)}


def difference(before, after):
    old, new = before.get("entries", {}), after.get("entries", {})
    return {"status": "passed" if before.get("status") == after.get("status") == "passed" else "failed",
            "added": sorted(new.keys() - old.keys()), "removed": sorted(old.keys() - new.keys()),
            "changed": {name: {key: {"before": old[name].get(key), "after": new[name].get(key)}
                               for key in old[name].keys() | new[name].keys() if old[name].get(key) != new[name].get(key)}
                        for name in sorted(old.keys() & new.keys()) if old[name] != new[name]}}


EMPTY_DIFF = {"status": "passed", "added": [], "removed": [], "changed": {}}


def protected(root, run):
    try:
        paths = []
        for subdir in ("lib", "bin"):
            directory = safe_path(root / subdir)
            with os.scandir(directory) as items:
                for index, item in enumerate(items):
                    require(index < MAX_PROTECTED_ENTRIES, "protected directory entry bound exceeded")
                    name = item.name
                    require(not (name.startswith(".install-") and name.endswith(".tmp")), "publisher temporary file remains")
                    if (subdir == "lib" and (name.endswith(".jar") or name.endswith("reference-v1.json"))) or (
                            subdir == "bin" and name in ("llm_bin_patch", "llm_bin_patch.bat")):
                        paths.append(str(pathlib.Path(item.path)))
        names = {pathlib.Path(p).name for p in paths}
        require({n for n in names if n.endswith("reference-v1.json")} == set(REFERENCES.values()), "protected reference set differs")
        require({"llm_bin_patch", "llm_bin_patch.bat"} <= names and any(n.endswith(".jar") for n in names), "protected closure incomplete")
        result = inventory(paths, max_entries=MAX_PROTECTED_ENTRIES, max_bytes=MAX_PROTECTED_BYTES)
        result["entries"] = {str(pathlib.Path(p).relative_to(run)): value for p, value in result["entries"].items()}
        return result
    except Exception as failure:
        return {"status": "failed", "error": repr(failure)[:2048], "entries": {}}


def build_controls(repo):
    return {name: file_receipt(repo / name)["sha256"] if os.path.lexists(repo / name) else None for name in BUILD_CONTROLS}


def plan_roots(plan):
    require(set(plan["producers"]) == set(PRODUCERS), "omitted/extra producer")
    roots = set(plan["installInputs"])
    for producer in plan["producers"].values():
        for group in ("inputs", "outputs", "classpath"):
            require(producer[group], f"missing producer {group}")
            roots.update(producer[group])
    roots.update(plan["mappingRoots"].values())
    roots.add(plan["originalJar"])
    return sorted(roots)


def mapping(plan, entries, run):
    required = {"stageKotlinBootRuntime", "startScripts", *REFERENCES}
    require(set(plan["mappingRoots"]) == required, "protected mapping task set differs")
    result = {}
    for task, root in plan["mappingRoots"].items():
        root = pathlib.Path(root)
        for name, receipt in entries.items():
            source = pathlib.Path(name)
            if receipt["type"] != "file" or not (source == root or source.is_relative_to(root)):
                continue
            if task == "stageKotlinBootRuntime":
                require(source.parent == root and source.suffix == ".jar", "staged runtime contains non-JAR/nested input")
                logical = "lib/" + source.name
            elif task == "startScripts":
                require(source.parent == root and source.name in ("llm_bin_patch", "llm_bin_patch.bat"), "unexpected launcher input")
                logical = "bin/" + source.name
            else:
                require(source == root and source.name == REFERENCES[task], "reference output differs")
                logical = "lib/" + source.name
            require(logical not in result, "duplicate protected mapping")
            result[logical] = {"source": name, "destination": str(run / "root-build/install/llm_bin_patch" / logical),
                               "requiredMode": 0o755 if logical == "bin/llm_bin_patch" else 0o644, **receipt}
    require({"bin/llm_bin_patch", "bin/llm_bin_patch.bat", *("lib/" + n for n in REFERENCES.values())} < result.keys(),
            "protected mapping incomplete")
    original = entries[plan["originalJar"]]
    staged = result["lib/" + pathlib.Path(plan["originalJar"]).name]
    require(all(original[k] == staged[k] for k in ("sha256", "bytes")), "original/staged app differs")
    return result


def small_bytes(path, limit=65536):
    with regular(pathlib.Path(path), limit) as (stream, _):
        data = stream.read(limit + 1)
        require(len(data) <= limit, "provenance input exceeds bound")
        return data


def validate_tools(tools, entries, read):
    require(set(tools) == {"java", "javaRelease", "node"}, "build tool set differs")
    for name in ("java", "node"):
        tool = tools[name]
        home = pathlib.Path(tool["home"])
        path = pathlib.Path(tool["path"])
        require(home.is_absolute() and '..' not in home.parts and str(home) == tool["home"] and
                path == home / "bin" / name and entries[str(path)]["type"] == "file" and
                entries[str(path)]["mode"] & 0o111, "build tool executable/home differs")
    release = tools["javaRelease"]["path"]
    require(release == str(pathlib.Path(tools["java"]["home"]) / "release"), "Java release/home differs")
    versions = re.findall(r'^JAVA_VERSION="([^"\n]+)"$', read(release).decode(), re.MULTILINE)
    require(len(versions) == 1 and re.fullmatch(r'21(?:[.+\-][^\s"]+)?', versions[0]),
            "retained JDK release is not qualified Java 21")


def validate_provenance(plan, entries, prov, read):
    """Validate actual producer schemas/tuples using original or retained bytes.

    The receipts bind compilation inputs and outputs consistently. They do not
    authenticate the compiler's implicit toolchain or historical execution.
    """
    repo = pathlib.Path(plan["repoRoot"])
    run = pathlib.Path(plan["runRoot"])
    def record(path):
        # Use the same duplicate-key rejection as retained JSON reads.
        def pairs(items):
            value = {}
            for k, v in items:
                require(k not in value, "duplicate provenance key")
                value[k] = v
            return value
        return json.loads(read(str(path)), object_pairs_hook=pairs)
    def tuple_for(path):
        item = entries[str(path)]
        require(item["type"] == "file", "provenance tuple is not a file")
        return {"fileName": path.name, "bytes": item["bytes"], "sha256": item["sha256"]}
    def successful(result, analysis):
        require(set(result) == ({"exitCode", "signal", "stdoutBytes", "stdoutSha256", "stderrBytes", "stderrSha256"}
                               if analysis else {"exitCode", "stdout", "stderr"}), "compiler result schema differs")
        require(type(result["exitCode"]) is int and result["exitCode"] == 0, "compiler command failed")
        if analysis:
            require(result["signal"] is None, "compiler command signaled")
        for channel in ("stdout", "stderr"):
            value = {"bytes": result[channel + "Bytes"], "sha256": result[channel + "Sha256"]} if analysis else result[channel]
            require(set(value) == ({"bytes", "sha256"} if analysis else {"fileName", "bytes", "sha256"}),
                    "compiler output schema differs")
            require(type(value["bytes"]) is int and 0 <= value["bytes"] <= 65536 and
                    re.fullmatch('[0-9a-f]{64}', value["sha256"]), "compiler output receipt differs")
            require(value["bytes"] != 0 or value["sha256"] == hashlib.sha256(b"").hexdigest(),
                    "empty compiler output has a foreign hash")
            if not analysis:
                require(value["fileName"] == channel, "compiler output name differs")
    expected_resources = {}
    for producer, (directory, _) in HELPER_OUTPUTS.items():
        analysis = directory == "analysis"
        root = run / "root-build/native" / directory
        binary = "decomp-analysis-io-helper" if analysis else "decomp-llvm-behavior-helper"
        source_name = "decomp_analysis_io_helper.c" if analysis else "decomp_llvm_behavior_helper.c"
        source = repo / "src/main/c" / source_name
        copied = root / ("analysis-native-io/source.c" if analysis else source_name)
        helper = root / binary
        checksum = root / (binary + ".sha256")
        build = root / ("analysis-native-io/build-v1.json" if analysis else "decomp-llvm-behavior-helper-build-v2.json")
        reference = build if analysis else root / "llvm-behavior-native-helper-deployment-reference-v1.json"
        require(any(source == pathlib.Path(p) or source.is_relative_to(p) for p in plan["producers"][producer]["inputs"]),
                "helper source is not a declared producer input")
        require(all(entries[str(source)][k] == entries[str(copied)][k] for k in ("sha256", "bytes")),
                "helper source copy differs from compilation input")
        require(entries[str(helper)]["mode"] == 0o755 and
                read(str(checksum)) == (entries[str(helper)]["sha256"] + "  " + binary + "\n").encode(),
                "helper output/checksum differs")
        item = prov["producers"][producer]
        data = record(reference)
        require(item["path"] == str(reference) and item["record"] == data, "producer provenance path/record differs")
        common = {"schemaVersion", "compiler", "compilation"}
        expected_keys = common | ({"kind", "binaryName", "architecture", "sourceSha256", "buildPolicySha256", "helperSha256", "helperBytes"}
            if analysis else {"provider", "protocol", "provenanceScope", "compilerToolchainClosureAuthenticated",
                              "source", "helper", "checksum", "buildRecord", "claims", "closureSha256"})
        require(set(data) == expected_keys and type(data["schemaVersion"]) is int, "producer provenance schema fields differ")
        compiler = data["compiler"]
        require(set(compiler) == {"path", "bytes", "sha256", "version", "versionCommand", "result"}, "compiler schema differs")
        require(compiler["versionCommand"] == [compiler["path"], "--version"] and
                isinstance(compiler["version"], str) and 0 < len(compiler["version"].encode()) <= 4096 and
                all(ord(c) >= 32 and ord(c) != 127 for c in compiler["version"]), "compiler identity differs")
        successful(compiler["result"], analysis)
        version_stdout_bytes = (compiler["result"]["stdoutBytes"] if analysis else
                                compiler["result"]["stdout"]["bytes"])
        require(version_stdout_bytes >= len(compiler["version"].encode()),
                "compiler version exceeds observed stdout bytes")
        compilation = data["compilation"]
        require(set(compilation) == {"arguments", "environment", "workingDirectory", "result"} |
                ({"timeoutMillis", "maximumStdoutBytes", "maximumStderrBytes"} if analysis else set()),
                "compilation schema differs")
        successful(compilation["result"], analysis)
        flags = ["-std=c11", "-O2", "-static"] + (["-no-pie"] if analysis else []) + [
            "-Wall", "-Wextra", "-Werror", "-Wformat=2", "-Wl,--build-id=none"]
        args = compilation["arguments"]
        require(len(args) == len(flags) + 4 and args[:len(flags)+1] == [compiler["path"], *flags] and args[-2] == "-o",
                "fixed compilation arguments differ")
        staged_source, staged_output = pathlib.Path(args[-3]), pathlib.Path(args[-1])
        scratch = staged_source.parent
        require(staged_source.name == source_name and staged_output == scratch / binary and
                scratch.parent == root and scratch.name.startswith(".analysis-io-build-" if analysis else ".native-helper-build-"),
                "compilation source/output relationship differs")
        require(compilation["workingDirectory"] == "/" and compilation["environment"] == {
            "HOME": str(scratch / "home"), "TMPDIR": str(scratch / "tmp"), "LANG": "C", "LC_ALL": "C",
            "PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": "1779182222", "TZ": "UTC"}, "compilation environment differs")
        if analysis:
            policy = root / "analysis-native-io/build-policy.txt"
            require(data["schemaVersion"] == 1 and data["kind"] == "analysis-native-io-helper-build-v1" and
                    data["binaryName"] == binary and data["architecture"] == "linux-x86-64" and
                    data["sourceSha256"] == entries[str(source)]["sha256"] and
                    data["buildPolicySha256"] == entries[str(policy)]["sha256"] and
                    data["helperSha256"] == entries[str(helper)]["sha256"] and data["helperBytes"] == entries[str(helper)]["bytes"],
                    "analysis source/policy/helper tuple differs")
            require([compilation[k] for k in ("timeoutMillis", "maximumStdoutBytes", "maximumStderrBytes")] ==
                    [30000, 65536, 65536], "analysis compilation bounds differ")
            props = {}
            for line in read(str(root / "analysis-native-io/decomp-analysis-io-helper-v1.properties")).decode().splitlines():
                key, value = line.split('=', 1)
                require(key not in props, "duplicate analysis property")
                props[key] = value
            expected = {k: str(data[k]) for k in ("schemaVersion", "sourceSha256", "buildPolicySha256", "helperSha256",
                        "helperBytes", "architecture", "binaryName")}
            expected.update(sourcePath="analysis-native-io/source.c", buildRecordPath="analysis-native-io/build-v1.json",
                            buildRecordBytes=str(entries[str(build)]["bytes"]), buildRecordSha256=entries[str(build)]["sha256"])
            require(props == expected, "analysis properties/build-record tuple differs")
            for name in ("source.c", "build-policy.txt", "build-v1.json", "decomp-analysis-io-helper-v1.properties"):
                expected_resources["analysis-native-io/" + name] = str(root / "analysis-native-io" / name)
        else:
            require(data["schemaVersion"] == 1 and data["provider"] == "llvm-behavior-native-helper-deployment-reference-v1" and
                    data["protocol"] == "decomp-llvm-behavior-helper-v2" and
                    data["provenanceScope"] == "reviewed-source-compiler-executable-and-fixed-compilation" and
                    data["compilerToolchainClosureAuthenticated"] is False, "LLVM provenance schema differs")
            for field, path in (("source", copied), ("helper", helper), ("checksum", checksum), ("buildRecord", build)):
                require(data[field] == tuple_for(path), "LLVM " + field + " tuple differs")
            build_data = record(build)
            require(build_data == {"schemaVersion": 2, "kind": "llvm-behavior-native-helper-build-record",
                    "compiler": {"executable": compiler["path"], "version": compiler["version"]},
                    "argumentTemplate": [*flags, "${SOURCE}", "-o", "${OUTPUT}"],
                    "source": tuple_for(copied), "output": tuple_for(helper)}, "LLVM build-record schema/tuple differs")
            require(data["claims"] == dict.fromkeys(("runtimeProfilePinned", "referencePinned", "startAuthorized",
                    "containmentAuthority", "scoringAuthority", "releaseEligible"), False), "LLVM unsupported authority claim")
            unsigned = {k: v for k, v in data.items() if k != "closureSha256"}
            require(data["closureSha256"] == hashlib.sha256((json.dumps(unsigned, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode()).hexdigest(), "LLVM closure checksum differs")
            for path in (copied, build, reference):
                expected_resources["oracle/native-helper/" + path.name] = str(path)
    require(prov["embeddedResources"] == expected_resources, "embedded resource source paths differ")


def provenance(plan, entries):
    """Retain original compiler/version receipts and embedded resource binding."""
    validate_output_sets(plan, entries)
    provenance_paths = {}
    resources = {}
    for name in entries:
        path = pathlib.Path(name)
        if "/native/analysis/analysis-native-io/" in name and entries[name]["type"] == "file":
            resources["analysis-native-io/" + path.name] = name
            if path.name == "build-v1.json":
                provenance_paths[PRODUCERS[0]] = name
        elif "/native/behavior/" in name and path.name in (
                "decomp_llvm_behavior_helper.c", "decomp-llvm-behavior-helper-build-v2.json",
                "llvm-behavior-native-helper-deployment-reference-v1.json"):
            resources["oracle/native-helper/" + path.name] = name
            if path.name == "llvm-behavior-native-helper-deployment-reference-v1.json":
                provenance_paths[PRODUCERS[1]] = name
    require(set(provenance_paths) == set(PRODUCERS) and set(resources) == EMBEDDED_RESOURCES, "helper provenance/resource set incomplete")
    receipts = {}
    for producer, path in provenance_paths.items():
        data = read_json(pathlib.Path(path))
        compiler = data["compiler"]
        actual = file_receipt(pathlib.Path(compiler["path"]))
        require(all(actual[k] == compiler[k] for k in ("bytes", "sha256")) and actual["mode"] & 0o111,
                "compiler differs from original producer receipt")
        require(compiler["version"] and compiler["versionCommand"] == [compiler["path"], "--version"] and
                compiler["result"]["exitCode"] == 0 and data["compilation"]["result"]["exitCode"] == 0,
                "compiler/version/compilation receipt incomplete")
        receipts[producer] = {"path": path, "record": data, "compilerFile": actual}
    with regular(pathlib.Path(plan["originalJar"])) as (stream, _):
        with zipfile.ZipFile(stream) as archive:
            require(len(archive.infolist()) <= MAX_INPUT_ENTRIES, "app archive entry bound exceeded")
            for resource, path in resources.items():
                matches = [item for item in archive.infolist() if item.filename == resource]
                require(len(matches) == 1 and matches[0].file_size <= 65536, "embedded helper resource missing/duplicate/oversize")
                with archive.open(matches[0]) as member:
                    data = member.read(65537)
                require(len(data) <= 65536 and hashlib.sha256(data).hexdigest() == entries[path]["sha256"], "embedded helper differs")
    result = {"producers": receipts, "embeddedResources": resources}
    validate_provenance(plan, entries, result, small_bytes)
    return result


def validate_output_sets(plan, entries):
    for producer, (directory, expected) in HELPER_OUTPUTS.items():
        root = pathlib.Path(plan["runRoot"]) / "root-build/native" / directory
        outputs = plan["producers"][producer]["outputs"]
        require(outputs and all(pathlib.Path(p) == root or pathlib.Path(p).is_relative_to(root) for p in outputs),
                "producer output escaped fresh root")
        actual = {str(pathlib.Path(p).relative_to(root)) for p, value in entries.items()
                  if value["type"] == "file" and pathlib.Path(p).is_relative_to(root)}
        require(actual == expected, "producer output set missing/extra member")
        require(all(any(pathlib.Path(root / name) == pathlib.Path(p) or pathlib.Path(root / name).is_relative_to(p)
                        for p in outputs) for name in actual), "producer output is undeclared")


ACP_SCOPE = 'cooperative-build-producer-v1'
ACP_BINDING = 'stable-namespace-path-observations-v1'
ACP_FLAGS = ['-std=c11', '-O2', '-static', '-Wall', '-Wextra', '-Werror', '-Wl,--build-id=none']
ACP_SOURCE = 'src/main/c/decomp_acp_gate_helper.c'
ACP_PUBLICATION = 'scripts/atomic-install-acp-publication.groovy'


def validate_acp(event, plan, entries, command=None):
    """Fresh compiler execution is mandatory, independent of claimed retain outcome."""
    config = plan['acp']
    repo, run = pathlib.Path(plan['repoRoot']), pathlib.Path(plan['runRoot'])
    require(set(config) == {'compiler', 'source', 'recipe', 'publication', 'output', 'publicationScope', 'bindingEvidence'}, 'ACP plan schema differs')
    require(config['publicationScope'] == ACP_SCOPE and config['bindingEvidence'] == ACP_BINDING, 'ACP plan scope/binding differs')
    for key, relative in (('source', ACP_SOURCE), ('recipe', 'build.gradle.kts'), ('publication', ACP_PUBLICATION)):
        require(config[key] == str(repo / relative), 'ACP source/recipe path differs')
    require(config['output'] == str(run / 'root-build/native/acp/decomp-acp-gate-helper'), 'ACP final path differs')
    tasks = [t for t in event['tasks'] if t['path'] == ':buildAcpGateHelper']
    require(len(tasks) == 1 and tasks[0]['enabled'] is True and tasks[0]['executed'] is True and
            all(tasks[0][k] is False for k in ('skipped', 'upToDate', 'noSource', 'failure')), 'ACP fresh task missing/skipped')
    value = event['acp']
    require(set(value) == {'schemaVersion', 'publicationScope', 'bindingEvidence', 'commandId', 'runRoot', 'initSha256', 'startedAtUnixNs',
        'compileStartedAtUnixNs', 'compileFinishedAtUnixNs', 'finishedAtUnixNs', 'cleanupFinishedAtUnixNs',
        'compiler', 'source', 'recipe', 'publication', 'output', 'flags', 'arguments', 'exitCode', 'cleanup',
        'candidatePath', 'candidate', 'previous', 'final', 'outcome', 'candidateValidationExitCode', 'finalValidationExitCode'}, 'ACP receipt fields differ')
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 2 and type(value['commandId']) is int and value['commandId'] == event['commandId'] in (1, 2) and
            value['runRoot'] == event['runRoot'] == str(run), 'ACP receipt command role differs')
    require(value['publicationScope'] == ACP_SCOPE and value['bindingEvidence'] == ACP_BINDING, 'ACP receipt scope/binding differs')
    require(type(value['exitCode']) is int and value['exitCode'] == 0 and value['cleanup'] is True,
            'ACP fresh compiler/cleanup failed')
    require(value['candidateValidationExitCode'] == value['finalValidationExitCode'] == 120, 'ACP static/protocol validation differs')
    require(value['flags'] == ACP_FLAGS and value['output'] == config['output'], 'ACP recipe differs')
    for name in ('compiler', 'source', 'recipe', 'publication'):
        require(value[name] == {'path': config[name], 'file': entries[config[name]]}, 'ACP compiler/source/recipe inventory differs')
    require(entries[config['compiler']]['mode'] & 0o111, 'ACP compiler not executable')
    candidate = pathlib.Path(value['candidatePath'])
    require(str(candidate) == value['candidatePath'] and '..' not in candidate.parts and
            candidate.parent.parent == run / 'root-build/acp-publication-private' and
            candidate.parent.name.startswith('invocation-') and len(candidate.parent.name) <= 128 and
            candidate.name == pathlib.Path(config['output']).name, 'ACP private candidate path differs')
    require(not any(candidate.is_relative_to(pathlib.Path(root)) for root in plan_roots(plan)),
            'ACP candidate overlaps sealed input roots')
    require(value['arguments'] == [config['compiler'], *ACP_FLAGS, config['source'], '-o', str(candidate)], 'ACP compilation arguments differ')
    require(value['final'] == entries[config['output']], 'ACP final differs from independent inventory')
    for item in (value['candidate'], value['final']):
        require(set(item) == {'type', 'bytes', 'sha256', 'mode', 'key'} and item['type'] == 'file' and
                type(item['bytes']) is int and 64 <= item['bytes'] <= 4 * 1024**2 and item['mode'] == 0o755 and
                re.fullmatch('[0-9a-f]{64}', item['sha256']) and isinstance(item['key'], list) and len(item['key']) == 2 and
                all(type(i) is int and i >= 0 for i in item['key']), 'ACP bounded output receipt differs')
    require(all(value['candidate'][k] == value['final'][k] for k in ('type', 'bytes', 'sha256', 'mode')),
            'ACP candidate/final content differs')
    require(value['candidate']['key'][0] == value['final']['key'][0], 'ACP candidate crosses filesystem')
    if value['outcome'] == 'retained':
        require(value['previous'] == value['final'] and value['candidate']['key'] != value['final']['key'],
                'ACP retained identity claim differs')
    else:
        require(value['outcome'] == 'replaced' and value['candidate'] == value['final'], 'ACP replacement identity differs')
    if value['commandId'] == 2:
        require(value['outcome'] == 'retained', 'ACP strict replay did not retain prepared final')
    times = [value[k] for k in ('startedAtUnixNs', 'compileStartedAtUnixNs', 'compileFinishedAtUnixNs',
                               'finishedAtUnixNs', 'cleanupFinishedAtUnixNs')] + [tasks[0]['atUnixNs']]
    require(all(type(t) is int and t > 0 for t in times) and times == sorted(times), 'ACP execution ordering differs')
    require(tasks[0]['atUnixNs'] <= event['actionsStartedAtUnixNs'], 'ACP execution did not precede Sync guard')
    if command is not None:
        require(command['commandId'] == value['commandId'] and command['initSha256'] == value['initSha256'] and
                command['startedAtUnixNs'] <= times[0] <= times[-1] <= command['finishedAtUnixNs'], 'ACP command/init binding differs')
    else:
        require(value['initSha256'] == file_receipt(run / f"command-{value['commandId']:02d}.init.gradle")['sha256'],
                'ACP immutable init differs')
    return value


def capture(plan, repo, source_hashes, tools):
    validate_semantic_plan(plan, tools)
    roots = plan_roots(plan)
    for path in roots:
        safe_path(path, repo)
    roots += [str(repo / p) for p in source_hashes]
    roots += [entry["path"] for entry in tools.values()]
    roots += [plan["acp"]["compiler"]]
    # Compiler paths come from actual retained original provenance, never an override.
    initial = inventory(sorted(set(roots)))
    if initial["status"] != "passed":
        write_json(pathlib.Path(plan["runRoot"]) / "prepared-seal-failure.json", initial, immutable=True)
    require(initial["status"] == "passed", "prepared inventory failed: " + initial.get("error", ""))
    prov = provenance(plan, initial["entries"])
    roots += [p["record"]["compiler"]["path"] for p in prov["producers"].values()]
    current = inventory(sorted(set(roots)))
    if current["status"] != "passed":
        write_json(pathlib.Path(plan["runRoot"]) / "prepared-seal-failure.json", current, immutable=True)
    require(current["status"] == "passed", "prepared compiler inventory failed")
    validate_acp(read_json(pathlib.Path(plan["runRoot"]) / "command-01-events.json"), plan, current["entries"])
    validate_tools(tools, current["entries"], small_bytes)
    require(all(plan['jdkBinding']['entries'][relative] == current['entries'][tools[key]['path']]
                for key,relative in (('java','bin/java'),('javaRelease','release'))), 'selected JDK/tool receipt disagreement')
    require(plan["frontendNodeHome"] in ("PATH", tools["node"]["home"]), "frontend Node home differs")
    return {"roots": sorted(set(roots)), "inventory": current, "provenance": prov,
            "mapping": mapping(plan, current["entries"], pathlib.Path(plan["runRoot"]))}


def check_prepared(manifest, plan):
    validate_semantic_plan(plan, manifest.get("tools"))
    require(plan == manifest["plan"], "prepared task configuration/input set changed")
    check_sources(manifest)
    current = inventory(manifest["roots"])
    diff = difference(manifest["inventory"], current)
    require(diff == EMPTY_DIFF, "prepared input changed: " + json.dumps(diff)[:4096])
    return current


def check_sources(manifest):
    repo = pathlib.Path(manifest["plan"]["repoRoot"])
    names = set(subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                                       cwd=repo, timeout=30).decode().split("\0")) | set(BUILD_CONTROLS)
    current = {name for name in names if name and (name in BUILD_CONTROLS or
               name.startswith(("src/", "scripts/", "frontend/", "ghidra-bridge/", "contracts/", "oracle/")) or
               name.endswith((".gradle.kts", ".properties"))) and (repo / name).is_file() and not (repo / name).is_symlink()}
    require(current == set(manifest["sourceHashes"]), "source input set changed")
    require(build_controls(repo) == manifest["buildControls"], "build-control inputs changed")


def validate_publisher(receipt, manifest):
    require(receipt.get("commandId") == 2 and receipt.get("runRoot") == manifest["runRoot"], "publisher command role differs")
    require(receipt.get("actionsStarted") is True and receipt.get("publisherCompleted") is True and
            receipt.get("stalePruneCandidates") == [], "publisher skipped/incomplete or prune candidates remain")
    tasks = [t for t in receipt["tasks"] if t["path"] == ":installDist"]
    require(len(tasks) == 1 and tasks[0]["executed"] is True and tasks[0]["enabled"] is True and
            all(tasks[0][k] is False for k in ("skipped", "upToDate", "noSource", "failure")), "installDist actions did not execute")
    require(not any(t["path"] in {":" + p for p in PRODUCERS} for t in receipt["tasks"]), "excluded helper ran in replay")
    expected = manifest["mapping"]
    events = receipt["events"]
    require(len(events) == 4 * len(expected) + 1, "publisher event count differs (rename or missing publication)")
    require(all(event["phase"] in {"source-before-copy", "source-after-copy", "staged", "published", "lib-validated"}
                for event in events), "unexpected publisher mutation/event")
    for item in expected.values():
        for phase in ("source-before-copy", "source-after-copy", "staged", "published"):
            path = item["source"] if phase.startswith("source-") else item["destination"]
            require(sum(e["phase"] == phase and e["path"] == path for e in events) == 1, "publisher source/destination event missing/duplicate")
    lib_events = [i for i, e in enumerate(events) if e["phase"] == "lib-validated"]
    require(len(lib_events) == 1 and events[lib_events[0]]["path"] == str(pathlib.Path(manifest["runRoot"]) / "root-build/install/llm_bin_patch/lib"), "lib validation event differs")
    require(max(i for i, e in enumerate(events) if e["phase"] == "staged") <
            min(i for i, e in enumerate(events) if e["phase"] == "published"), "publication preceded staging")
    require(all(i > lib_events[0] for i, e in enumerate(events) if e["phase"] == "published" and "/bin/" in e["path"]), "launcher preceded lib validation")
    times = [receipt["actionsStartedAtUnixNs"], receipt["guardPassedAtUnixNs"],
             *[e["atUnixNs"] for e in events], receipt["publisherCompletedAtUnixNs"], tasks[0]["atUnixNs"]]
    require(all(type(t) is int and t > 0 for t in times) and times == sorted(times), "publisher event ordering differs")


def retain_inputs(manifest, run):
    """Independent byte copies survive subsequent normal installs; never restore them."""
    # Enumerate the original roots independently, before later builds overwrite them.
    # This is historical completeness consistency, not authentication of receipts.
    closure = inventory(manifest["roots"])
    require(closure["status"] == "passed" and closure == manifest["inventory"],
            "original recursive closure differs before retention")
    folder = run / "prepared-products"
    folder.mkdir()
    budget = [MAX_INPUT_BYTES]
    retained = {}
    for index, (name, claimed) in enumerate(closure["entries"].items()):
        if claimed["type"] != "file":
            continue
        target = folder / f"{index:06d}"
        actual = file_receipt(pathlib.Path(name), budget, target)
        require(actual == claimed, "prepared source changed during retention")
        target.chmod(claimed["mode"])
        retained[name] = {"path": str(target.relative_to(run)), **file_receipt(target)}
    require(inventory(manifest["roots"]) == closure, "original recursive closure changed during retention")
    write_json(run / "prepared-closure.json", {"schemaVersion": 1, "roots": manifest["roots"],
               "inventory": closure, "copies": retained}, immutable=True)
    return retained


def frontend_compare(produced, consumed):
    # Vite still runs fresh. Only avoid rewriting identical bridge inputs on replay.
    def content(root):
        snap = inventory([str(root / n) for n in ("dist", "bundle-report.json", "bundle-composition.json")])
        require(snap["status"] == "passed", "frontend inventory failed")
        return {str(pathlib.Path(p).relative_to(root)): {k: v for k, v in r.items() if k != "key"}
                for p, r in snap["entries"].items()}
    require(content(produced) == content(consumed), "fresh frontend changed prepared inputs")


def main():
    if sys.argv[1] == "frontend":
        frontend_compare(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
        return
    if sys.argv[1] == "bindings":
        budget = BindingBudget(float(sys.argv[5]))
        value = {"jdkBinding": jdk_binding(pathlib.Path(sys.argv[2]), budget),
                 "gradleBinding": gradle_binding(pathlib.Path(sys.argv[3]), budget)}
        validate_binding_receipts(value["jdkBinding"], value["gradleBinding"], budget.deadline)
        budget.check()
        write_json(pathlib.Path(sys.argv[4]), value, immutable=True)
        budget.check()
        return
    require(sys.argv[1] == "guard", "unknown prepared operation")
    run = safe_path(pathlib.Path(sys.argv[2]))
    manifest = read_json(run / "prepared-A.json")
    plan = read_json(run / "command-02-plan.json")
    current = inventory(manifest["roots"])
    diff = difference(manifest["inventory"], current)
    source_error = None
    try:
        validate_semantic_plan(plan, manifest["tools"])
        check_sources(manifest)
    except Exception as failure:
        source_error = repr(failure)
    acp = None
    acp_error = None
    try:
        acp = validate_acp(read_json(run / "command-02-events.json"), plan, current['entries'])
    except Exception as failure:
        acp_error = repr(failure)[:2048]
    write_json(run / "prepared-guard.json", {"commandId": 2, "runRoot": str(run), "atUnixNs": time.time_ns(),
               "manifestSha256": file_receipt(run / "prepared-A.json")["sha256"],
               "acp": acp, "acpError": acp_error, "inventory": current, "diff": diff, "planEqual": plan == manifest["plan"], "sourceError": source_error}, immutable=True)
    require(plan == manifest["plan"] and diff == EMPTY_DIFF and source_error is None and acp_error is None, "pre-Sync sealed-input guard failed")


if __name__ == "__main__":
    main()
