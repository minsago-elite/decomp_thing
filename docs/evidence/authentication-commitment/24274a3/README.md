# Commitment launcher diagnostic isolation

All 13 AcpAuthenticationInventoryTest tests passed offline on the unchanged source
immediately before commit 24274a3. Both isolated child JVMs explicitly set
JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS and _JAVA_OPTIONS to benign fixture properties.
Stderr is separate from the exact two-line stdout protocol; UUID/commitment syntax
and differing scope/commitment across processes remain asserted. The original
JUnit report and digest are retained here. No ACP agent or target was executed.
Full CI omitted because its patch lane executes vulnerability reproduction.
