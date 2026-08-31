import java.nio.charset.StandardCharsets;
import java.util.Map;

/** Minimal strict JSON encoder for the trusted ACP compatibility support programs. */
final class AcpCompatibilityJson {
    private AcpCompatibilityJson() {}

    static byte[] encode(Map<String, Object> document) {
        var output = new StringBuilder();
        appendValue(output, document);
        output.append('\n');
        return output.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void appendValue(StringBuilder output, Object value) {
        switch (value) {
            case null -> output.append("null");
            case String text -> appendString(output, text);
            case Boolean bool -> output.append(bool ? "true" : "false");
            case Byte number -> output.append(number);
            case Short number -> output.append(number);
            case Integer number -> output.append(number);
            case Long number -> output.append(number);
            case Map<?, ?> object -> appendObject(output, object);
            case Iterable<?> values -> appendArray(output, values);
            default -> throw new IllegalArgumentException(
                "unsupported ACP compatibility JSON value: " + value.getClass().getName()
            );
        }
    }

    private static void appendObject(StringBuilder output, Map<?, ?> object) {
        output.append('{');
        var first = true;
        for (var entry : object.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IllegalArgumentException("ACP compatibility JSON object key is not a string");
            }
            if (!first) {
                output.append(',');
            }
            first = false;
            appendString(output, key);
            output.append(':');
            appendValue(output, entry.getValue());
        }
        output.append('}');
    }

    private static void appendArray(StringBuilder output, Iterable<?> values) {
        output.append('[');
        var first = true;
        for (var value : values) {
            if (!first) {
                output.append(',');
            }
            first = false;
            appendValue(output, value);
        }
        output.append(']');
    }

    private static void appendString(StringBuilder output, String value) {
        output.append('"');
        for (var index = 0; index < value.length();) {
            var codePoint = value.codePointAt(index);
            var width = Character.charCount(codePoint);
            if (width == 1 && Character.isSurrogate(value.charAt(index))) {
                throw new IllegalArgumentException("ACP compatibility JSON string contains an unpaired surrogate");
            }
            index += width;
            switch (codePoint) {
                case '"' -> output.append("\\\"");
                case '\\' -> output.append("\\\\");
                case '\b' -> output.append("\\b");
                case '\f' -> output.append("\\f");
                case '\n' -> output.append("\\n");
                case '\r' -> output.append("\\r");
                case '\t' -> output.append("\\t");
                default -> {
                    if (codePoint < 0x20) {
                        output.append(String.format("\\u%04x", codePoint));
                    } else {
                        output.appendCodePoint(codePoint);
                    }
                }
            }
        }
        output.append('"');
    }
}
