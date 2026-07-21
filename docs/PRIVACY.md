# Metadata Sanitization

SolGuard creates a separate, bounded observability copy of payment metadata before data reaches logs, audit events, or the dashboard. The canonical payment request evaluated for signing is never silently modified.

## Recognized categories

- Email addresses
- Bearer-style authorization values
- Common API-token formats and sensitive field names
- Session identifiers and cookie-style fields
- Card-like digit sequences that pass a Luhn checksum

Redacted values are replaced with an explicit category marker. Audit evidence contains only category counts, not the original values.

## Bounds

The sanitizer limits nesting depth, collection length, individual string length, and total serialized metadata size. Data outside those bounds is removed from the observability copy rather than partially logged.

## Security boundary

Sanitization is deterministic local processing with no external service dependency. It reduces common accidental disclosure risks; it is not a universal PII detector, data-loss-prevention system, or compliance guarantee. Unknown secret formats, encoded data, natural-language identifiers, and deliberately obfuscated values may not be recognized.

Production use would require organization-specific classifiers, privacy review, retention controls, access control, monitoring, and adversarial testing.
