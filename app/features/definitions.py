"""Feature schema version and column definitions shared by train + serve."""

FEATURE_SCHEMA_VERSION = "1"

# Order matters — must match training artifact feature_schema.json
FEATURE_DEFINITIONS: list[tuple[str, str]] = [
    ("url_length", "int"),
    ("domain_length", "int"),
    ("num_subdomains", "int"),
    ("has_https", "int"),
    ("has_ip_address", "int"),
    ("num_digits", "int"),
    ("num_hyphens", "int"),
    ("num_at_signs", "int"),
    ("num_dots", "int"),
    ("has_login_keyword", "int"),
    ("has_verify_keyword", "int"),
    ("suspicious_tld", "int"),
    ("path_depth", "int"),
    ("query_length", "int"),
    ("domain_age_days", "float"),  # -1 when unknown (ML only; heuristic uses known flag)
    ("domain_age_known", "int"),
    ("tls_ok", "int"),
    ("hostname_match", "int"),
    ("cert_expired", "int"),
    ("password_input_count", "int"),
    ("credit_card_field_count", "int"),
    ("form_count", "int"),
    ("iframe_count", "int"),
    ("suspicious_word_count", "int"),
    ("has_login_form", "int"),
    ("external_form_action", "int"),
    ("brand_similarity", "float"),
    ("brand_in_domain", "int"),
    ("impersonation_likely", "int"),
    ("redirect_count", "int"),
]

FEATURE_COLUMNS = [name for name, _ in FEATURE_DEFINITIONS]
