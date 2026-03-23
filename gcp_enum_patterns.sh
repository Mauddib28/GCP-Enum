# gcp_enum_patterns.sh - shared concern patterns (sourced by gcp_enum.sh).
# Do not execute directly. Uses POSIX sh-safe defaults (no ${var:=...} with } in regex).

# --- Name-oriented (BQ dataset/table IDs, Artifact repo IDs): grep -iE ---
if [ -z "$GCP_ENUM_NAME_CONCERN_ERE" ]; then
  GCP_ENUM_NAME_CONCERN_ERE='password|passwd|secret|private|credential|token|api[_-]?key|admin|administrator|root|super[-_]?user|sudo|keys?|key|user'
fi

# --- Object body sampling: grep -E on bytes (override with GCP_ENUM_GREP_PATTERN) ---
if [ -z "$GCP_ENUM_GREP_PATTERN" ]; then
  GCP_ENUM_GREP_PATTERN='API_?KEY|api[_-]?key|SECRET|secret|password|PASSWORD|passwd|PASSWD|BEGIN[[:space:]]+PRIVATE|private_key|private[[:space:]]+key|credential|token[[:space:]]*[=:]|bearer[[:space:]]+[A-Za-z0-9_-]{20,}|admin|administrator|root|sudo|super[-_]?user|USER_MANAGED'
fi

# --- Cloud Logging read filter subexpression (RE2, (?i) applied in filter wrapper) ---
if [ -z "$GCP_ENUM_LOGGING_SUBEXP" ]; then
  GCP_ENUM_LOGGING_SUBEXP='api_?key|password|passwd|secret|BEGIN[[:space:]]+PRIVATE|credential|token|admin|administrator|root|sudo|super[- ]?user|private[[:space:]]+key|keys?|user'
fi

GCP_ENUM_PATTERNS_LOADED=1
