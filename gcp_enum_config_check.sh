# gcp_enum_config_check.sh - shell-first configuration heuristics (sourced).
# Expects: LOG, section, run, PFLAG, PROJECT, _ENUM_ROOT, GCP_ENUM_JSON_ANALYSIS (0|1).
# Requires: gcp_enum_patterns.sh (GCP_ENUM_PATTERNS_LOADED=1).

if [ -z "$GCP_ENUM_PATTERNS_LOADED" ]; then
  echo "gcp_enum_config_check.sh: gcp_enum_patterns.sh must be sourced first." >&2
  exit 1
fi

: "${GCP_ENUM_CONFIG_MAX_BUCKETS:=50}"
: "${GCP_ENUM_CONFIG_MAX_SA:=100}"
: "${GCP_ENUM_CONFIG_MAX_SQL:=20}"
: "${GCP_ENUM_CONFIG_MAX_GKE:=15}"
: "${GCP_ENUM_CONFIG_MAX_SECRETS:=200}"

_config_emit() {
  _sev="$1"
  _rule="$2"
  shift 2
  echo "CONFIG_FINDING source=shell severity=$_sev rule=$_rule $*" | tee -a "$LOG"
}

_config_check_log_limits() {
  section "Config check: limits"
  echo "GCP_ENUM_CONFIG_MAX_BUCKETS=$GCP_ENUM_CONFIG_MAX_BUCKETS GCP_ENUM_CONFIG_MAX_SA=$GCP_ENUM_CONFIG_MAX_SA" | tee -a "$LOG"
  echo "GCP_ENUM_CONFIG_MAX_SQL=$GCP_ENUM_CONFIG_MAX_SQL GCP_ENUM_CONFIG_MAX_GKE=$GCP_ENUM_CONFIG_MAX_GKE GCP_ENUM_CONFIG_MAX_SECRETS=$GCP_ENUM_CONFIG_MAX_SECRETS" | tee -a "$LOG"
  echo "GCP_ENUM_JSON_ANALYSIS=${GCP_ENUM_JSON_ANALYSIS:-0}" | tee -a "$LOG"
}

config_check_project_iam() {
  section "Config check: project IAM (public principals & primitive roles)"
  [ -z "$PROJECT" ] && {
    echo "Config check: no project id; skip project IAM" | tee -a "$LOG"
    return 0
  }
  _ptmp=$(mktemp "${TMPDIR:-/tmp}/gcp_enum_iam.XXXXXX") || return 0
  if ! gcloud projects get-iam-policy "$PROJECT" $PFLAG \
    --flatten="bindings[].members" \
    --format="csv[no-heading](bindings.role,bindings.members)" 2>/dev/null >"$_ptmp"; then
    rm -f "$_ptmp"
    echo "Config check: project get-iam-policy failed; skip" | tee -a "$LOG"
    return 0
  fi
  while IFS= read -r _line || [ -n "$_line" ]; do
    [ -z "$_line" ] && continue
    _role="${_line%%,*}"
    _mem="${_line#*,}"
    _role=$(echo "$_role" | tr -d '"')
    _mem=$(echo "$_mem" | tr -d '"')
    [ -z "$_role" ] || [ -z "$_mem" ] && continue
    case "$_mem" in
      allUsers|allAuthenticatedUsers)
        case "$_role" in
          roles/owner|roles/editor)
            _config_emit HIGH iam_public_primitive "project=$PROJECT role=$_role member=$_mem"
            ;;
          *)
            _config_emit MEDIUM iam_public_principal "project=$PROJECT role=$_role member=$_mem"
            ;;
        esac
        ;;
    esac
  done <"$_ptmp"
  rm -f "$_ptmp"

  if [ "${GCP_ENUM_JSON_ANALYSIS:-0}" = 1 ] && command -v python3 >/dev/null 2>&1; then
    _jtmp=$(mktemp "${TMPDIR:-/tmp}/gcp_enum_ij.XXXXXX") || return 0
    if gcloud projects get-iam-policy "$PROJECT" $PFLAG --format=json 2>/dev/null >"$_jtmp"; then
      section "Config check: project IAM (Python supplemental — conditional bindings)"
      GCP_ENUM_PROJECT="$PROJECT" python3 "$_ENUM_ROOT/gcp_enum_analyze_json.py" project-iam \
        <"$_jtmp" 2>/dev/null | tee -a "$LOG" || true
    fi
    rm -f "$_jtmp"
  fi
}

config_check_bucket_iam() {
  section "Config check: Cloud Storage bucket IAM (public principals)"
  _bc=0
  while read -r _bkt; do
    [ -z "$_bkt" ] && continue
    _bc=$((_bc + 1))
    [ "$_bc" -gt "$GCP_ENUM_CONFIG_MAX_BUCKETS" ] && break
    _bout=$(gsutil iam get "$_bkt" 2>/dev/null) || continue
    echo "$_bout" | grep -q '"allUsers"' && _config_emit MEDIUM storage_public_principal "bucket=$_bkt member=allUsers"
    echo "$_bout" | grep -q '"allAuthenticatedUsers"' && _config_emit MEDIUM storage_public_principal "bucket=$_bkt member=allAuthenticatedUsers"
  done <<EOF
$(gsutil ls 2>/dev/null)
EOF
}

config_check_sa_keys() {
  section "Config check: service account user-managed keys"
  _sc=0
  for _sa in $(gcloud iam service-accounts list $PFLAG --format="value(email)" 2>/dev/null); do
    [ -z "$_sa" ] && continue
    _sc=$((_sc + 1))
    [ "$_sc" -gt "$GCP_ENUM_CONFIG_MAX_SA" ] && break
    _keys=$(gcloud iam service-accounts keys list --iam-account="$_sa" $PFLAG --format="value(keyType)" 2>/dev/null) || continue
    echo "$_keys" | grep -q USER_MANAGED && _config_emit MEDIUM sa_user_managed_key "serviceAccount=$_sa"
  done
}

config_check_sql() {
  section "Config check: Cloud SQL (open network / SSL)"
  _qc=0
  for _inst in $(gcloud sql instances list $PFLAG --format="value(name)" 2>/dev/null); do
    [ -z "$_inst" ] && continue
    _qc=$((_qc + 1))
    [ "$_qc" -gt "$GCP_ENUM_CONFIG_MAX_SQL" ] && break
    _jtmp=$(mktemp "${TMPDIR:-/tmp}/gcp_enum_sql.XXXXXX") || continue
    if ! gcloud sql instances describe "$_inst" $PFLAG --format=json 2>/dev/null >"$_jtmp"; then
      rm -f "$_jtmp"
      continue
    fi
    if grep -q '0\.0\.0\.0/0' "$_jtmp" 2>/dev/null; then
      _config_emit HIGH sql_authorized_network_open "instance=$_inst"
    fi
    if grep -q '"requireSsl": false' "$_jtmp" 2>/dev/null; then
      _config_emit MEDIUM sql_require_ssl_disabled "instance=$_inst"
    fi
    rm -f "$_jtmp"
  done
}

config_check_gke() {
  section "Config check: GKE (legacy ABAC / master authorized networks)"
  _gc=0
  _clist=$(gcloud container clusters list $PFLAG --format="value(name,zone)" 2>/dev/null | tr '\t' ',')
  for _line in $_clist; do
    [ -z "$_line" ] && continue
    _gname="${_line%%,*}"
    _gzone="${_line#*,}"
    [ -z "$_gname" ] || [ -z "$_gzone" ] && continue
    _gc=$((_gc + 1))
    [ "$_gc" -gt "$GCP_ENUM_CONFIG_MAX_GKE" ] && break
    _jtmp=$(mktemp "${TMPDIR:-/tmp}/gcp_enum_gke.XXXXXX") || continue
    if ! gcloud container clusters describe "$_gname" --zone="$_gzone" $PFLAG --format=json 2>/dev/null >"$_jtmp"; then
      rm -f "$_jtmp"
      continue
    fi
    if grep -q '"legacyAbac"' "$_jtmp" 2>/dev/null && grep -q '"enabled": true' "$_jtmp" 2>/dev/null; then
      _config_emit MEDIUM gke_legacy_abac_enabled "cluster=$_gname zone=$_gzone"
    fi
    if grep -q '0\.0\.0\.0/0' "$_jtmp" 2>/dev/null; then
      _config_emit HIGH gke_master_authorized_network_open "cluster=$_gname zone=$_gzone"
    fi
    rm -f "$_jtmp"
  done
}

config_check_secret_names() {
  section "Config check: Secret Manager (name concern match)"
  [ -z "$GCP_ENUM_NAME_CONCERN_ERE" ] && return 0
  _secn=0
  for _sid in $(gcloud secrets list $PFLAG --format="value(name)" 2>/dev/null); do
    [ -z "$_sid" ] && continue
    _secn=$((_secn + 1))
    [ "$_secn" -gt "$GCP_ENUM_CONFIG_MAX_SECRETS" ] && break
    _base="${_sid##*/}"
    echo "$_base" | grep -qiE "$GCP_ENUM_NAME_CONCERN_ERE" && _config_emit LOW secret_name_concern "secret=$_sid"
  done
}

do_config_check() {
  _config_check_log_limits
  config_check_project_iam
  config_check_bucket_iam
  config_check_sa_keys
  config_check_sql
  config_check_gke
  config_check_secret_names
}
