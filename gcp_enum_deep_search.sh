# gcp_enum_deep_search.sh - bounded inventory + pattern-oriented search (sourced).
# Expects: LOG, section, run, PFLAG, PROJECT; limit vars from gcp_enum.sh.
# Requires: gcp_enum_patterns.sh sourced first (GCP_ENUM_PATTERNS_LOADED=1).

if [ -z "$GCP_ENUM_PATTERNS_LOADED" ]; then
  echo "gcp_enum_deep_search.sh: gcp_enum_patterns.sh must be sourced first." >&2
  exit 1
fi

# Optional: comma-separated extensions for content scan (no leading dots).
: "${GCP_ENUM_CONTENT_EXT:=json,txt,yml,yaml,env,xml,csv,md,html,properties,cfg,toml,ini,sh}"

# Max object bodies to scan per bucket when --storage-content is set.
: "${GCP_ENUM_STORAGE_CONTENT_MAX:=25}"

_deep_search_ext_ok() {
  _obj="$1"
  _base="${_obj##*/}"
  _e=""
  case "$_base" in
    *.*) _e="${_base##*.}" ;;
    *) return 1 ;;
  esac
  _el=$(echo "$_e" | tr '[:upper:]' '[:lower:]')
  _allowed=",${GCP_ENUM_CONTENT_EXT},"
  _allowed_low=$(echo "$_allowed" | tr '[:upper:]' '[:lower:]')
  case "$_allowed_low" in
    *",${_el},"*) return 0 ;;
    *) return 1 ;;
  esac
}

_deep_search_log_limits() {
  section "Deep search configuration"
  echo "storage_max_objects=$storage_max_objects storage_max_describe=$storage_max_describe" | tee -a "$LOG"
  echo "storage_content=$storage_content storage_max_bytes=$storage_max_bytes content_max_per_bucket=$GCP_ENUM_STORAGE_CONTENT_MAX" | tee -a "$LOG"
  echo "bq_max_tables_schema=$bq_max_tables_schema artifact_max_repos=$artifact_max_repos artifact_max_packages=$artifact_max_packages" | tee -a "$LOG"
  echo "log_search_limit=$log_search_limit log_freshness=$log_freshness" | tee -a "$LOG"
}

deep_search_storage() {
  section "Deep search: Cloud Storage (objects list + describe + optional content)"
  run gcloud storage buckets list $PFLAG 2>/dev/null || true
  _buckets=$(gsutil ls 2>/dev/null)
  [ -z "$_buckets" ] && return 0
  echo "$_buckets" | while read -r _bkt || [ -n "$_bkt" ]; do
    [ -z "$_bkt" ] && continue
    _bp="${_bkt%/}/**"
    section "Deep search bucket: $_bkt"
    run gsutil iam get "$_bkt" 2>/dev/null || true
    _olist=$(mktemp "${TMPDIR:-/tmp}/gcp_enum_os.XXXXXX") || continue
    if ! gcloud storage objects list "$_bp" --limit="$storage_max_objects" --format="value(name)" 2>/dev/null >"$_olist"; then
      rm -f "$_olist"
      continue
    fi
    echo "Object names (capped at $storage_max_objects):" | tee -a "$LOG"
    tee -a "$LOG" <"$_olist" >/dev/null
    _n=0
    while read -r _obj || [ -n "$_obj" ]; do
      [ -z "$_obj" ] && continue
      _n=$((_n + 1))
      [ "$_n" -gt "$storage_max_describe" ] && break
      run gcloud storage objects describe "$_obj" 2>/dev/null || true
    done <"$_olist"
    if [ "$storage_content" -eq 1 ]; then
      _sc=0
      while read -r _obj || [ -n "$_obj" ]; do
        [ -z "$_obj" ] && continue
        _deep_search_ext_ok "$_obj" || continue
        _sc=$((_sc + 1))
        [ "$_sc" -gt "$GCP_ENUM_STORAGE_CONTENT_MAX" ] && break
        section "Deep search content sample: $_obj (bytes 0-$((storage_max_bytes - 1)))"
        _range="$((storage_max_bytes - 1))"
        _matches=$(gcloud storage cat -r "0-$_range" "$_obj" 2>/dev/null | grep -E "$GCP_ENUM_GREP_PATTERN" 2>/dev/null | head -50)
        if [ -n "$_matches" ]; then
          echo "$_matches" >>"$LOG"
          echo "(pattern match in sampled bytes: $_obj)" | tee -a "$LOG"
        else
          echo "(no pattern match in sampled bytes: $_obj)" >>"$LOG"
        fi
      done <"$_olist"
    fi
    rm -f "$_olist"
  done
}

deep_search_bigquery() {
  section "Deep search: BigQuery (datasets, tables, schema sample, name grep)"
  command -v bq >/dev/null 2>&1 || {
    echo "bq not in PATH; skip BigQuery deep search" | tee -a "$LOG"
    return 0
  }
  if [ -z "$PROJECT" ]; then
    echo "No project id; bq ls without --project_id" | tee -a "$LOG"
    run bq ls 2>/dev/null || true
    return 0
  fi
  run bq ls "--project_id=$PROJECT" 2>/dev/null || true
  _dtmp=$(mktemp "${TMPDIR:-/tmp}/gcp_enum_bqd.XXXXXX") || return 0
  bq ls -q "--project_id=$PROJECT" --format=csv >"$_dtmp" 2>/dev/null || true
  _ds_header=1
  while IFS= read -r _line || [ -n "$_line" ]; do
    [ -z "$_line" ] && continue
    if [ "$_ds_header" -eq 1 ]; then
      _ds_header=0
      continue
    fi
    _ds="${_line%%,*}"
    _ds=$(echo "$_ds" | tr -d '"')
    [ -z "$_ds" ] && continue
    echo "$_ds" | grep -qiE "$GCP_ENUM_NAME_CONCERN_ERE" && echo "BQ dataset name match: $_ds" | tee -a "$LOG"
    section "Deep search BQ dataset: $PROJECT:$_ds"
    run bq ls "$PROJECT:$_ds" 2>/dev/null || true
    _ttmp=$(mktemp "${TMPDIR:-/tmp}/gcp_enum_bqt.XXXXXX") || continue
    bq ls -q "$PROJECT:$_ds" --format=csv >"$_ttmp" 2>/dev/null || {
      rm -f "$_ttmp"
      continue
    }
    _thdr=1
    _tc=0
    while IFS= read -r _tl || [ -n "$_tl" ]; do
      [ -z "$_tl" ] && continue
      if [ "$_thdr" -eq 1 ]; then
        _thdr=0
        continue
      fi
      _tc=$((_tc + 1))
      [ "$_tc" -gt "$bq_max_tables_schema" ] && break
      _tid="${_tl%%,*}"
      _tid=$(echo "$_tid" | tr -d '"')
      [ -z "$_tid" ] && continue
      echo "$_tid" | grep -qiE "$GCP_ENUM_NAME_CONCERN_ERE" && echo "BQ table name match: $_ds.$_tid" | tee -a "$LOG"
      run bq show --schema --format=prettyjson "$PROJECT:$_ds.$_tid" 2>/dev/null | head -c 16384 >>"$LOG" || true
      echo "" >>"$LOG"
    done <"$_ttmp"
    rm -f "$_ttmp"
  done <"$_dtmp"
  rm -f "$_dtmp"
}

deep_search_artifacts() {
  section "Deep search: Artifact Registry (repos + packages, capped)"
  _art=$(mktemp "${TMPDIR:-/tmp}/gcp_enum_ar.XXXXXX") || return 0
  gcloud artifacts repositories list $PFLAG --format="value(name)" 2>/dev/null >"$_art" || true
  _rc=0
  while read -r _rname || [ -n "$_rname" ]; do
    [ -z "$_rname" ] && continue
    _rc=$((_rc + 1))
    [ "$_rc" -gt "$artifact_max_repos" ] && break
    _loc="${_rname#*locations/}"
    _loc="${_loc%%/repositories*}"
    _rep="${_rname##*/}"
    [ -z "$_loc" ] || [ -z "$_rep" ] && continue
    section "Deep search Artifact repo: $_loc/$_rep"
    run gcloud artifacts packages list --repository="$_rep" --location="$_loc" $PFLAG --limit="$artifact_max_packages" 2>/dev/null || true
    echo "$_rep" | grep -qiE "$GCP_ENUM_NAME_CONCERN_ERE" && echo "Artifact repo id match: $_rep" | tee -a "$LOG"
  done <"$_art"
  rm -f "$_art"
}

deep_search_logging() {
  section "Deep search: Logging (keyword read, capped)"
  _sub="$GCP_ENUM_LOGGING_SUBEXP"
  _lf=""
  _lf="${_lf}(textPayload=~\"(?i)("
  _lf="${_lf}${_sub}"
  _lf="${_lf})\" OR jsonPayload.message=~\"(?i)("
  _lf="${_lf}${_sub}"
  _lf="${_lf})\" )"
  run gcloud logging read "$_lf" --limit="$log_search_limit" --freshness="$log_freshness" $PFLAG 2>/dev/null || true
}

do_deep_search() {
  _deep_search_log_limits
  deep_search_storage
  deep_search_bigquery
  deep_search_artifacts
  deep_search_logging
}
