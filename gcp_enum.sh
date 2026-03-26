#!/bin/sh
#
# gcp_enum.sh - GCP enumeration (full | initial | deep | deep-search).
# Uses gcloud, gsutil, bq, and POSIX shell; optional python3 for supplemental JSON (see --with-json-analysis).
# See workDocs/PLAN.enumeration-script.md, workDocs/DEEP_SEARCH.md, workDocs/CONFIG_CHECK.md.
#
# Usage: gcp_enum.sh [MODE] [-o OUTFILE] [-p PROJECT] [-c] [OPTIONS]
#   -c: limit to current project only (no iteration over projects list in full mode).
#   --deep-search runs config checks by default; use --no-config-check to skip.
#   --iam-policy-summary: with --full / --deep, append per-role row counts after each project IAM table.
#   BigQuery: bq ls -p JSON -> table + gcloud projects describe per id (python3); GCP_ENUM_BQ_* caps; best-effort bq show.
#
# Auth: if no active gcloud user account, runs: gcloud auth login --no-browser
#

# Do not exit on first failure; enumeration continues.
set +e

# --- Defaults and usage ---
usage() {
  echo "Usage: gcp_enum.sh [--full|--initial|--deep|--deep-search] [-o OUTFILE] [-p PROJECT] [-c] [options]"
  echo "  --full         full enumeration (default)"
  echo "  --initial      initial investigation subset"
  echo "  --deep         deeper dive on IAM, containers, secrets, logging, SQL, BigQuery"
  echo "  --deep-search  runs --deep, then bounded storage / BigQuery / Artifact Registry / Logging search"
  echo "  -o FILE        output log file (default: GCP_OSINT_<project>_Results.txt)"
  echo "  -p PROJ        project ID (default: from gcloud config)"
  echo "  -c             current project only (full mode: do not iterate projects)"
  echo "Deep search caps (only for --deep-search):"
  echo "  --storage-max-objects N   (default 500)  --storage-max-describe N (default 50)"
  echo "  --storage-content         scan object bodies (extensions + bytes cap; see workDocs/DEEP_SEARCH.md)"
  echo "  --storage-max-bytes N     bytes per object for content scan (default 65536)"
  echo "  --bq-max-tables-schema N  tables per dataset for schema sample (default 30)"
  echo "  --artifact-max-repos N    (default 30)  --artifact-max-packages N (default 20)"
  echo "  --log-search-limit N      logging read limit (default 50)  --log-freshness FRESHNESS (default 1d)"
  echo "Config check (--deep-search; see workDocs/CONFIG_CHECK.md):"
  echo "  --no-config-check         skip shell config heuristics after deep-search"
  echo "  --with-json-analysis      run optional Python IAM conditional-binding pass (requires python3)"
  echo "Project IAM (--full and --deep):"
  echo "  --iam-policy-summary      after each project IAM table, append role occurrence counts (flattened member rows)"
  echo "Environment (optional):"
  echo "  GCP_ENUM_BQ_LS_P_MAX              max projects for bq ls -p pagination (default 1000000)"
  echo "  GCP_ENUM_BQ_GCLOUD_DESCRIBE_MAX   max gcloud projects describe per BQ-listed id (0=unlimited; default 0)"
  echo "  If no account is active, gcloud auth login --no-browser runs automatically."
  exit 1
}

mode=full
outfile=""
project=""
current_only=0
storage_max_objects=500
storage_max_describe=50
storage_content=0
storage_max_bytes=65536
bq_max_tables_schema=30
artifact_max_repos=30
artifact_max_packages=20
log_search_limit=50
log_freshness=1d
no_config_check=0
iam_policy_summary=0

: "${GCP_ENUM_JSON_ANALYSIS:=0}"
: "${GCP_ENUM_BQ_LS_P_MAX:=1000000}"
: "${GCP_ENUM_BQ_GCLOUD_DESCRIBE_MAX:=0}"

while [ $# -gt 0 ]; do
  case "$1" in
    --full|-f)   mode=full; shift ;;
    --initial|-i) mode=initial; shift ;;
    --deep|-d)  mode=deep; shift ;;
    --deep-search) mode=deepsearch; shift ;;
    --storage-content) storage_content=1; shift ;;
    --storage-max-objects=*) storage_max_objects="${1#*=}"; shift ;;
    --storage-max-objects) storage_max_objects="$2"; shift 2 ;;
    --storage-max-describe=*) storage_max_describe="${1#*=}"; shift ;;
    --storage-max-describe) storage_max_describe="$2"; shift 2 ;;
    --storage-max-bytes=*) storage_max_bytes="${1#*=}"; shift ;;
    --storage-max-bytes) storage_max_bytes="$2"; shift 2 ;;
    --bq-max-tables-schema=*) bq_max_tables_schema="${1#*=}"; shift ;;
    --bq-max-tables-schema) bq_max_tables_schema="$2"; shift 2 ;;
    --artifact-max-repos=*) artifact_max_repos="${1#*=}"; shift ;;
    --artifact-max-repos) artifact_max_repos="$2"; shift 2 ;;
    --artifact-max-packages=*) artifact_max_packages="${1#*=}"; shift ;;
    --artifact-max-packages) artifact_max_packages="$2"; shift 2 ;;
    --log-search-limit=*) log_search_limit="${1#*=}"; shift ;;
    --log-search-limit) log_search_limit="$2"; shift 2 ;;
    --log-freshness=*) log_freshness="${1#*=}"; shift ;;
    --log-freshness) log_freshness="$2"; shift 2 ;;
    --no-config-check) no_config_check=1; shift ;;
    --iam-policy-summary) iam_policy_summary=1; shift ;;
    --with-json-analysis) GCP_ENUM_JSON_ANALYSIS=1; shift ;;
    -o) outfile="$2"; shift 2 ;;
    -p) project="$2"; shift 2 ;;
    -c) current_only=1; shift ;;
    -h) usage ;; --help) usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

# --- Helpers ---
LOG=""
section() { echo "------ $1 ------" | tee -a "$LOG"; }
run() { "$@" 2>&1 | tee -a "$LOG"; true; }

# Args: section_title project_id
# Table: one row per (binding,member); COND_TITLE empty when binding has no IAM condition.
_enum_project_iam_bindings() {
  _iam_title="$1"
  _iam_proj="$2"
  [ -z "$_iam_proj" ] && return 0
  section "$_iam_title"
  run gcloud projects get-iam-policy "$_iam_proj" --flatten="bindings[].members" \
    --format="table(bindings.role,bindings.members,bindings.condition.title:label=COND_TITLE)" \
    2>/dev/null || true
  [ "$iam_policy_summary" -eq 1 ] || return 0
  section "$_iam_title — role row counts (one row per principal in each binding)"
  gcloud projects get-iam-policy "$_iam_proj" --flatten="bindings[].members" \
    --format="value(bindings.role)" 2>/dev/null | sort | uniq -c | tee -a "$LOG" || true
}

# gcloud describe is reliable; bq show <project> still uses bq's project resolution (may fail if >1000 BQ-listed projects).
_enum_bq_default_project_summary() {
  if [ -n "$PROJECT" ]; then
    run gcloud projects describe "$PROJECT" $PFLAG 2>/dev/null || true
    run bq ls --project_id="$PROJECT" 2>/dev/null || true
    run bq show "$PROJECT" 2>/dev/null || true
  else
    echo "BigQuery: no project id; skipping gcloud projects describe, scoped bq ls, and bq show <id> (use -p or gcloud config set project)" | tee -a "$LOG"
    run bq ls 2>/dev/null || true
    echo "BigQuery: best-effort default-project bq show (may error if many BQ-listed projects)" | tee -a "$LOG"
    run bq show 2>/dev/null || true
  fi
}

# One bq ls -p --format=json (paginated via -n); table + per-id gcloud projects describe (RM metadata; avoids bq show resolution cap).
_enum_bq_accessible_projects_list() {
  _bj=$(mktemp "${TMPDIR:-/tmp}/gcp_enum_bqp.XXXXXX") || return 0
  if ! bq ls -p -n "$GCP_ENUM_BQ_LS_P_MAX" --format=json 2>/dev/null >"$_bj"; then
    rm -f "$_bj"
    echo "BigQuery: bq ls -p --format=json failed; fallback bq ls -p table only" | tee -a "$LOG"
    run bq ls -p -n "$GCP_ENUM_BQ_LS_P_MAX" 2>/dev/null || true
    return 0
  fi
  [ ! -s "$_bj" ] && {
    rm -f "$_bj"
    echo "BigQuery: no BQ-accessible projects in list response" | tee -a "$LOG"
    return 0
  }
  section "BigQuery: BQ-accessible projects (projectId, friendlyName)"
  if command -v python3 >/dev/null 2>&1; then
    python3 -c '
import json,sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    raw = f.read().strip()
if not raw:
    sys.exit(0)
r = json.loads(raw)
if isinstance(r, dict) and isinstance(r.get("projects"), list):
    r = r["projects"]
if not isinstance(r, list):
    sys.exit(0)
print("projectId\tfriendlyName")
for x in r:
    if not isinstance(x, dict):
        continue
    pid = x.get("id") or x.get("projectId")
    if not pid and isinstance(x.get("projectReference"), dict):
        pid = x["projectReference"].get("projectId")
    if not pid:
        continue
    fn = x.get("friendlyName") or ""
    print("%s\t%s" % (pid, fn))
' "$_bj" 2>/dev/null | tee -a "$LOG" || true
  else
    echo "BigQuery: python3 not found; dumping raw JSON (install python3 for a clear table + per-project gcloud describe)" | tee -a "$LOG"
    tee -a "$LOG" <"$_bj" >/dev/null || true
  fi
  _enum_gcloud_describe_bq_json_projects "$_bj"
  rm -f "$_bj"
}

# Args: path to bq ls -p --format=json file
_enum_gcloud_describe_bq_json_projects() {
  _bjf="$1"
  [ -s "$_bjf" ] || return 0
  if ! command -v python3 >/dev/null 2>&1; then
    echo "BigQuery: skip gcloud projects describe for each BQ id (python3 required to parse JSON list)" | tee -a "$LOG"
    return 0
  fi
  _idsf=$(mktemp "${TMPDIR:-/tmp}/gcp_enum_bqid.XXXXXX") || return 0
  python3 -c '
import json,sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    raw = f.read().strip()
if not raw:
    sys.exit(0)
r = json.loads(raw)
if isinstance(r, dict) and isinstance(r.get("projects"), list):
    r = r["projects"]
if not isinstance(r, list):
    sys.exit(0)
seen = set()
for x in r:
    if not isinstance(x, dict):
        continue
    pid = x.get("id") or x.get("projectId")
    if not pid and isinstance(x.get("projectReference"), dict):
        pid = x["projectReference"].get("projectId")
    if pid and pid not in seen:
        seen.add(pid)
        print(pid)
' "$_bjf" >"$_idsf" 2>/dev/null || {
    rm -f "$_idsf"
    return 0
  }
  [ ! -s "$_idsf" ] && {
    rm -f "$_idsf"
    return 0
  }
  section "BigQuery: gcloud projects describe (Resource Manager) per BQ-accessible project id"
  if [ "$GCP_ENUM_BQ_GCLOUD_DESCRIBE_MAX" != "0" ]; then
    echo "BigQuery: applying GCP_ENUM_BQ_GCLOUD_DESCRIBE_MAX=$GCP_ENUM_BQ_GCLOUD_DESCRIBE_MAX" | tee -a "$LOG"
    _idcap=$(mktemp "${TMPDIR:-/tmp}/gcp_enum_bqidc.XXXXXX") || {
      rm -f "$_idsf"
      return 0
    }
    head -n "$GCP_ENUM_BQ_GCLOUD_DESCRIBE_MAX" "$_idsf" >"$_idcap"
    mv "$_idcap" "$_idsf"
  fi
  while read -r _bqpid || [ -n "$_bqpid" ]; do
    [ -z "$_bqpid" ] && continue
    section "BigQuery RM metadata: $_bqpid"
    run gcloud projects describe "$_bqpid" 2>/dev/null || true
  done <"$_idsf"
  rm -f "$_idsf"
}

check_gcloud() {
  if ! command -v gcloud >/dev/null 2>&1; then
    echo "gcloud not found. Install GCP SDK." >&2
    exit 1
  fi
}

has_active_account() {
  gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | grep -q .
}

# If no user credential is active, run no-browser login (exact CLI as required).
ensure_auth() {
  if has_active_account; then
    return 0
  fi
  echo "No active gcloud account. Running: gcloud auth login --no-browser" >&2
  if ! gcloud auth login --no-browser; then
    echo "gcloud auth login --no-browser failed." >&2
    exit 1
  fi
  if ! has_active_account; then
    echo "No active account after login; complete the device/URL flow and re-run." >&2
    exit 1
  fi
}

# Resolve project: -p wins, else config.
get_project() {
  if [ -n "$project" ]; then
    echo "$project"
    return
  fi
  gcloud config get-value project 2>/dev/null || true
}

# --- Main ---
check_gcloud
ensure_auth
PROJECT=$(get_project)
[ -z "$outfile" ] && outfile="GCP_OSINT_${PROJECT:-default}_Results.txt"
LOG="$outfile"
: > "$LOG"
echo "Mode: $mode | Project: $PROJECT | Log: $LOG" | tee -a "$LOG"

# Optional: set project for this run
set_project_flag() {
  [ -z "$PROJECT" ] && return
  echo "--project=$PROJECT"
}
PFLAG=$(set_project_flag)

_ENUM_ROOT=$(CDPATH= cd "$(dirname "$0")" && pwd)
for _lib in gcp_enum_patterns.sh gcp_enum_deep_search.sh gcp_enum_config_check.sh; do
  if ! . "$_ENUM_ROOT/$_lib"; then
    echo "$_lib not found or failed to load (expected next to gcp_enum.sh)." >&2
    exit 1
  fi
done
unset _lib

do_initial() {
  section "CLI check"
  run gcloud help 2>/dev/null | head -50
  run gcloud info
  section "Auth"
  run gcloud auth list
  run gcloud auth application-default print-access-token 2>/dev/null || true
  section "Config"
  run gcloud config list
  run gcloud config configurations list 2>/dev/null || true
  section "Projects"
  run gcloud projects list
  section "Services"
  run gcloud services list $PFLAG
  section "Compute"
  run gcloud compute instances list $PFLAG 2>/dev/null || true
  section "App"
  run gcloud app instances list $PFLAG 2>/dev/null || true
  section "Containers"
  run gcloud container clusters list $PFLAG 2>/dev/null || true
  section "Secrets"
  run gcloud secrets list $PFLAG 2>/dev/null || true
  section "Logging"
  run gcloud logging logs list $PFLAG 2>/dev/null || true
  section "Storage"
  run gsutil ls 2>/dev/null || true
  for b in $(gsutil ls 2>/dev/null); do
    run gsutil iam get "$b" 2>/dev/null || true
  done
  section "Kubernetes"
  if command -v kubectl >/dev/null 2>&1; then
    run kubectl get namespaces 2>/dev/null || true
    run kubectl cluster-info 2>/dev/null || true
  fi
  section "IAM (project roles)"
  run gcloud iam roles list $PFLAG 2>/dev/null || true
  run gcloud iam service-accounts list $PFLAG 2>/dev/null || true
}

do_deep() {
  if [ -n "$PROJECT" ]; then
    section "IAM grantable roles"
    run gcloud iam list-grantable-roles "//cloudresourcemanager.googleapis.com/projects/$PROJECT" 2>/dev/null || true
    section "IAM testable permissions"
    run gcloud iam list-testable-permissions "//cloudresourcemanager.googleapis.com/projects/$PROJECT" 2>/dev/null || true
  fi
  section "IAM service accounts"
  run gcloud iam service-accounts list $PFLAG
  for sa in $(gcloud iam service-accounts list $PFLAG --format="value(email)" 2>/dev/null); do
    run gcloud iam service-accounts describe "$sa" $PFLAG 2>/dev/null || true
    run gcloud iam service-accounts keys list --iam-account="$sa" $PFLAG 2>/dev/null || true
  done
  if [ -n "$PROJECT" ]; then
    _enum_project_iam_bindings "Project IAM policy" "$PROJECT"
  fi
  section "Services"
  run gcloud services list $PFLAG
  section "Containers"
  run gcloud container clusters list $PFLAG
  for line in $(gcloud container clusters list $PFLAG --format="value(name,zone)" 2>/dev/null | tr '\t' ','); do
    name="${line%%,*}"; zone="${line#*,}"
    [ -z "$name" ] && continue
    run gcloud container clusters describe "$name" --zone="$zone" $PFLAG 2>/dev/null || true
  done
  if command -v kubectl >/dev/null 2>&1; then
    run kubectl api-resources 2>/dev/null || true
  fi
  section "Secrets (list; versions only listed)"
  run gcloud secrets list $PFLAG
  section "Logging"
  run gcloud logging logs list $PFLAG
  run gcloud logging buckets list $PFLAG 2>/dev/null || true
  section "SQL"
  run gcloud sql instances list $PFLAG
  for inst in $(gcloud sql instances list $PFLAG --format="value(name)" 2>/dev/null); do
    run gcloud sql backups list --instance="$inst" $PFLAG 2>/dev/null || true
  done
  section "BigQuery"
  if command -v bq >/dev/null 2>&1; then
    run bq version 2>/dev/null || true
    _enum_bq_default_project_summary
    _enum_bq_accessible_projects_list
  fi
}

do_full() {
  section "CLI / environment"
  run gcloud help 2>/dev/null | head -80
  run gcloud info
  run gcloud info --run-diagnostics 2>/dev/null || true
  run gcloud components list 2>/dev/null || true
  section "Auth"
  run gcloud auth list
  run gcloud auth application-default print-access-token 2>/dev/null || true
  run gcloud auth print-access-token 2>/dev/null || true
  section "Config"
  run gcloud config list
  run gcloud config configurations list
  section "Projects"
  run gcloud projects list
  if [ $current_only -eq 0 ]; then
    for proj in $(gcloud projects list --format="value(projectId)" 2>/dev/null); do
      _enum_project_iam_bindings "Project IAM: $proj" "$proj"
    done
  else
    if [ -n "$PROJECT" ]; then
      _enum_project_iam_bindings "Project IAM (current)" "$PROJECT"
    fi
  fi
  section "Services"
  run gcloud services list $PFLAG
  section "IAM"
  run gcloud iam roles list $PFLAG
  for role in $(gcloud iam roles list $PFLAG --format="value(name)" 2>/dev/null); do
    run gcloud iam roles describe "$role" $PFLAG 2>/dev/null || true
  done
  if [ -n "$PROJECT" ]; then
    run gcloud iam list-grantable-roles "//cloudresourcemanager.googleapis.com/projects/$PROJECT" 2>/dev/null || true
    run gcloud iam list-testable-permissions "//cloudresourcemanager.googleapis.com/projects/$PROJECT" 2>/dev/null || true
  fi
  run gcloud iam service-accounts list $PFLAG
  for sa in $(gcloud iam service-accounts list $PFLAG --format="value(email)" 2>/dev/null); do
    run gcloud iam service-accounts describe "$sa" $PFLAG 2>/dev/null || true
    run gcloud iam service-accounts keys list --iam-account="$sa" $PFLAG 2>/dev/null || true
    run gcloud iam service-accounts get-iam-policy "$sa" $PFLAG 2>/dev/null || true
  done
  section "Compute"
  run gcloud compute instances list $PFLAG
  run gcloud compute networks list $PFLAG
  run gcloud compute networks subnets list $PFLAG
  section "App"
  run gcloud app instances list $PFLAG 2>/dev/null || true
  section "Containers"
  run gcloud container clusters list $PFLAG
  run gcloud container images list $PFLAG 2>/dev/null || true
  for line in $(gcloud container clusters list $PFLAG --format="value(name,zone)" 2>/dev/null | tr '\t' ','); do
    name="${line%%,*}"; zone="${line#*,}"
    [ -z "$name" ] && continue
    run gcloud container clusters describe "$name" --zone="$zone" $PFLAG 2>/dev/null || true
  done
  if command -v kubectl >/dev/null 2>&1; then
    run kubectl get namespaces 2>/dev/null || true
    run kubectl cluster-info 2>/dev/null || true
    run kubectl api-resources 2>/dev/null || true
  fi
  section "Secrets"
  run gcloud secrets list $PFLAG
  section "KMS"
  run gcloud kms keyrings list --location=global $PFLAG 2>/dev/null || true
  section "Logging"
  run gcloud logging logs list $PFLAG
  run gcloud logging buckets list $PFLAG 2>/dev/null || true
  section "SQL"
  run gcloud sql instances list $PFLAG
  for inst in $(gcloud sql instances list $PFLAG --format="value(name)" 2>/dev/null); do
    run gcloud sql backups list --instance="$inst" $PFLAG 2>/dev/null || true
  done
  section "Organizations"
  run gcloud organizations list 2>/dev/null || true
  for org in $(gcloud organizations list --format="value(name)" 2>/dev/null); do
    run gcloud resource-manager folders list --organization="${org#organizations/}" 2>/dev/null || true
  done
  section "Storage"
  run gsutil ls 2>/dev/null || true
  run gcloud storage buckets list $PFLAG 2>/dev/null || true
  for b in $(gsutil ls 2>/dev/null); do
    section "Bucket: $b"
    run gsutil iam get "$b" 2>/dev/null || true
    run gsutil acl get "$b" 2>/dev/null || true
    run gsutil lifecycle get "$b" 2>/dev/null || true
    run gsutil versioning get "$b" 2>/dev/null || true
  done
  section "General gcloud groups"
  for grp in auth config compute container iam kms projects services secrets; do
    run gcloud "$grp" --help 2>/dev/null | head -20 || true
  done
  section "BigQuery"
  if command -v bq >/dev/null 2>&1; then
    run bq version
    _enum_bq_default_project_summary
    _enum_bq_accessible_projects_list
  fi
}

case "$mode" in
  initial) do_initial ;;
  deep)    do_deep ;;
  deepsearch)
    do_deep
    do_deep_search
    [ "$no_config_check" -eq 0 ] && do_config_check
    ;;
  full)    do_full ;;
  *)       do_full ;;
esac

echo "Done. Log: $LOG"
