#!/usr/bin/env bash

set -euo pipefail;

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)";
CONFIG_FILE="$DIR/cert.conf";
OPENSSL_CNF="$DIR/openssl.cnf";

# Load defaults if config exists
if [[ -f "$CONFIG_FILE" ]]; then
  source "$CONFIG_FILE";
fi;

OUTPUT_DIR=${OUTPUT_DIR:-"$DIR/certs"};
if [[ "$OUTPUT_DIR" != /* ]]; then
  OUTPUT_DIR="$(cd "$(dirname "$CONFIG_FILE")" && pwd)/$OUTPUT_DIR";
fi;
mkdir -p "$OUTPUT_DIR";

# Default fallback values
DEFAULT_CIPHER=${CIPHER:-"aes256"};
DEFAULT_ASYM_ALGO=${ASYM_ALGO:-"ED25519"};
DEFAULT_CA_DAYS=${CA_DAYS:-3650};
DEFAULT_CERT_DAYS=${CERT_DAYS:-365};
DEFAULT_CA_CN=${CA_CN:-"My Root CA"};
DEFAULT_INTERMEDIATE_CN=${INTERMEDIATE_CN:-"My Intermediate CA"};
DEFAULT_CLIENT_CN=${CLIENT_CN:-"My Client Certificate"};
DEFAULT_PASSWORD=${PASSWORD:-""};
DEFAULT_PASSWORD_FILE=${PASSWORD_FILE:-""};
DEFAULT_PRIVKEY_FILE=${PRIVKEY_FILENAME:-"privkey.pem"};
DEFAULT_CERT_FILE=${CERT_FILENAME:-"certs.pem"};
DEFAULT_CHAIN_FILE=${CHAIN_FILENAME:-"fullchain.pem"};
DEFAULT_SECRET_FILE=${SECRET_FILENAME:-"secret.txt"};
DEFAULT_CACHED_CNF=${CACHED_CNF_FILENAME:-"openssl.cnf"};

# ANSI Color Codes
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

parse_expiration() {
  local exp="$1";
  if [[ "$exp" =~ ^([0-9]+)d$ ]]; then
    echo "${BASH_REMATCH[1]}";
  elif [[ "$exp" =~ ^([0-9]+)w$ ]]; then
    echo $(( ${BASH_REMATCH[1]} * 7 ));
  elif [[ "$exp" =~ ^([0-9]+)m$ ]]; then
    echo $(( ${BASH_REMATCH[1]} * 30 ));
  elif [[ "$exp" =~ ^([0-9]+)y$ ]]; then
    echo $(( ${BASH_REMATCH[1]} * 365 ));
  else
    echo "Error: Invalid expiration format $exp. Use Nd, Nw, Nm, Ny." >&2;
    exit 1;
  fi;
}

get_pass_args() {
  local pass="$1";
  local pass_file="$2";
  local mode="$3"; # "in" or "out"

  if [[ -n "$pass_file" ]]; then
    if [[ ! -f "$pass_file" ]]; then
      echo "Error: Password file $pass_file not found." >&2;
      exit 1;
    fi;
    echo "-pass$mode file:$pass_file";
  elif [[ -n "$pass" ]]; then
    echo "-pass$mode pass:$pass";
  fi;
}

print_help() {
  local cmd=${1:-""};
  if [[ "$cmd" == "rootca" ]]; then
    echo -e "Usage: $0 ${CYAN}rootca${RESET} ${GREEN}--name <cname>${RESET} [${GREEN}--expiration <Nd|Nw|Nm|Ny>${RESET}] [${GREEN}--cipher <cipher>${RESET}] [${GREEN}--no-password${RESET}] [${GREEN}--password-file <path>${RESET}] [${GREEN}--output-dir <dir>${RESET}] [${GREEN}--force${RESET}]";
    echo "Generate a Root CA.";
    echo -e "${BOLD}Required Options:${RESET}";
    echo -e "  ${GREEN}--name${RESET}             Common Name for the Root CA (e.g., \"My Trusted Root CA\")";
    echo -e "${BOLD}Optional Options:${RESET}";
    echo -e "  ${GREEN}--expiration${RESET}       Expiration time (e.g., 30d, 1w, 6m, 1y) (default: ${DEFAULT_CA_DAYS}d)";
    echo -e "  ${GREEN}--cipher${RESET}           Encryption cipher for private key (e.g., aes256, aes128, none) (default: ${DEFAULT_CIPHER})";
    echo -e "  ${GREEN}--no-password${RESET}      Do not encrypt the private key (otherwise a password is auto-generated)";
    echo -e "  ${GREEN}--password-file${RESET}    Provide a custom password file path (e.g., /path/to/pass.txt)";
    echo -e "  ${GREEN}--output-dir${RESET}       Output directory for the generated certificates (e.g., ./my_certs)";
    echo -e "  ${GREEN}--force${RESET}            Overwrite existing certificate and key if they exist";
  elif [[ "$cmd" == "intermediate" ]]; then
    echo -e "Usage: $0 ${CYAN}intermediate${RESET} ${GREEN}--ca <ca-name>${RESET} ${GREEN}--name <cname>${RESET} [${GREEN}--expiration <Nd|Nw|Nm|Ny>${RESET}] [${GREEN}--cipher <cipher>${RESET}] [${GREEN}--no-password${RESET}] [${GREEN}--password-file <path>${RESET}] [${GREEN}--output-dir <dir>${RESET}] [${GREEN}--force${RESET}]";
    echo "Generate an Intermediate CA signed by the Root CA.";
    echo -e "${BOLD}Required Options:${RESET}";
    echo -e "  ${GREEN}--ca${RESET}               Filepath prefix or CNAME matching the previously generated CA (e.g., \"My Trusted Root CA\")";
    echo -e "  ${GREEN}--name${RESET}             Common Name for the Intermediate CA (e.g., \"My Intermediate CA\")";
    echo -e "${BOLD}Optional Options:${RESET}";
    echo -e "  ${GREEN}--expiration${RESET}       Expiration time (e.g., 365d, 1y) (default: ${DEFAULT_CA_DAYS}d)";
    echo -e "  ${GREEN}--cipher${RESET}           Encryption cipher for private key (e.g., aes256, none) (default: ${DEFAULT_CIPHER})";
    echo -e "  ${GREEN}--no-password${RESET}      Do not encrypt the private key";
    echo -e "  ${GREEN}--password-file${RESET}    Provide a custom password file path (e.g., /path/to/pass.txt)";
    echo -e "  ${GREEN}--output-dir${RESET}       Output directory for the generated certificates (e.g., ./my_certs)";
    echo -e "  ${GREEN}--force${RESET}            Overwrite existing certificate and key if they exist";
  elif [[ "$cmd" == "certs" ]]; then
    echo -e "Usage: $0 ${CYAN}certs${RESET} ${GREEN}--ca <ca-name>${RESET} ${GREEN}--name <cname>${RESET} ${GREEN}--purpose <server|client>${RESET} [${GREEN}--expiration <Nd|Nw|Nm|Ny>${RESET}] [${GREEN}--cipher <cipher>${RESET}] [${GREEN}--no-password${RESET}] [${GREEN}--random-password${RESET}] [${GREEN}--openssl-config-file <path>${RESET}] [${GREEN}--output-dir <dir>${RESET}] [${GREEN}--force${RESET}]";
    echo "Generate Server or Client certificates signed by a CA.";
    echo -e "${BOLD}Required Options:${RESET}";
    echo -e "  ${GREEN}--ca${RESET}               Filepath prefix or CNAME of the issuing CA (e.g., \"My Intermediate CA\")";
    echo -e "  ${GREEN}--name${RESET}             Common Name for the certificate (e.g., \"demo.example.com\")";
    echo -e "  ${GREEN}--purpose${RESET}          Must be 'server' or 'client'";
    echo -e "${BOLD}Optional Options:${RESET}";
    echo -e "  ${GREEN}--expiration${RESET}       Expiration time (e.g., 30d, 1y) (default: ${DEFAULT_CERT_DAYS}d)";
    echo -e "  ${GREEN}--cipher${RESET}           Encryption cipher for private key (e.g., aes256) (default: ${DEFAULT_CIPHER})";
    echo -e "  ${GREEN}--no-password${RESET}      Do not encrypt the private key (Default for server/client certs)";
    echo -e "  ${GREEN}--random-password${RESET}  Generate a random password and store it in ${SECRET_FILENAME}";
    echo -e "  ${GREEN}--openssl-config-file${RESET} Provide a custom OpenSSL configuration file";
    echo -e "  ${GREEN}--output-dir${RESET}       Output directory for the generated certificates (e.g., ./my_certs)";
    echo -e "  ${GREEN}--force${RESET}            Overwrite existing certificate and key if they exist";
  elif [[ "$cmd" == "info" ]]; then
    echo -e "Usage: $0 ${CYAN}info${RESET} [${GREEN}cname${RESET}]";
    echo "Display valid certificates, their expiration dates, and issuers.";
    echo -e "${BOLD}Optional Arguments:${RESET}";
    echo -e "  ${GREEN}cname${RESET}              Provide a Common Name substring to view detailed certificate text";
  elif [[ "$cmd" == "renew" ]]; then
    echo -e "Usage: $0 ${CYAN}renew${RESET} ${GREEN}--name <cname>${RESET} [${GREEN}--openssl-config-file <path>${RESET}]";
    echo "Renew an existing certificate, keeping its existing key and CSR.";
    echo -e "${BOLD}Required Options:${RESET}";
    echo -e "  ${GREEN}--name${RESET}             Common Name for the certificate to renew (e.g., \"demo.example.com\")";
    echo -e "${BOLD}Optional Options:${RESET}";
    echo -e "  ${GREEN}--openssl-config-file${RESET} Provide a custom OpenSSL configuration file (required if original cert used one)";
  else
    echo -e "Usage: $0 ${CYAN}<subcommand>${RESET} [${GREEN}options${RESET}]";
    echo -e "${BOLD}Subcommands:${RESET}";
    echo -e "  ${CYAN}rootca${RESET}         Generate Root CA";
    echo -e "  ${CYAN}intermediate${RESET}   Generate Intermediate CA";
    echo -e "  ${CYAN}certs${RESET}          Generate Server/Client certificate";
    echo -e "  ${CYAN}info${RESET}           Query and list existing certificates";
    echo -e "  ${CYAN}renew${RESET}          Renew an existing certificate";
    echo -e "Use '$0 ${CYAN}<subcommand>${RESET} ${GREEN}--help${RESET}' for detailed help.";
  fi;
}

setup_dir_and_pass() {
  local name="$1";
  local is_client="$2";
  local no_pass="$3";
  local cipher="$4";
  local pass_file="${5:-}";
  local force="${6:-false}";

  local safe_name;
  safe_name=$(echo "$name" | tr ' ' '_');
  local out_dir="$OUTPUT_DIR/$safe_name";

  if [[ -d "$out_dir" ]] && [[ "$force" != "true" ]]; then
    if [[ -f "$out_dir/$DEFAULT_CERT_FILE" ]] || [[ -f "$out_dir/$DEFAULT_PRIVKEY_FILE" ]]; then
      echo -e "${RED}Error: Certificate or key already exists in $out_dir.${RESET}" >&2
      echo -e "Use ${GREEN}--force${RESET} to overwrite." >&2
      exit 1
    fi
  fi

  mkdir -p "$out_dir";

  if [[ "$is_client" == "true" ]] && [[ -z "$no_pass" ]]; then
    no_pass="true";
  fi;

  if [[ "$no_pass" == "true" ]]; then
    OUT_PASS_GEN="";
    OUT_PASS_IN="";
    OUT_CIPHER_OPT="";
  elif [[ -n "$pass_file" ]] && [[ -f "$pass_file" ]]; then
    local read_pass;
    read_pass=$(cat "$pass_file");
    echo "$read_pass" > "$out_dir/$DEFAULT_SECRET_FILE";
    chmod 600 "$out_dir/$DEFAULT_SECRET_FILE";
    OUT_PASS_GEN="-pass pass:$read_pass";
    OUT_PASS_IN="-passin pass:$read_pass";
    if [[ -n "$cipher" ]] && [[ "$cipher" != "none" ]]; then
      OUT_CIPHER_OPT="-$cipher";
    else
      OUT_CIPHER_OPT="";
    fi;
    echo "Imported custom password via $pass_file";
  else
    local rand_pass;
    rand_pass=$(openssl rand -base64 32);
    echo "$rand_pass" > "$out_dir/$DEFAULT_SECRET_FILE";
    chmod 600 "$out_dir/$DEFAULT_SECRET_FILE";
    OUT_PASS_GEN="-pass pass:$rand_pass";
    OUT_PASS_IN="-passin pass:$rand_pass";
    if [[ -n "$cipher" ]] && [[ "$cipher" != "none" ]]; then
      OUT_CIPHER_OPT="-$cipher";
    else
      OUT_CIPHER_OPT="";
    fi;
    echo "Generated random password at $out_dir/$DEFAULT_SECRET_FILE";
  fi;
  OUT_CERT_DIR="$out_dir";
}

resolve_ca() {
  local ca_name="$1";
  local safe_ca;
  safe_ca=$(echo "$ca_name" | tr ' ' '_');

  local cert_path="$OUTPUT_DIR/${safe_ca}/$DEFAULT_CERT_FILE"
  local key_path="$OUTPUT_DIR/${safe_ca}/$DEFAULT_PRIVKEY_FILE"
  local chain_path="$OUTPUT_DIR/${safe_ca}/$DEFAULT_CHAIN_FILE"

  if [[ -f "$cert_path" ]] && [[ -f "$key_path" ]]; then
    CA_CERT="$cert_path";
    CA_KEY="$key_path";
    if [[ -f "$chain_path" ]]; then CA_CHAIN="$chain_path"; else CA_CHAIN="$cert_path"; fi;
  elif [[ -f "$OUTPUT_DIR/${safe_ca}/${safe_ca}.pem" ]] && [[ -f "$OUTPUT_DIR/${safe_ca}/${safe_ca}.key" ]]; then
    # Fallback for old style naming inside CN directory
    CA_CERT="$OUTPUT_DIR/${safe_ca}/${safe_ca}.pem";
    CA_KEY="$OUTPUT_DIR/${safe_ca}/${safe_ca}.key";
    CA_CHAIN="$CA_CERT";
  elif [[ -f "$OUTPUT_DIR/${safe_ca}.pem" ]] && [[ -f "$OUTPUT_DIR/${safe_ca}.key" ]]; then
    # Fallback for old style naming in base directory
    CA_CERT="$OUTPUT_DIR/${safe_ca}.pem";
    CA_KEY="$OUTPUT_DIR/${safe_ca}.key";
    CA_CHAIN="$CA_CERT";
  else
    echo -e "${RED}Error: CA key or cert not found for $ca_name${RESET}" >&2;
    echo "Checked: $cert_path and $key_path" >&2;
    exit 1;
  fi;
}

get_ca_pass_in() {
  local ca_name="$1";
  local safe_ca;
  safe_ca=$(echo "$ca_name" | tr ' ' '_');
  local ca_dir="$OUTPUT_DIR/${safe_ca}";

  if [[ -f "$ca_dir/$DEFAULT_SECRET_FILE" ]]; then
    echo "-passin file:$ca_dir/$DEFAULT_SECRET_FILE";
  elif [[ -f "$ca_dir/password.txt" ]]; then
    # Fallback for old naming convention
    echo "-passin file:$ca_dir/password.txt";
  elif [[ -n "$DEFAULT_PASSWORD" ]]; then
    echo "-passin pass:$DEFAULT_PASSWORD";
  else
    # If the CA doesn't have an auto password file, we prompt manually
    read -s -r -p "Enter password for CA $ca_name: " ca_pass;
    echo "";
    if [[ -n "$ca_pass" ]]; then
      echo "-passin pass:$ca_pass";
    else
      echo "";
    fi;
  fi;
}

cmd_rootca() {
  local name="$DEFAULT_CA_CN";
  local exp="";
  local cipher="$DEFAULT_CIPHER";
  local no_pass="";
  local custom_out_dir="";
  local pass_file="";
  local force="";

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --name) name="$2"; shift 2;;
      --expiration) exp="$2"; shift 2;;
      --cipher) cipher="$2"; shift 2;;
      --no-password) no_pass="true"; shift 1;;
      --password-file) pass_file="$2"; shift 2;;
      --output-dir) custom_out_dir="$2"; shift 2;;
      --force) force="true"; shift 1;;
      --help) print_help rootca; exit 0;;
      *) echo "Unknown option $1" >&2; print_help rootca; exit 1;;
    esac;
  done;

  if [[ -z "$name" ]]; then echo "Error: --name is required" >&2; exit 1; fi;

  local days=$DEFAULT_CA_DAYS;
  if [[ -n "$exp" ]]; then days=$(parse_expiration "$exp"); fi;

  if [[ -n "$custom_out_dir" ]]; then
    if [[ "$custom_out_dir" != /* ]]; then
      OUTPUT_DIR="$PWD/$custom_out_dir"
    else
      OUTPUT_DIR="$custom_out_dir"
    fi
  fi
  mkdir -p "$OUTPUT_DIR"

  setup_dir_and_pass "$name" "false" "$no_pass" "$cipher" "$pass_file" "$force";

  local safe_name;
  safe_name=$(echo "$name" | tr ' ' '_');
  local key_file="$OUT_CERT_DIR/$DEFAULT_PRIVKEY_FILE";
  local cert_file="$OUT_CERT_DIR/$DEFAULT_CERT_FILE";
  local chain_file="$OUT_CERT_DIR/$DEFAULT_CHAIN_FILE";
  local csr_file="$OUT_CERT_DIR/request.csr";

  echo -e "Generating Root CA: ${CYAN}${name}${RESET}";
  # Not quoting OUT_PASS_GEN allows it to word-split if present
  openssl genpkey -algorithm $DEFAULT_ASYM_ALGO $OUT_CIPHER_OPT $OUT_PASS_GEN -out "$key_file";

  openssl req -x509 -new -key "$key_file" $OUT_PASS_IN -days "$days" -out "$cert_file" -subj "/CN=${name}" -extensions v3_ca -config "$OPENSSL_CNF";

  cp "$cert_file" "$chain_file"

  cp "$OPENSSL_CNF" "$OUT_CERT_DIR/$DEFAULT_CACHED_CNF"

  echo -e "Root CA created at ${GREEN}${cert_file}${RESET}";
}

cmd_intermediate() {
  local ca_name="";
  local name="$DEFAULT_INTERMEDIATE_CN";
  local exp="";
  local cipher="$DEFAULT_CIPHER";
  local no_pass="";
  local custom_out_dir="";
  local pass_file="";
  local force="";

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ca) ca_name="$2"; shift 2;;
      --name) name="$2"; shift 2;;
      --expiration) exp="$2"; shift 2;;
      --cipher) cipher="$2"; shift 2;;
      --no-password) no_pass="true"; shift 1;;
      --password-file) pass_file="$2"; shift 2;;
      --output-dir) custom_out_dir="$2"; shift 2;;
      --force) force="true"; shift 1;;
      --help) print_help intermediate; exit 0;;
      *) echo "Unknown option $1" >&2; print_help intermediate; exit 1;;
    esac;
  done;

  if [[ -z "$ca_name" ]]; then echo "Error: --ca is required" >&2; exit 1; fi;
  if [[ -z "$name" ]]; then echo "Error: --name is required" >&2; exit 1; fi;

  if [[ -n "$custom_out_dir" ]]; then
    if [[ "$custom_out_dir" != /* ]]; then
      OUTPUT_DIR="$PWD/$custom_out_dir"
    else
      OUTPUT_DIR="$custom_out_dir"
    fi
  fi
  mkdir -p "$OUTPUT_DIR"

  resolve_ca "$ca_name";
  local ca_pass_in;
  ca_pass_in=$(get_ca_pass_in "$ca_name");

  local days=$DEFAULT_CA_DAYS;
  if [[ -n "$exp" ]]; then days=$(parse_expiration "$exp"); fi;

  setup_dir_and_pass "$name" "false" "$no_pass" "$cipher" "$pass_file" "$force";

  local safe_name;
  safe_name=$(echo "$name" | tr ' ' '_');
  local key_file="$OUT_CERT_DIR/$DEFAULT_PRIVKEY_FILE";
  local csr_file="$OUT_CERT_DIR/request.csr";
  local cert_file="$OUT_CERT_DIR/$DEFAULT_CERT_FILE";
  local chain_file="$OUT_CERT_DIR/$DEFAULT_CHAIN_FILE";

  echo -e "Generating Intermediate CA: ${CYAN}${name}${RESET} signed by ${MAGENTA}${ca_name}${RESET}";
  openssl genpkey -algorithm $DEFAULT_ASYM_ALGO $OUT_CIPHER_OPT $OUT_PASS_GEN -out "$key_file";

  openssl req -new -key "$key_file" $OUT_PASS_IN -out "$csr_file" -subj "/CN=${name}" -config "$OPENSSL_CNF";

  openssl x509 -req -in "$csr_file" -CA "$CA_CERT" -CAkey "$CA_KEY" $ca_pass_in -CAcreateserial -out "$cert_file" -days "$days" -extfile "$OPENSSL_CNF" -extensions v3_intermediate_ca;

  cat "$cert_file" "$CA_CHAIN" > "$chain_file"
  cp "$OPENSSL_CNF" "$OUT_CERT_DIR/$DEFAULT_CACHED_CNF"

  echo -e "Intermediate CA created at ${GREEN}${cert_file}${RESET}";
}

cmd_certs() {
  local ca_name="";
  local name="$DEFAULT_CLIENT_CN";
  local purpose="";
  local exp="";
  local cipher="$DEFAULT_CIPHER";
  local custom_out_dir="";
  local force="";
  local random_pass="";
  local custom_cnf="";

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ca) ca_name="$2"; shift 2;;
      --name) name="$2"; shift 2;;
      --purpose) purpose="$2"; shift 2;;
      --expiration) exp="$2"; shift 2;;
      --cipher) cipher="$2"; shift 2;;
      --no-password) no_pass="true"; shift 1;;
      --random-password) random_pass="true"; shift 1;;
      --openssl-config-file) custom_cnf="$2"; shift 2;;
      --output-dir) custom_out_dir="$2"; shift 2;;
      --force) force="true"; shift 1;;
      --help) print_help certs; exit 0;;
      *) echo "Unknown option $1" >&2; print_help certs; exit 1;;
    esac;
  done;

  # Respect explicitly requested random-password, otherwise default to no-password for certs
  if [[ "$random_pass" == "true" ]]; then
    no_pass="false";
  else
    no_pass="true";
  fi;

  if [[ -z "$ca_name" ]]; then echo "Error: --ca is required" >&2; exit 1; fi;
  if [[ -z "$name" ]]; then echo "Error: --name is required" >&2; exit 1; fi;
  if [[ "$purpose" != "server" ]] && [[ "$purpose" != "client" ]]; then
    echo "Error: --purpose must be server or client" >&2;
    exit 1;
  fi;

  if [[ -n "$custom_out_dir" ]]; then
    if [[ "$custom_out_dir" != /* ]]; then
      OUTPUT_DIR="$PWD/$custom_out_dir"
    else
      OUTPUT_DIR="$custom_out_dir"
    fi
  fi
  mkdir -p "$OUTPUT_DIR"

  resolve_ca "$ca_name";
  local ca_pass_in;
  ca_pass_in=$(get_ca_pass_in "$ca_name");

  local days=$DEFAULT_CERT_DAYS;
  if [[ -n "$exp" ]]; then days=$(parse_expiration "$exp"); fi;

  local is_client="false";
  if [[ "$purpose" == "client" ]]; then is_client="true"; fi;

  setup_dir_and_pass "$name" "false" "$no_pass" "$cipher" "" "$force";

  local safe_name;
  safe_name=$(echo "$name" | tr ' ' '_');
  local key_file="$OUT_CERT_DIR/$DEFAULT_PRIVKEY_FILE";
  local csr_file="$OUT_CERT_DIR/request.csr";
  local cert_file="$OUT_CERT_DIR/$DEFAULT_CERT_FILE";
  local chain_file="$OUT_CERT_DIR/$DEFAULT_CHAIN_FILE";

  local conf_file="${custom_cnf:-$OPENSSL_CNF}";
  if [[ -n "$custom_cnf" ]] && [[ ! -f "$custom_cnf" ]]; then
    echo "Error: OpenSSL config file $custom_cnf not found." >&2;
    exit 1;
  fi;

  echo -e "Generating $purpose certificate: ${CYAN}${name}${RESET} signed by ${MAGENTA}${ca_name}${RESET}";
  if [[ -n "$custom_cnf" ]]; then
    echo "Using custom OpenSSL config: $custom_cnf";
  fi;
  openssl genpkey -algorithm $DEFAULT_ASYM_ALGO $OUT_CIPHER_OPT $OUT_PASS_GEN -out "$key_file";

  openssl req -new -key "$key_file" $OUT_PASS_IN -out "$csr_file" -subj "/CN=${name}" -config "$conf_file";

  local ext="${purpose}_cert";

  openssl x509 -req -in "$csr_file" -CA "$CA_CERT" -CAkey "$CA_KEY" $ca_pass_in -CAcreateserial -out "$cert_file" -days "$days" -extfile "$conf_file" -extensions "$ext";

  cat "$cert_file" "$CA_CHAIN" > "$chain_file"
  cp "$conf_file" "$OUT_CERT_DIR/$DEFAULT_CACHED_CNF"

  echo -e "$purpose certificate created at ${GREEN}${cert_file}${RESET}";
}

cmd_info() {
  local target_name=""

  for arg in "$@"; do
    if [[ "$arg" == "--help" ]] || [[ "$arg" == "-h" ]]; then
      print_help info; exit 0;
    else
      target_name="$arg"
    fi
  done

  if [[ -n "$target_name" ]]; then
    local matched_certs=()
    while IFS= read -r cert; do
      local filename;
      filename=$(basename "$cert")
      if [[ "$filename" == "$DEFAULT_CHAIN_FILE" ]]; then continue; fi
      if [[ "$filename" != "${target_name:-*}.pem" ]] && [[ "$filename" != "$DEFAULT_CERT_FILE" ]] && [[ "$filename" != "*_*.pem" ]]; then continue; fi

      local name;
      name=$(openssl x509 -in "$cert" -noout -subject -nameopt sep_multiline 2>/dev/null | grep -i "^ *CN=" | sed 's/^ *CN=//' || true)

      if [[ "$name" == *"$target_name"* ]]; then
        matched_certs+=("$cert")
      fi
    done < <(find "$OUTPUT_DIR" -type f -name "*.pem" 2>/dev/null)

    if [[ ${#matched_certs[@]} -eq 0 ]]; then
      echo "No certificates found matching '$target_name'." >&2
      exit 1
    fi

    for cert in "${matched_certs[@]}"; do
      openssl x509 -text -in "$cert"
    done | less
    exit 0
  fi

  local ca_names=() ca_dates=() ca_issuers=()
  local client_names=() client_dates=() client_issuers=()

  local max_name=4
  local max_date=20
  local max_issuer=6
  local total_certs=0

  # Find all PEMs in OUTPUT_DIR and parse properties
  while IFS= read -r cert; do
    local filename;
    filename=$(basename "$cert")
    if [[ "$filename" == "$DEFAULT_CHAIN_FILE" ]]; then continue; fi
    if [[ "$filename" != "${target_name:-*}.pem" ]] && [[ "$filename" != "$DEFAULT_CERT_FILE" ]] && [[ "$filename" != "*_*.pem" ]]; then continue; fi

    local is_ca;
    is_ca=$(openssl x509 -in "$cert" -noout -ext basicConstraints 2>/dev/null | grep -i "CA:TRUE" || true)

    local name;
    name=$(openssl x509 -in "$cert" -noout -subject -nameopt sep_multiline | grep -i "^ *CN=" | sed 's/^ *CN=//')

    local issuer;
    issuer=$(openssl x509 -in "$cert" -noout -issuer -nameopt sep_multiline | grep -i "^ *CN=" | sed 's/^ *CN=//')
    if [[ "$name" == "$issuer" ]] || [[ -z "$issuer" ]]; then
      issuer="N/A"
    fi

    local enddate;
    enddate=$(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)
    local iso_date;
    iso_date=$(date -j -f "%b %e %H:%M:%S %Y %Z" "$enddate" "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "$enddate")

    # Update dynamic column widths
    if (( ${#name} > max_name )); then max_name=${#name}; fi
    if (( ${#iso_date} > max_date )); then max_date=${#iso_date}; fi
    if (( ${#issuer} > max_issuer )); then max_issuer=${#issuer}; fi

    if [[ -n "$is_ca" ]]; then
      ca_names+=("$name")
      ca_dates+=("$iso_date")
      ca_issuers+=("$issuer")
      total_certs=$((total_certs + 1))
    else
      client_names+=("$name")
      client_dates+=("$iso_date")
      client_issuers+=("$issuer")
      total_certs=$((total_certs + 1))
    fi
  done < <(find "$OUTPUT_DIR" -type f -name "*.pem" 2>/dev/null)

  local ca_count=${#ca_names[@]}
  local client_count=${#client_names[@]}

  echo -e "${BOLD}Root/Intermediate CAs${RESET}"
  printf "${BOLD}%-${max_name}s | %-${max_date}s | %s${RESET}\n" "Name" "Expiration Date Time" "Issuer"

  if [[ $ca_count -eq 0 ]]; then
    echo -e "${RED}N/A${RESET}"
  else
    for (( i=0; i<ca_count; i++ )); do
      local iss="${ca_issuers[$i]}"
      local iss_color="${MAGENTA}"
      if [[ "$iss" == "N/A" ]]; then iss_color="${RED}"; fi
      printf "${CYAN}%-${max_name}s${RESET} | ${GREEN}%-${max_date}s${RESET} | ${iss_color}%s${RESET}\n" "${ca_names[$i]}" "${ca_dates[$i]}" "$iss"
    done
  fi

  echo ""
  echo -e "${BOLD}Client Certificates${RESET}"
  printf "${BOLD}%-${max_name}s | %-${max_date}s | %s${RESET}\n" "Name" "Expiration Date Time" "Issuer"

  if [[ $client_count -eq 0 ]]; then
    echo -e "${RED}N/A${RESET}"
  else
    for (( i=0; i<client_count; i++ )); do
      local iss="${client_issuers[$i]}"
      local iss_color="${MAGENTA}"
      if [[ "$iss" == "N/A" ]]; then iss_color="${RED}"; fi
      printf "${CYAN}%-${max_name}s${RESET} | ${GREEN}%-${max_date}s${RESET} | ${iss_color}%s${RESET}\n" "${client_names[$i]}" "${client_dates[$i]}" "$iss"
    done
  fi

  echo ""
  echo -e "${BOLD}Total: $total_certs certs${RESET}"
}

cmd_renew() {
  local name=""
  local custom_cnf=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --name) name="$2"; shift 2;;
      --openssl-config-file) custom_cnf="$2"; shift 2;;
      --help) print_help renew; exit 0;;
      *) echo "Unknown option $1" >&2; print_help renew; exit 1;;
    esac
  done

  if [[ -z "$name" ]]; then echo "Error: --name is required" >&2; exit 1; fi

  local safe_name;
  safe_name=$(echo "$name" | tr ' ' '_')
  local cert_dir="$OUTPUT_DIR/$safe_name"
  local cert_file="$cert_dir/$DEFAULT_CERT_FILE"
  local csr_file="$cert_dir/request.csr"
  local key_file="$cert_dir/$DEFAULT_PRIVKEY_FILE"
  local chain_file="$cert_dir/$DEFAULT_CHAIN_FILE"

  local cached_conf="$cert_dir/$DEFAULT_CACHED_CNF"
  local conf_file="$OPENSSL_CNF"
  if [[ -n "$custom_cnf" ]]; then
    conf_file="$custom_cnf"
  elif [[ -f "$cached_conf" ]]; then
    conf_file="$cached_conf"
    echo "Using cached OpenSSL config: $cached_conf"
  fi

  if [[ ! -f "$cert_file" ]] || [[ ! -f "$key_file" ]]; then
    # Fallback to old format
    cert_file="$cert_dir/${safe_name}.pem"
    csr_file="$cert_dir/${safe_name}.csr"
    key_file="$cert_dir/${safe_name}.key"
    if [[ ! -f "$cert_file" ]] || [[ ! -f "$key_file" ]]; then
      echo "Error: Cannot find Certificate/Key for $name in $cert_dir" >&2; exit 1
    fi
  fi

  local issuer;
  issuer=$(openssl x509 -in "$cert_file" -noout -issuer -nameopt sep_multiline | grep -i "^ *CN=" | sed 's/^ *CN=//' || true)
  if [[ "$issuer" == "$name" ]]; then
    echo -e "Renewing self-signed Root CA: ${CYAN}${name}${RESET}"
    local days=$DEFAULT_CA_DAYS
    local pass_in;
    pass_in=$(get_ca_pass_in "$name")

    openssl req -x509 -new -key "$key_file" $pass_in -days "$days" -out "${cert_file}.new" -subj "/CN=${name}" -extensions v3_ca -config "$conf_file"
    mv "${cert_file}.new" "$cert_file"
    cp "$cert_file" "$chain_file" 2>/dev/null || true
    echo -e "Root CA renewed at ${GREEN}${cert_file}${RESET}"
  else
    echo -e "Renewing certificate: ${CYAN}${name}${RESET} signed by ${MAGENTA}${issuer}${RESET}"
    resolve_ca "$issuer"
    local ca_pass_in;
    ca_pass_in=$(get_ca_pass_in "$issuer")

    local is_ca;
    is_ca=$(openssl x509 -in "$cert_file" -noout -ext basicConstraints 2>/dev/null | grep -i "CA:TRUE" || true)
    local days=$DEFAULT_CERT_DAYS
    if [[ -n "$is_ca" ]]; then days=$DEFAULT_CA_DAYS; fi
    local is_server;
    is_server=$(openssl x509 -in "$cert_file" -noout -ext extendedKeyUsage 2>/dev/null | grep -Ei "TLS Web Server Authentication" || true)

    local ext="client_cert"
    if [[ -n "$is_ca" ]]; then ext="v3_intermediate_ca"
    elif [[ -n "$is_server" ]]; then ext="server_cert"; fi

    if [[ ! -f "$csr_file" ]]; then
       local pass_in;
       pass_in=$(get_ca_pass_in "$name")
       openssl req -new -key "$key_file" $pass_in -out "$csr_file" -subj "/CN=${name}" -config "$conf_file"
    fi

    openssl x509 -req -in "$csr_file" -CA "$CA_CERT" -CAkey "$CA_KEY" $ca_pass_in -CAcreateserial -out "${cert_file}.new" -days "$days" -extfile "$conf_file" -extensions "$ext"
    mv "${cert_file}.new" "$cert_file"
    cat "$cert_file" "$CA_CHAIN" > "$chain_file" 2>/dev/null || true
    echo -e "Certificate renewed at ${GREEN}${cert_file}${RESET}"
  fi
}

if [[ $# -lt 1 ]]; then
  print_help;
  exit 1;
fi;

COMMAND="$1";
shift;

case "$COMMAND" in
  rootca) cmd_rootca "$@";;
  intermediate) cmd_intermediate "$@";;
  certs) cmd_certs "$@";;
  info) cmd_info "$@";;
  renew) cmd_renew "$@";;
  --help|-h) print_help;;
  *)
    echo "Unknown command: $COMMAND" >&2;
    print_help;
    exit 1;;
esac;
