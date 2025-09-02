pipeline {
  agent any

 options {
  timestamps()
  ansiColor('xterm')
  buildDiscarder(logRotator(numToKeepStr: '30'))
  timeout(time: 30, unit: 'HOURS')
}


  environment {
    // App VM
    APP_HOST   = '192.168.191.132'
    APP_USER   = 'app'
    DEPLOY_DIR = '/opt/dvwa'

    // DAST VM
    DAST_HOST     = '192.168.191.133'
    DAST_USER     = 'dast'
    DAST_SSH_CRED = 'dast_ssh_cred_id'

    // Image
    IMAGE_NAME = 'dvwa-local'
    IMAGE_TAG  = "${env.BUILD_NUMBER}"

    // Reports
    REPORT_DIR  = 'reports'
    REPORT_HTML = 'zap_report.html'
    REPORT_JSON = 'zap_report.json'

    // GitHub Issues
    GITHUB_TOKEN_CRED = 'github_token_cred_id'
    GITHUB_REPO       = 'jullof/DVWA'

    // AI Part
    USE_AI       = 'true'
    SHOW_RECOM   = 'true'
    AI_THRESHOLD = '0.6'                // 0.0–1.0
    OPENAI_MODEL = 'gpt-5'
    OPENAI_BASE  = 'https://api.openai.com/v1/chat/completions'

    // ZAP
    TARGET_URL  = 'http://127.0.0.1:8080'
    FAIL_ON_RISK = 'none'

    // Policy mode env gets set dynamically (abort | freeze)
    DAST_MODE = 'abort'
  }

  stages {

    // ===== 24h policy management (ABORT -> FREEZE) =====
    stage('Policy Mode (24h rule)') {
      steps {
        script {
          def mode = sh(
            returnStdout: true, label: 'compute-policy-mode',
            script: '''
python3 - <<'PY'
import json, os, time, sys
policy_file = "/var/lib/jenkins/dast_policy.json"
now = int(time.time())

# bootstrap if missing
if not os.path.exists(policy_file):
    os.makedirs(os.path.dirname(policy_file), exist_ok=True)
    with open(policy_file, "w", encoding="utf-8") as f:
        json.dump({"window_start": now, "mode": "abort"}, f)

# load & maybe transition to freeze after 24h
with open(policy_file, "r", encoding="utf-8") as f:
    data = json.load(f)

mode = data.get("mode", "abort")
ws   = int(data.get("window_start", now))

if mode == "abort" and (now - ws) >= 86400:  # 24h
    data["mode"] = "freeze"
    mode = "freeze"
    with open(policy_file, "w", encoding="utf-8") as f:
        json.dump(data, f)

print(mode)
PY
''').trim()
          env.DAST_MODE = mode
          echo "DAST_MODE=${env.DAST_MODE}"
        }
      }
    }
    stage('Concurrency Policy') {
  steps {
    script {
      if (env.DAST_MODE == 'abort') {
        // First 24 hour: If new build come abort current one
        properties([disableConcurrentBuilds(abortPrevious: true)])
        echo 'Concurrency: ABORT mode → abortPrevious=TRUE'
      } else {
        // After 24 hour (freeze): No parallel built, but don't stop ongoing 
        properties([disableConcurrentBuilds()])
        echo 'Concurrency: FREEZE mode → abortPrevious=FALSE'
      }
    }
  }
}
  
    stage('Checkout') {
      steps {
        script { if (env.DAST_MODE == 'abort') { milestone(10) } }
        checkout([$class: 'GitSCM',
          branches: [[name: '*/master']],
          userRemoteConfigs: [[url: 'https://github.com/jullof/DVWA.git']]
        ])
      }
    }

    stage('Setup Snyk CLI') {
      steps {
        sh '''
          set -e
          mkdir -p bin
          if [ ! -x "$PWD/bin/snyk" ]; then
            curl -fsSL https://static.snyk.io/cli/latest/snyk-linux -o bin/snyk
            chmod +x bin/snyk
          fi
          "$PWD/bin/snyk" --version
        '''
      }
    }

    stage('SCA (Snyk test)') {
      steps {
        withCredentials([string(credentialsId: 'snyk-token', variable: 'SNYK_TOKEN')]) {
          sh '''
            set -e
            SNYK_TOKEN=$SNYK_TOKEN "$PWD/bin/snyk" test --all-projects --severity-threshold=high \
            --json-file-output=${REPORT_DIR}/snyk_sca.json || true
            '''
        }
      }
    }

    stage('Semgrep (SAST)') {
  steps {
    sh '''
set -eu
RULE_DIR="semgrep_rules"
mkdir -p ${REPORT_DIR}

if [ ! -d "$RULE_DIR" ]; then
  echo "No rule dir, skipping"
  echo '{"results":[]}' > ${REPORT_DIR}/semgrep.json
  exit 0
fi

git rev-parse --git-dir >/dev/null 2>&1 || { echo ".git not found"; exit 1; }
git fetch --all --prune --tags || true

BASELINE=""
if [ -n "${GIT_PREVIOUS_SUCCESSFUL_COMMIT:-}" ] && git rev-parse -q --verify "$GIT_PREVIOUS_SUCCESSFUL_COMMIT" >/dev/null; then
  BASELINE="$GIT_PREVIOUS_SUCCESSFUL_COMMIT"
fi

if [ -n "$BASELINE" ]; then ENV_ARGS="-e SEMGREP_BASELINE_COMMIT=$BASELINE"; else ENV_ARGS=""; fi

docker run --rm -v "$PWD:/src" -w /src $ENV_ARGS semgrep/semgrep:latest \
  semgrep scan --metrics=off \
  --config "/src/$RULE_DIR" \
  --json --output="/src/${REPORT_DIR}/semgrep.json" || true
'''
  }
}


    stage('Build Docker image') {
      steps {
        script { if (env.DAST_MODE == 'abort') { milestone(20) } }
        sh '''
          set -e
          docker build -t ${IMAGE_NAME}:${IMAGE_TAG} .
        '''
      }
    }

    stage('Container scan (Snyk)') {
  steps {
    withCredentials([string(credentialsId: 'snyk-token', variable: 'SNYK_TOKEN')]) {
      sh '''
set -e
mkdir -p ${REPORT_DIR}
SNYK_TOKEN=$SNYK_TOKEN "$PWD/bin/snyk" container test ${IMAGE_NAME}:${IMAGE_TAG} --file=Dockerfile \
  --json-file-output=${REPORT_DIR}/snyk_container.json || true
'''
    }
  }
}


    stage('Send image to DAST VM') {
      steps {
        script { if (env.DAST_MODE == 'abort') { milestone(30) } }
        sshagent(credentials: [env.DAST_SSH_CRED]) {
          sh '''
            set -e
            docker save ${IMAGE_NAME}:${IMAGE_TAG} | gzip | \
              ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes \
                  ${DAST_USER}@${DAST_HOST} 'gunzip | docker load'
          '''
        }
      }
    }

        stage('Run DAST scan on DAST VM') {
  options { timeout(time: 24, unit: 'HOURS') }
  environment {
    ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
    DVWA_USER = "admin"
    DVWA_PASS = "password"
  }
  steps {
    script { if (env.DAST_MODE == 'abort') { milestone(40) } }
    sh 'mkdir -p ${REPORT_DIR}'

    sshagent(credentials: [env.DAST_SSH_CRED]) {
      lock(resource: 'dast-scan', inversePrecedence: true) {
        sh '''
set -e
SSH_OPTS='-o StrictHostKeyChecking=no -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes'

ssh $SSH_OPTS ${DAST_USER}@${DAST_HOST} "export ZAP_IMAGE='${ZAP_IMAGE}'; export IMAGE_NAME='${IMAGE_NAME}'; export IMAGE_TAG='${IMAGE_TAG}'; export TARGET_URL='${TARGET_URL}'; export REPORT_HTML='${REPORT_HTML}'; export REPORT_JSON='${REPORT_JSON}'; export DVWA_USER='${DVWA_USER}'; export DVWA_PASS='${DVWA_PASS}'; bash -s" <<'BASH'
set -eu
mkdir -p ~/dast_wrk

NET="dvwa-net"
DB="dvwa-db"
APP="app-under-test"

echo ">>> Ensure network"
docker network create "$NET" >/dev/null 2>&1 || true

echo ">>> Clean old"
docker rm -f "$APP" "$DB" >/dev/null 2>&1 || true

echo ">>> Start DB (MariaDB)"
docker run -d --name "$DB" --network "$NET" \
  -e MYSQL_ROOT_PASSWORD='p@ssw0rd' \
  -e MYSQL_DATABASE='dvwa' \
  -e MYSQL_USER='dvwa' \
  -e MYSQL_PASSWORD='p@ssw0rd' \
  mariadb:10.6 --default-authentication-plugin=mysql_native_password

echo ">>> Wait DB ready"
until docker exec "$DB" mysql -udvwa -p'p@ssw0rd' -e "SELECT 1" dvwa >/dev/null 2>&1; do
  sleep 2
done

echo ">>> Bring app-under-test up (wired to DB)"
docker run -d --name "$APP" --network "$NET" -p 8080:80 \
  -e DB_SERVER="$DB" \
  -e MYSQL_DATABASE='dvwa' \
  -e MYSQL_USER='dvwa' \
  -e MYSQL_PASSWORD='p@ssw0rd' \
  "${IMAGE_NAME}:${IMAGE_TAG}" || {
  echo "WARN: fallback to public DVWA image"
  docker run -d --name "$APP" --network "$NET" -p 8080:80 \
    -e DB_SERVER="$DB" \
    -e MYSQL_DATABASE='dvwa' \
    -e MYSQL_USER='dvwa' \
    -e MYSQL_PASSWORD='p@ssw0rd' \
    vulnerables/web-dvwa
}

for i in $(seq 1 60); do
  curl -sf "${TARGET_URL}/" >/dev/null && { echo "App is up"; break; }
  sleep 2
done

CJ=~/dast_wrk/c.txt
: > "$CJ"
CURL="curl -sS -L -c $CJ -b $CJ"
BASE="${TARGET_URL}"

echo ">>> setup.php (create/reset DB)"
$CURL -e "$BASE/setup.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "create_db=Create+%2F+Reset+Database" \
  "$BASE/setup.php" >/dev/null || true

if [ "$($CURL -o /dev/null -w '%{http_code}' "$BASE/login.php")" = "200" ]; then
  P=""
elif [ "$($CURL -o /dev/null -w '%{http_code}' "$BASE/dvwa/login.php")" = "200" ]; then
  P="/dvwa"
else
  P=""
fi
echo "PATH_PREFIX='$P'"

echo ">>> Fetch login page & token"
$CURL "$BASE$P/login.php" -o ~/dast_wrk/login.html || true
LTOK=$(grep -oP 'name=["'\\'']user_token["'\\'']\\s+value=["'\\'']\\K[^"\\'']+' ~/dast_wrk/login.html || true)
echo "login token: ${LTOK:-<none>}"

echo ">>> Login (with headers, token if present)"
POST="username=${DVWA_USER}&password=${DVWA_PASS}&Login=Login"
[ -n "$LTOK" ] && POST="$POST&user_token=$LTOK"
$CURL -e "$BASE$P/login.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "$POST" "$BASE$P/login.php" >/dev/null || true

if $CURL "$BASE$P/index.php" | grep -qE "Logout|Welcome"; then
  echo "LOGIN: OK"
else
  echo "LOGIN: FAILED (replacer ile cookie zorlanacak)"
fi

echo ">>> Get security page & token"
$CURL "$BASE$P/security.php" -o ~/dast_wrk/sec.html || true
STOK=$(grep -oP 'name=["'\\'']user_token["'\\'']\\s+value=["'\\'']\\K[^"\\'']+' ~/dast_wrk/sec.html || true)
echo "security token: ${STOK:-<none>}"

echo ">>> Set DVWA security=low"
SPOST="security=low&seclev_submit=Submit"
[ -n "$STOK" ] && SPOST="$SPOST&user_token=$STOK"
$CURL -e "$BASE$P/security.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "$SPOST" "$BASE$P/security.php" >/dev/null || true

LEVEL_TXT=$($CURL "$BASE$P/security.php" | grep -oP 'Security level:\\s*\\K\\w+' || true)
if [ "$LEVEL_TXT" != "low" ]; then
  echo ">>> Fallback GET"
  [ -z "$STOK" ] && STOK=$($CURL "$BASE$P/security.php" | grep -oP 'name=["'\\'']user_token["'\\'']\\s+value=["'\\'']\\K[^"\\'']+' || true)
  $CURL "$BASE$P/security.php?security=low&seclev_submit=Submit${STOK:+&user_token=$STOK}" >/dev/null || true
  LEVEL_TXT=$($CURL "$BASE$P/security.php" | grep -oP 'Security level:\\s*\\K\\w+' || true)
fi

PHPSESSID=$(awk '$6=="PHPSESSID"{print $7}' "$CJ" | tail -n1 || true)
SEC=$(awk '$6=="security"{print $7}' "$CJ" | tail -n1 || true)
echo "Verify -> level=${LEVEL_TXT:-unknown} cookie_security=${SEC:-none} phpsessid=${PHPSESSID:-none}"

echo ">>> Pull ZAP"
docker pull "${ZAP_IMAGE}" || true

echo ">>> Run ZAP scan"
docker run --rm --network host -v ~/dast_wrk:/zap/wrk:rw "${ZAP_IMAGE}" \
  zap-full-scan.py -j \
    -t "${TARGET_URL}" \
    -x ".*logout.*" \
    -r "/zap/wrk/${REPORT_HTML}" \
    -J "/zap/wrk/${REPORT_JSON}" \
    -z "
      -config replacer.full_list(0).description=AddCookie
      -config replacer.full_list(0).enabled=true
      -config replacer.full_list(0).matchtype=REQ_HEADER
      -config replacer.full_list(0).matchstr=Cookie
      -config replacer.full_list(0).regex=false
      -config replacer.full_list(0).replacement=PHPSESSID=${PHPSESSID}; security=low
    " || true
BASH

scp $SSH_OPTS ${DAST_USER}@${DAST_HOST}:"~/dast_wrk/${REPORT_HTML}"  "${REPORT_DIR}/${REPORT_HTML}"  || true
scp $SSH_OPTS ${DAST_USER}@${DAST_HOST}:"~/dast_wrk/${REPORT_JSON}"  "${REPORT_DIR}/${REPORT_JSON}"  || true
'''
      }
    }
  }
}







    stage('Collect & Normalize findings') {
      when {
        expression { env.USE_AI == 'true' }
      }
      steps {
        sh '''set -eu
python3 collector_normalize.py
'''
      }
    }

    stage('AI Triage & Recommend (GPT-5)') {
      when {
        expression { env.USE_AI == 'true' && fileExists("${env.REPORT_DIR}/findings_raw.json") }
      }
      steps {
        withCredentials([string(credentialsId: 'openai_api_key_cred_id', variable: 'OPENAI_API_KEY')]) {
          sh '''set -eu
python3 ai_triage.py
'''
        }
      }
    }

    stage('Publish grouped AI-refined issues') {
      when {
        expression { env.USE_AI == 'true' && fileExists("${env.REPORT_DIR}/ai_findings.json") }
      }
      steps {
        withCredentials([string(credentialsId: env.GITHUB_TOKEN_CRED, variable: 'GITHUB_TOKEN')]) {
          sh '''set -eu
export GH_TOKEN="${GITHUB_TOKEN}"
python3 create_issues_grouped.py
'''
        }
      }
    }


    stage('DAST → App VM: deliver & deploy') {
      steps {
        script { if (env.DAST_MODE == 'abort') { milestone(50) } }
        sshagent(credentials: ['dast_ssh_cred_id', 'app']) {
          sh '''#!/usr/bin/env bash
set -eu
SSH_OPTS="-o StrictHostKeyChecking=no -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes"

# Stream image DAST → APP over SSH (gzip)
ssh $SSH_OPTS ${DAST_USER}@${DAST_HOST} "docker save ${IMAGE_NAME}:${IMAGE_TAG} | gzip -c" \
| ssh $SSH_OPTS ${APP_USER}@${APP_HOST} 'gunzip -c | docker load'

# Deploy compose file & start
ssh $SSH_OPTS ${APP_USER}@${APP_HOST} "mkdir -p ${DEPLOY_DIR}"
scp -o StrictHostKeyChecking=no docker-compose.yml ${APP_USER}@${APP_HOST}:${DEPLOY_DIR}/docker-compose.yml
ssh $SSH_OPTS ${APP_USER}@${APP_HOST} "
  set -eux
  cd ${DEPLOY_DIR}
  IMAGE_NAME=${IMAGE_NAME} IMAGE_TAG=${IMAGE_TAG} docker compose up -d --remove-orphans
"
'''
        }
      }
    }

    stage('Health check (via DAST → APP)') {
      steps {
        sshagent(credentials: [env.DAST_SSH_CRED]) {
          sh '''
set -eu
SSH_OPTS="-o StrictHostKeyChecking=no -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes"
CODE="$(ssh $SSH_OPTS ${DAST_USER}@${DAST_HOST} "curl -s -o /dev/null -w '%{http_code}' http://${APP_HOST}:8080/ || true")"
echo "$CODE" | tee http_code.txt
test "$CODE" = "200" || echo "HTTP ${CODE}"
'''
        }
      }
    }

  } // end stages

post {
  always {
    sh '''python3 - <<'PY'
import json, os, time
policy_file = "/var/lib/jenkins/dast_policy.json"
os.makedirs(os.path.dirname(policy_file), exist_ok=True)
with open(policy_file, "w", encoding="utf-8") as f:
    json.dump({"window_start": int(time.time()), "mode": "abort"}, f)
print("Policy reset: mode=abort, window_start=now")
PY'''
  }

  aborted {
    echo 'Build aborted → Cleaning on DAST VM '
  }

  success {
    echo "DAST → Issues → (DAST→APP) Deploy OK: ${IMAGE_NAME}:${IMAGE_TAG}"
  }

  failure {
    echo "Pipeline failed."
    archiveArtifacts artifacts: "${REPORT_DIR}/*", allowEmptyArchive: true
  }
}
}
