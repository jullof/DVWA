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
    DEPLOY_DIR = '/opt/app'

    // DAST VM
    DAST_HOST     = '192.168.191.133'
    DAST_USER     = 'dast'
    DAST_SSH_CRED = 'dast_ssh_cred_id'

    // Image
    IMAGE_NAME = 'app-local'
    IMAGE_TAG  = "${env.BUILD_NUMBER}"

    // Reports
    REPORT_DIR  = 'reports'
    REPORT_HTML = 'zap_report.html'
    REPORT_JSON = 'zap_report.json'

    // GitHub Issues
    GITHUB_TOKEN_CRED = 'github_token_cred_id'
    GITHUB_REPO       = 'jullof/DVWA'  // Update with your actual repo name

    // AI Configuration
    USE_AI       = 'true'
    SHOW_RECOM   = 'true'
    AI_THRESHOLD = '0.6'
    OPENAI_MODEL = 'gpt-5'
    OPENAI_BASE  = 'https://api.openai.com/v1/chat/completions'

    // DAST Configuration
    TARGET_URL     = 'http://127.0.0.1:8080'
    FAIL_ON_RISK   = 'none'
    APP_CONTEXT    = ''  // Application context path (e.g., '/api', '/app')
    
    // Authentication (if needed)
    APP_LOGIN_URL     = ''  // Login endpoint if authentication required
    APP_USERNAME      = ''  // Application username
    APP_PASSWORD      = ''  // Application password
    
    // Health check endpoint
    HEALTH_CHECK_PATH = '/'  // Health check path

    // Policy mode (abort | freeze)
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
            // First 24 hours: If new build comes, abort current one
            properties([disableConcurrentBuilds(abortPrevious: true)])
            echo 'Concurrency: ABORT mode → abortPrevious=TRUE'
          } else {
            // After 24 hours (freeze): No parallel builds, but don't stop ongoing 
            properties([disableConcurrentBuilds()])
            echo 'Concurrency: FREEZE mode → abortPrevious=FALSE'
          }
        }
      }
    }
  //
    stage('Checkout') {
      steps {
        script { if (env.DAST_MODE == 'abort') { milestone(10) } }
        // Generic SCM checkout - will use the configured SCM in Jenkins job
        checkout scm
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
            mkdir -p ${REPORT_DIR}
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
  echo "No rule directory found, using default rules"
  RULE_CONFIG="--config=auto"
else
  RULE_CONFIG="--config=/src/$RULE_DIR"
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
  $RULE_CONFIG \
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
      }
      steps {
        script { if (env.DAST_MODE == 'abort') { milestone(40) } }
        sh 'mkdir -p ${REPORT_DIR}'

        sshagent(credentials: [env.DAST_SSH_CRED]) {
          lock(resource: 'dast-scan', inversePrecedence: true) {
            sh '''
set -e
SSH_OPTS='-o StrictHostKeyChecking=no -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes'

ssh $SSH_OPTS ${DAST_USER}@${DAST_HOST} "export ZAP_IMAGE='${ZAP_IMAGE}'; export IMAGE_NAME='${IMAGE_NAME}'; export IMAGE_TAG='${IMAGE_TAG}'; export TARGET_URL='${TARGET_URL}'; export REPORT_HTML='${REPORT_HTML}'; export REPORT_JSON='${REPORT_JSON}'; export APP_CONTEXT='${APP_CONTEXT}'; export APP_LOGIN_URL='${APP_LOGIN_URL}'; export APP_USERNAME='${APP_USERNAME}'; export APP_PASSWORD='${APP_PASSWORD}'; bash -s" <<'BASH'
set -eu
mkdir -p ~/dast_wrk

NET="app-net"
APP="app-under-test"

echo ">>> Ensure network"
docker network create "$NET" >/dev/null 2>&1 || true

echo ">>> Clean old containers"
docker rm -f "$APP" >/dev/null 2>&1 || true

echo ">>> Start application under test"
docker run -d --name "$APP" --network "$NET" -p 8080:8080 \
  "${IMAGE_NAME}:${IMAGE_TAG}"

# Wait for application to be ready
echo ">>> Waiting for application to be ready..."
for i in $(seq 1 60); do
  if curl -sf "${TARGET_URL}${APP_CONTEXT}/" >/dev/null 2>&1; then
    echo "Application is ready"
    break
  fi
  echo "Waiting for application... ($i/60)"
  sleep 5
done

# Optional: Handle authentication if credentials are provided
AUTH_CONFIG=""
if [ -n "${APP_LOGIN_URL:-}" ] && [ -n "${APP_USERNAME:-}" ] && [ -n "${APP_PASSWORD:-}" ]; then
  echo ">>> Setting up authentication context"
  CJ=~/dast_wrk/cookies.txt
  : > "$CJ"
  
  # Basic login attempt - customize based on your application
  curl -sS -L -c "$CJ" -b "$CJ" \
    -d "username=${APP_USERNAME}&password=${APP_PASSWORD}" \
    "${TARGET_URL}${APP_LOGIN_URL}" || true
    
  # Extract session information if needed
  if [ -f "$CJ" ]; then
    COOKIES=$(awk 'NF==7 && $1!~/^#/ {printf "%s=%s; ", $6, $7}' "$CJ" | sed 's/; $//')
    if [ -n "$COOKIES" ]; then
      AUTH_CONFIG="-config replacer.full_list(0).description=AddAuthCookie
        -config replacer.full_list(0).enabled=true
        -config replacer.full_list(0).matchtype=REQ_HEADER
        -config replacer.full_list(0).matchstr=Cookie
        -config replacer.full_list(0).regex=false
        -config 'replacer.full_list(0).replacement=${COOKIES}'"
    fi
  fi
fi

echo ">>> Pull ZAP image"
docker pull "${ZAP_IMAGE}" || true

echo ">>> Run ZAP DAST scan"
docker run --rm --network host -v ~/dast_wrk:/zap/wrk:rw "${ZAP_IMAGE}" \
  zap-full-scan.py -j \
    -t "${TARGET_URL}${APP_CONTEXT}" \
    -x ".*logout.*" \
    -r "/zap/wrk/${REPORT_HTML}" \
    -J "/zap/wrk/${REPORT_JSON}" \
    ${AUTH_CONFIG:+-z "$AUTH_CONFIG"} || true

echo ">>> DAST scan completed"
BASH

# Copy reports back to Jenkins
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

    stage('AI Triage & Recommend') {
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

    stage('Deploy to App VM') {
      steps {
        script { if (env.DAST_MODE == 'abort') { milestone(50) } }
        sshagent(credentials: ['dast_ssh_cred_id', 'app']) {
          sh '''#!/usr/bin/env bash
set -eu
SSH_OPTS="-o StrictHostKeyChecking=no -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes"

# Stream image DAST → APP over SSH (compressed)
ssh $SSH_OPTS ${DAST_USER}@${DAST_HOST} "docker save ${IMAGE_NAME}:${IMAGE_TAG} | gzip -c" \
| ssh $SSH_OPTS ${APP_USER}@${APP_HOST} 'gunzip -c | docker load'

# Deploy application
ssh $SSH_OPTS ${APP_USER}@${APP_HOST} "mkdir -p ${DEPLOY_DIR}"

# Copy deployment files if they exist
if [ -f "docker-compose.yml" ]; then
  scp -o StrictHostKeyChecking=no docker-compose.yml ${APP_USER}@${APP_HOST}:${DEPLOY_DIR}/docker-compose.yml
  ssh $SSH_OPTS ${APP_USER}@${APP_HOST} "
    set -eux
    cd ${DEPLOY_DIR}
    IMAGE_NAME=${IMAGE_NAME} IMAGE_TAG=${IMAGE_TAG} docker compose up -d --remove-orphans
  "
elif [ -f "k8s-deployment.yaml" ]; then
  # Kubernetes deployment example
  scp -o StrictHostKeyChecking=no k8s-deployment.yaml ${APP_USER}@${APP_HOST}:${DEPLOY_DIR}/
  ssh $SSH_OPTS ${APP_USER}@${APP_HOST} "
    cd ${DEPLOY_DIR}
    sed -i 's|IMAGE_PLACEHOLDER|${IMAGE_NAME}:${IMAGE_TAG}|g' k8s-deployment.yaml
    kubectl apply -f k8s-deployment.yaml
  "
else
  # Simple docker run fallback
  ssh $SSH_OPTS ${APP_USER}@${APP_HOST} "
    docker stop app-container 2>/dev/null || true
    docker rm app-container 2>/dev/null || true
    docker run -d --name app-container -p 8080:8080 ${IMAGE_NAME}:${IMAGE_TAG}
  "
fi
'''
        }
      }
    }

    stage('Health check') {
      steps {
        sshagent(credentials: [env.DAST_SSH_CRED]) {
          sh '''
set -eu
SSH_OPTS="-o StrictHostKeyChecking=no -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes"

# Health check via DAST VM → APP VM
for i in $(seq 1 30); do
  CODE="$(ssh $SSH_OPTS ${DAST_USER}@${DAST_HOST} "curl -s -o /dev/null -w '%{http_code}' http://${APP_HOST}:8080${HEALTH_CHECK_PATH} || echo 'ERROR'")"
  echo "Health check attempt $i: HTTP $CODE"
  
  if [ "$CODE" = "200" ]; then
    echo "✅ Health check passed"
    exit 0
  fi
  
  sleep 10
done

echo "❌ Health check failed after 30 attempts"
exit 1
'''
        }
      }
    }

  } // end stages

  post {
    always {
      // Reset policy after build completion
      sh '''python3 - <<'PY'
import json, os, time
policy_file = "/var/lib/jenkins/dast_policy.json"
os.makedirs(os.path.dirname(policy_file), exist_ok=True)
with open(policy_file, "w", encoding="utf-8") as f:
    json.dump({"window_start": int(time.time()), "mode": "abort"}, f)
print("Policy reset: mode=abort, window_start=now")
PY'''

      // Archive reports
      archiveArtifacts artifacts: "${REPORT_DIR}/*", allowEmptyArchive: true
      
      // Publish test results if available
      script {
        if (fileExists("${REPORT_DIR}/${REPORT_HTML}")) {
          publishHTML([
            allowMissing: false,
            alwaysLinkToLastBuild: true,
            keepAll: true,
            reportDir: env.REPORT_DIR,
            reportFiles: env.REPORT_HTML,
            reportName: 'DAST Security Report'
          ])
        }
      }
    }

    aborted {
      echo 'Build aborted → Cleaning resources on DAST VM'
      // Optional: Add cleanup scripts here
    }

    success {
      echo "✅ DevSecOps Pipeline completed successfully: ${IMAGE_NAME}:${IMAGE_TAG}"
    }

    failure {
      echo "❌ Pipeline failed. Check logs and reports for details."
    }
  }
}