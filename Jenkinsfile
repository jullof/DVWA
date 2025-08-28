pipeline {
  agent any

  options {
    timestamps()
    ansiColor('xterm')
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '30'))
    timeout(time: 30, unit: 'HOURS')
  }

  environment {
    APP_HOST = '192.168.191.132'
    APP_USER = 'app'
    DEPLOY_DIR = '/opt/dvwa'

    DAST_HOST = '192.168.191.133'
    DAST_USER = 'dast'
    DAST_SSH_CRED = 'dast_ssh_cred_id'

    IMAGE_NAME = 'dvwa-local'
    IMAGE_TAG  = "${env.BUILD_NUMBER}"

    REPORT_DIR  = 'reports'
    REPORT_HTML = 'zap_report.html'
    REPORT_JSON = 'zap_report.json'

    GITHUB_TOKEN_CRED = 'github_token_cred_id'
    GITHUB_REPO = 'jullof/DVWA'

    TARGET_URL = 'http://127.0.0.1:8080'
    FAIL_ON_RISK = 'none'
  }

  stages {

    stage('Checkout') {
      steps {
        milestone(10)
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
            SNYK_TOKEN=$SNYK_TOKEN "$PWD/bin/snyk" test --all-projects --severity-threshold=high
          '''
        }
      }
    }

    stage('Semgrep (SAST - alerts only)') {
      steps {
        sh '''
set -eu
RULE_DIR="semgrep_rules"
RULES="$(ls -1 "$RULE_DIR"/*.yml "$RULE_DIR"/*.yaml 2>/dev/null | sort -u || true)"
[ -n "$RULES" ] || { echo "No rule files in $RULE_DIR"; exit 0; }
git rev-parse --git-dir >/dev/null 2>&1 || { echo ".git not found"; exit 1; }
git fetch --all --prune --tags || true
BASELINE=""
if [ -n "${GIT_PREVIOUS_SUCCESSFUL_COMMIT:-}" ] && git rev-parse -q --verify "$GIT_PREVIOUS_SUCCESSFUL_COMMIT" >/dev/null; then
  BASELINE="$GIT_PREVIOUS_SUCCESSFUL_COMMIT"
fi
if [ -n "$BASELINE" ]; then ENV_ARGS="-e SEMGREP_BASELINE_COMMIT=$BASELINE"; else ENV_ARGS=""; fi
for f in $RULES; do
  docker run --rm -v "$PWD:/src" -w /src $ENV_ARGS semgrep/semgrep:latest semgrep scan --metrics=off --config="/src/$f" || true
done
'''
      }
    }

    stage('Build Docker image') {
      steps {
        milestone(20)
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
            SNYK_TOKEN=$SNYK_TOKEN "$PWD/bin/snyk" container test ${IMAGE_NAME}:${IMAGE_TAG} --file=Dockerfile --severity-threshold=medium
          '''
        }
      }
    }

    stage('Send image to DAST VM') {
      steps {
        milestone(30)
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
  steps {
    milestone(40)
    sh "mkdir -p ${REPORT_DIR}"

    sshagent(credentials: [env.DAST_SSH_CRED]) {
      lock(resource: 'dast-scan') {
        sh '''
          set -eux
          SSH_OPTS="-o StrictHostKeyChecking=no -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes"

          ssh $SSH_OPTS ${DAST_USER}@${DAST_HOST} "
            set -eux
            mkdir -p ~/dast_wrk
            docker pull ghcr.io/zaproxy/zaproxy:stable || true
            docker rm -f app-under-test || true
            docker run -d --name app-under-test -p 8080:80 ${IMAGE_NAME}:${IMAGE_TAG}
            sleep 15
            docker run --rm --network host -v ~/dast_wrk:/zap/wrk:rw \
              ghcr.io/zaproxy/zaproxy:stable \
              zap-baseline.py -t ${TARGET_URL} \
                -r ${REPORT_HTML} \
                -J ${REPORT_JSON} \
                -m 5 -I
          "

          scp $SSH_OPTS ${DAST_USER}@${DAST_HOST}:"~/dast_wrk/${REPORT_HTML}"  "${REPORT_DIR}/${REPORT_HTML}"  || true
          scp $SSH_OPTS ${DAST_USER}@${DAST_HOST}:"~/dast_wrk/${REPORT_JSON}"  "${REPORT_DIR}/${REPORT_JSON}"  || true
        '''
      }
    }
  }
  post {
    always {
      publishHTML(target: [
        reportDir: "${REPORT_DIR}",
        reportFiles: "${REPORT_HTML}",
        reportName: "ZAP DAST Report",
        keepAll: true,
        alwaysLinkToLastBuild: true
      ])
      archiveArtifacts artifacts: "${REPORT_DIR}/*", fingerprint: true, allowEmptyArchive: false
    }
    unsuccessful {
      echo 'DAST scan failed or timed out.'
    }
  }
}

stage('Parse report & create GitHub issues') {
  when { expression { fileExists("${REPORT_DIR}/${REPORT_JSON}") } }
  steps {
    milestone(45)
    withCredentials([string(credentialsId: env.GITHUB_TOKEN_CRED, variable: 'GITHUB_TOKEN')]) {
      sh '''#!/usr/bin/env bash
set -eu
export GH_TOKEN="${GITHUB_TOKEN}"

gh --version
gh api user >/dev/null 2>&1 || { echo "GH token invalid or gh not installed"; exit 1; }

for L in "ZAP" "risk:high" "risk:medium" "risk:low" "risk:informational"; do
  gh label create "$L" -R "${GITHUB_REPO}" -c "CCCCCC" || true
done

ASSIGNEE="$(gh api repos/${GITHUB_REPO}/commits/${GIT_COMMIT} --jq '.author.login // .committer.login // ""' || true)"
[ -z "$ASSIGNEE" ] && ASSIGNEE="jullof"
export ASSIGNEE

cat > parse_zap_and_create_issues.py <<'PY'
import json, os, subprocess, sys

repo     = os.environ["GITHUB_REPO"]
report   = os.path.join(os.environ["REPORT_DIR"], os.environ["REPORT_JSON"])
fail_on  = os.environ.get("FAIL_ON_RISK","none").lower()
assignee = os.environ.get("ASSIGNEE") or None

def risk_level(r):
    return {"informational":0,"low":1,"medium":2,"high":3}.get((r or "").lower(),0)

with open(report, "r", encoding="utf-8") as f:
    data = json.load(f)

alerts = []
for site in data.get("site", []):
    base = site.get("@name") or site.get("name") or ""
    for a in site.get("alerts", []):
        risk = (a.get("risk") or a.get("riskdesc") or "Informational").split()[0]
        name = a.get("alert","")
        desc = (a.get("desc") or "").strip()
        sol  = (a.get("solution") or "").strip()
        inst = a.get("instances") or []
        first_url = "N/A"
        for i in inst:
            u = i.get("uri") or i.get("url")
            if u:
                first_url = u
                break
        alerts.append({
            "risk": risk,
            "title": name,
            "url": first_url,
            "desc": desc,
            "solution": sol,
            "base": base,
            "count": len(inst),
        })

max_risk, created = 0, 0

def exists_issue(repo, title):
    q = f'title:"{title}" state:open label:ZAP'
    out = subprocess.run(
        ["gh","issue","list","-R",repo,"--search",q,"--json","number"],
        capture_output=True, text=True
    )
    return '"number":' in (out.stdout or "")

def create_issue(repo, title, body, labels, assignee):
    cmd = ["gh","issue","create","-R",repo,"-t",title,"-b",body]
    for lb in labels:
        cmd += ["-l", lb]
    if assignee:
        cmd += ["--assignee", assignee]
    subprocess.run(cmd, check=True)

for it in alerts:
    max_risk = max(max_risk, risk_level(it["risk"]))
    title = f"[ZAP] {it['title']} - {it['url']} (risk: {it['risk']})"
    if exists_issue(repo, title):
        print("Skip (exists):", title)
        continue
    body = f"""Automated ZAP finding

**Alert:** {it['title']}
**Risk:** {it['risk']}
**Base:** {it['base']}
**First URL:** {it['url']}
**Occurrences:** {it['count']}

**Description:**
{it['desc']}

**Suggested solution:**
{it['solution']}
"""
    labels = ["ZAP", f"risk:{it['risk'].lower()}"]
    print("Creating:", title)
    create_issue(repo, title, body, labels, assignee)
    created += 1

print(f"Created {created} issues.")

gate = {"none":99, "medium":2, "high":3}.get(fail_on, 99)
if max_risk >= gate:
    sys.exit(2)
PY

python3 parse_zap_and_create_issues.py
'''
    }
  }
}





stage('DAST → App VM: deliver & deploy') {
  steps {
    milestone(50)
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
    success {
      echo "DAST → Issues → (DAST→APP) Deploy OK: ${IMAGE_NAME}:${IMAGE_TAG}"
    }
    failure {
      echo "Pipeline failed."
      archiveArtifacts artifacts: "${REPORT_DIR}/*", allowEmptyArchive: true
    }
  }
}
