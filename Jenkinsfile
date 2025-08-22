pipeline {
  agent any

  options {
    timestamps()
    ansiColor('xterm')
    timeout(time: 20, unit: 'MINUTES')
  }

  environment {
    APP_HOST = '192.168.191.132'
    APP_USER = 'app'
    SSH_CRED = 'app'                  
    IMAGE_NAME = 'dvwa-local'
    IMAGE_TAG  = "${env.BUILD_NUMBER}"
    DEPLOY_DIR = '/opt/dvwa'
  }

  stages {

    stage('Checkout') {
      steps {
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
            echo "Running Snyk SCA (fail on high) ..."
            SNYK_TOKEN=$SNYK_TOKEN "$PWD/bin/snyk" test --all-projects --severity-threshold=high
          '''
        }
      }
    }

stage('Semgrep (SAST - alerts only)') {
  steps {
    sh '''
#!/usr/bin/env bash
set -eu

echo "🔍 Checking Semgrep rules exist..."

RULE_DIR="semgrep_rules"
RULES="semgrep-dvwa-xss.yml semgrep-dvwa-rce.yml semgrep-dvwa-sql.yml"

# Ensure rule dir & files exist
if [ ! -d "$RULE_DIR" ]; then
  echo "❌ $RULE_DIR/ directory is missing!"
  ls -la
  exit 1
fi

missing=0
for f in "${RULES[@]}"; do
  if [ ! -f "$RULE_DIR/$f" ]; then
    echo "❌ Missing rule file: $RULE_DIR/$f"
    missing=1
  fi
done
[ "$missing" -eq 0 ] || exit 1

# Repo history (for baseline)
git fetch --all --prune --tags || true

# Baseline: last successful build or merge-base with target
if [ -n "${GIT_PREVIOUS_SUCCESSFUL_COMMIT:-}" ]; then
  BASELINE="$GIT_PREVIOUS_SUCCESSFUL_COMMIT"
  echo "🟢 Baseline = last successful build: $BASELINE"
else
  TARGET="${CHANGE_TARGET:-master}"
  git fetch origin "$TARGET:$TARGET" || true
  BASELINE="$(git merge-base "$TARGET" HEAD)"
  echo "🟡 Baseline fallback = merge-base($TARGET, HEAD): $BASELINE"
fi

# Show local diffs (debug)
if ! git diff --quiet; then
  echo "ℹ️ Workspace has unstaged changes; showing diff for debugging:"
  git status
  git diff --stat || true
fi

git rev-parse --verify "$BASELINE" >/dev/null

# Run each ruleset separately (alerts-only)
for f in "${RULES[@]}"; do
  echo ""
  echo "=============================="
  echo "▶️  Semgrep scanning: $RULE_DIR/$f"
  echo "=============================="
  docker run --rm -v "$PWD:/src" -w /src \
    -e SEMGREP_BASELINE_COMMIT="$BASELINE" \
    returntocorp/semgrep:latest \
      semgrep scan --metrics=off --config="/src/$RULE_DIR/$f" || true
done
'''
  }
}

    stage('Build Docker image') {
      steps {
        sh '''
          set -e
          docker version
          echo "Building image: ${IMAGE_NAME}:${IMAGE_TAG}"
          docker build -t ${IMAGE_NAME}:${IMAGE_TAG} .
        '''
      }
    }

    stage('Container scan (Snyk)') {
      steps {
        withCredentials([string(credentialsId: 'snyk-token', variable: 'SNYK_TOKEN')]) {
          sh '''
            set -e
            echo "Scanning container image with Snyk (fail on >= medium) ..."
            SNYK_TOKEN=$SNYK_TOKEN "$PWD/bin/snyk" container test ${IMAGE_NAME}:${IMAGE_TAG} \
              --file=Dockerfile --severity-threshold=medium
          '''
        }
      }
    }

    stage('Deliver image to App VM') {
      steps {
        sshagent(credentials: [env.SSH_CRED]) {
          sh '''
            set -e
            echo "Shipping image to ${APP_HOST} ..."
            docker save ${IMAGE_NAME}:${IMAGE_TAG} | gzip | \
              ssh -o StrictHostKeyChecking=no ${APP_USER}@${APP_HOST} 'gunzip | docker load'
          '''
        }
      }
    }

    stage('Deploy (docker compose up)') {
      steps {
        sshagent(credentials: [env.SSH_CRED]) {
          sh '''
            set -e
            echo "Preparing ${DEPLOY_DIR} on ${APP_HOST} ..."
            ssh -o StrictHostKeyChecking=no ${APP_USER}@${APP_HOST} "mkdir -p ${DEPLOY_DIR}"

            echo "Copying compose file ..."
            scp -o StrictHostKeyChecking=no docker-compose.yml \
                ${APP_USER}@${APP_HOST}:${DEPLOY_DIR}/docker-compose.yml

            echo "Compose up ..."
            ssh -o StrictHostKeyChecking=no ${APP_USER}@${APP_HOST} "\
              cd ${DEPLOY_DIR} && \
              IMAGE_NAME=${IMAGE_NAME} IMAGE_TAG=${IMAGE_TAG} \
              docker compose up -d --remove-orphans"
          '''
        }
      }
    }

    stage('Health check') {
      steps {
        sshagent(credentials: [env.SSH_CRED]) {
          sh '''
            set +e
            echo "Waiting app to respond ..."
            ssh -o StrictHostKeyChecking=no ${APP_USER}@${APP_HOST} \
              "sleep 3 && curl -s -o /dev/null -w '%{http_code}\\n' http://localhost:8080/" | tee http_code.txt
            CODE=$(cat http_code.txt)
            test "$CODE" = "200" || echo "HTTP ${CODE}"
          '''
        }
      }
    }
  } 


  post {
    success {
      echo "✅ Deployed ${IMAGE_NAME}:${IMAGE_TAG} → http://${APP_HOST}:8080"
      archiveArtifacts artifacts: 'semgrep.sarif', onlyIfSuccessful: true, allowEmptyArchive: true
    }
    failure {
      echo "❌ Build/Deploy failed. Check the stage logs."
      archiveArtifacts artifacts: 'semgrep.sarif', onlyIfSuccessful: false, allowEmptyArchive: true
    }
  }
}
