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
set -eu

echo "🔍 Checking Semgrep rules exist..."

RULE_DIR="semgrep_rules"
RULES="$(ls -1 "$RULE_DIR"/*.yml "$RULE_DIR"/*.yml 2>/dev/null || true)"
[ -n "$RULES" ] || { echo "❌ No rule files found in $RULE_DIR"; exit 1; }

missing=0
for f in $RULES; do
  [ -f "$f" ] || { echo "❌ Missing: $f"; missing=1; }
done
[ "$missing" -eq 0 ] || exit 1

for f in $RULES; do
  echo "▶️  Semgrep scanning: $f"
  docker run --rm -v "$PWD:/src" -w /src \
    -e SEMGREP_BASELINE_COMMIT="$BASELINE" \
    returntocorp/semgrep:latest \
      semgrep scan --metrics=off --config="/src/$f" || true
done

[ "$missing" -eq 0 ] || exit 1

git rev-parse --git-dir >/dev/null 2>&1 || { echo "❌ .git not found"; exit 1; }
git fetch --all --prune --tags || true

if [ -n "${GIT_PREVIOUS_SUCCESSFUL_COMMIT:-}" ]; then
  BASELINE="$GIT_PREVIOUS_SUCCESSFUL_COMMIT"
  echo "🟢 Baseline = last successful build: $BASELINE"
else
  TARGET="${CHANGE_TARGET:-master}"
  git fetch origin "$TARGET:$TARGET" || true
  BASELINE="$(git merge-base "$TARGET" HEAD || true)"
  if [ -z "$BASELINE" ]; then
    # merge-base bulunamazsa HEAD~1'e düş
    BASELINE="$(git rev-parse HEAD~1 || true)"
  fi
  echo "🟡 Baseline fallback: $BASELINE"
fi

git rev-parse --verify "$BASELINE" >/dev/null

if ! git diff --quiet; then
  echo "ℹ️ Unstaged changes detected:"
  git status
  git diff --stat || true
fi

for f in $RULES; do
  echo ""
  echo "=============================="
  echo "▶️  Semgrep scanning: $RULE_DIR/$f"
  echo "=============================="

  docker run --rm \
    -v "$PWD:/src" -w /src \
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
