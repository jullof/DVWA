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
RULES="$(ls -1 "$RULE_DIR"/*.yml "$RULE_DIR"/*.yaml 2>/dev/null | sort -u || true)"
[ -n "$RULES" ] || { echo "❌ No rule files found in $RULE_DIR"; exit 1; }

git rev-parse --git-dir >/dev/null 2>&1 || { echo "❌ .git not found"; exit 1; }
git fetch --all --prune --tags || true

BASELINE=""
if [ -n "${GIT_PREVIOUS_SUCCESSFUL_COMMIT:-}" ] && git rev-parse -q --verify "$GIT_PREVIOUS_SUCCESSFUL_COMMIT" >/dev/null; then
  BASELINE="$GIT_PREVIOUS_SUCCESSFUL_COMMIT"
  echo "🟢 Using last successful commit as baseline: $BASELINE"
else
  echo "⚠️ No previous successful build commit available; running without baseline"
fi

if [ -n "$BASELINE" ]; then
  ENV_ARGS="-e SEMGREP_BASELINE_COMMIT=$BASELINE"
else
  ENV_ARGS=""
fi

if ! git diff --quiet; then
  echo "ℹ️ Unstaged changes present:"
  git status
  git diff --stat || true
fi

for f in $RULES; do
  echo ""
  echo "=============================="
  echo "▶️  Semgrep scanning: $f"
  echo "=============================="
  docker run --rm -v "$PWD:/src" -w /src $ENV_ARGS \
    semgrep/semgrep:latest \
      semgrep scan --metrics=off --config="/src/$f" || true
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
