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

    // --- Snyk config ---
  
    SNYK_CRED = 'snyk-token'
    SNYK_SEVERITY = 'medium'       
    SNYK_CLI = "${env.WORKSPACE}/bin/snyk"
    PATH = "${env.WORKSPACE}/bin:${env.PATH}"
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
          if [ ! -x "${SNYK_CLI}" ]; then
            echo "Downloading Snyk CLI..."
            curl -sSL https://static.snyk.io/cli/latest/snyk-linux -o "${SNYK_CLI}"
            chmod +x "${SNYK_CLI}"
          fi
          "${SNYK_CLI}" --version
        '''
      }
    }

    stage('SCA (Snyk test)') {
      steps {
        withCredentials([string(credentialsId: env.SNYK_CRED, variable: 'SNYK_TOKEN')]) {
          sh '''
            set -e
            echo "Running Snyk SCA (fail on >= ${SNYK_SEVERITY}) ..."
            # Scan all supported manifests in repo (composer, npm, etc.)
            SNYK_TOKEN="$SNYK_TOKEN" "${SNYK_CLI}" test --all-projects --severity-threshold="${SNYK_SEVERITY}"
          '''
        }
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
        withCredentials([string(credentialsId: env.SNYK_CRED, variable: 'SNYK_TOKEN')]) {
          sh '''
            set -e
            echo "Scanning container image with Snyk (fail on >= ${SNYK_SEVERITY}) ..."
            SNYK_TOKEN="$SNYK_TOKEN" "${SNYK_CLI}" container test "${IMAGE_NAME}:${IMAGE_TAG}" \
              --file=Dockerfile \
              --severity-threshold="${SNYK_SEVERITY}"
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
    }
    failure {
      echo "❌ Build/Deploy failed. Check the stage logs."
    }
  }
}
