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
    SSH_CRED = 'app-ssh'          
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

    stage('Deliver image to App VM') {
      steps {
        sshagent(credentials: [env.SSH_CRED]) {
          sh '''
            set -e
            echo "Shipping image to ${APP_HOST} ..."
            docker save ${IMAGE_NAME}:${IMAGE_TAG} | bzip2 | \
            ssh -o StrictHostKeyChecking=no ${APP_USER}@${APP_HOST} 'bunzip2 | docker load'
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
