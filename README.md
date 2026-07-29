AWS Credentials Plugin
=========

- Allows storing Amazon IAM credentials within the Jenkins Credentials API.
- Store Amazon IAM access keys (AWSAccessKeyId and AWSSecretKey) within the Jenkins Credentials API.
- Also supports IAM Roles and IAM MFA Token.

# Usage

## Rotating AWS Credentials

AWS access keys should be rotated regularly for security best practices.

To rotate credentials stored in Jenkins:

1. Create a new access key in AWS IAM
2. In Jenkins, open **Manage Jenkins → Credentials**
3. Locate the existing AWS credential
4. Click **Update**
5. Replace the Access Key ID and Secret Access Key
6. Save the credential
7. Verify jobs or pipelines using the credential

Pipelines referencing the credential ID do not need to be modified
after rotation.

# Sample Pipeline Usage

**AWS Credential, this example will automatically setup environment variables AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY**

```groovy
  withCredentials([[ $class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'my_aws_credential']]){
```

**To assign values to custom variables**

```groovy
  withCredentials([[ $class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'my_aws_credential', accessKeyVariable: 'CUSTOM_AWS_ACCESS_KEY_ID', secretKeyVariable: 'CUSTOM_AWS_SECRET_ACCESS_KEY']]){
```

**Assume a role, this example will automatically setup environment variables AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY & AWS_SESSION_TOKEN**

```groovy
    withCredentials([[ $class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'plt-ia-dev-images-ecr-use1-read', roleArn: 'arn:aws:iam::130312249203:role/PullDockerImages']]){
      sh "aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin  ecr_registry
    }
```

**Assume a role and specify a role session name**

```groovy
    withCredentials([[ $class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'plt-ia-dev-images-ecr-use1-read', roleArn: 'arn:aws:iam::130312249203:role/PullDockerImages', roleSessionName: 'PullDockerImages']]){
      sh "aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin  ecr_registry
```

For more information review [this PR](https://github.com/jenkinsci/aws-credentials-plugin/pull/81).
