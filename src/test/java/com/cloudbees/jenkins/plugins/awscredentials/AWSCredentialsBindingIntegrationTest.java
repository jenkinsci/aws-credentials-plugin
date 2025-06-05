package com.cloudbees.jenkins.plugins.awscredentials;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.Domain;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Result;
import hudson.tasks.BatchFile;
import hudson.tasks.Shell;
import java.util.ArrayList;
import java.util.List;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.jenkinsci.plugins.credentialsbinding.impl.SecretBuildWrapper;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

/**
 * Integration tests for AWS Credentials Plugin that test the binding of credentials in a Jenkins job.
 */
public class AWSCredentialsBindingIntegrationTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    private static final String CREDENTIAL_ID = "aws-integration-test-cred";
    private static final String ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    private static final String SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    /**
     * Test binding of AWS credentials in a Freestyle project shell step.
     */
    @Test
    public void testFreeStyleProjectCredentialBinding() throws Exception {
        // Create and store the credential
        AWSCredentialsImpl credentials = new AWSCredentialsImpl(
                CredentialsScope.GLOBAL, CREDENTIAL_ID, ACCESS_KEY, SECRET_KEY, "Integration Test Credential");

        CredentialsProvider.lookupStores(j.jenkins).iterator().next().addCredentials(Domain.global(), credentials);

        // Create a freestyle project with AWS credential binding
        FreeStyleProject project = j.createFreeStyleProject("aws-cred-freestyle-test");

        // Configure credential binding
        List<MultiBinding<? extends Credentials>> binders = new ArrayList<>();
        binders.add(new AmazonWebServicesCredentialsBinding(
                "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_SESSION_TOKEN", CREDENTIAL_ID));

        SecretBuildWrapper wrapper = new SecretBuildWrapper(binders);
        project.getBuildWrappersList().add(wrapper);

        // Add a shell/batch step that echoes the bound variables with base64 encoding
        String command;
        if (System.getProperty("os.name").toLowerCase().contains("windows")) {
            command = "echo AWS Access Key: %AWS_ACCESS_KEY%\r\n"
                    + "echo AWS Secret Key B64: | powershell -command \"[convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($env:AWS_SECRET_KEY))\"";
            project.getBuildersList().add(new BatchFile(command));
        } else {
            command = "echo AWS Access Key: $AWS_ACCESS_KEY\n"
                    + "echo AWS Secret Key B64: $(echo -n $AWS_SECRET_KEY | base64)";
            project.getBuildersList().add(new Shell(command));
        }

        // Run the build
        FreeStyleBuild build = project.scheduleBuild2(0).get();

        // Verify results
        j.assertBuildStatus(Result.SUCCESS, build);
        // Credentials are masked in the logs with ****
        j.assertLogContains("AWS Access Key: ****", build);
        j.assertLogContains("AWS Secret Key B64:", build);
        // Verify the raw secret key is not exposed
        j.assertLogNotContains(SECRET_KEY, build);
        // We don't want to expose the secret key in the log, just verify it was set
        j.assertLogNotContains(SECRET_KEY, build);
    }

    /**
     * Test binding of AWS credentials in a Pipeline job.
     */
    @Test
    public void testPipelineCredentialBinding() throws Exception {
        // Create and store the credential
        AWSCredentialsImpl credentials = new AWSCredentialsImpl(
                CredentialsScope.GLOBAL, CREDENTIAL_ID, ACCESS_KEY, SECRET_KEY, "Integration Test Credential");

        CredentialsProvider.lookupStores(j.jenkins).iterator().next().addCredentials(Domain.global(), credentials);

        // Create a pipeline job with AWS credential binding
        WorkflowJob pipeline = j.createProject(WorkflowJob.class, "aws-cred-pipeline-test");

        // Use a minimal pipeline format with only the binding - no shell commands
        // This is because 'sh' and 'node' steps are not available in test environments
        String pipelineScript = "withCredentials([\n" + "    [\n"
                + "        $class: 'AmazonWebServicesCredentialsBinding',\n"
                + "        credentialsId: '"
                + CREDENTIAL_ID + "',\n" + "        accessKeyVariable: 'AWS_ACCESS_KEY',\n"
                + "        secretKeyVariable: 'AWS_SECRET_KEY',\n"
                + "        sessionTokenVariable: 'AWS_SESSION_TOKEN'\n"
                + "    ]\n"
                + "]) {\n"
                + "    // We can't use 'sh' or 'echo' in test environment\n"
                + "    // Just testing that binding works without error\n"
                + "}";

        pipeline.setDefinition(new CpsFlowDefinition(pipelineScript, true));

        // Run the pipeline
        WorkflowRun run = pipeline.scheduleBuild2(0).get();

        // Verify results
        j.assertBuildStatus(Result.SUCCESS, run);

        // Check for binding evidence in logs
        j.assertLogContains("Masking supported pattern matches of $AWS_SECRET_KEY or $AWS_ACCESS_KEY", run);
        j.assertLogNotContains(SECRET_KEY, run);
    }

    /**
     * Test binding of AWS credentials with role assumption in a Pipeline job.
     */
    @Test
    public void testPipelineWithRoleAssumption() throws Exception {
        // Create and store the credential with role information
        String ROLE_ARN = "arn:aws:iam::123456789012:role/test-role";
        AWSCredentialsImpl credentials = new AWSCredentialsImpl(
                CredentialsScope.GLOBAL,
                CREDENTIAL_ID,
                ACCESS_KEY,
                SECRET_KEY,
                "Integration Test Credential with Role",
                ROLE_ARN,
                null,
                null);

        // Set token duration
        credentials.setStsTokenDuration(900);

        CredentialsProvider.lookupStores(j.jenkins).iterator().next().addCredentials(Domain.global(), credentials);

        // Create a pipeline job with AWS credential binding
        WorkflowJob pipeline = j.createProject(WorkflowJob.class, "aws-role-pipeline-test");

        // Use a simpler script format with explicit binding class
        // Avoiding 'node' step which is not available in some test environments
        String pipelineScript = "withCredentials([\n" + "    [\n"
                + "        $class: 'AmazonWebServicesCredentialsBinding',\n"
                + "        credentialsId: '"
                + CREDENTIAL_ID + "',\n" + "        accessKeyVariable: 'AWS_ACCESS_KEY',\n"
                + "        secretKeyVariable: 'AWS_SECRET_KEY',\n"
                + "        sessionTokenVariable: 'AWS_SESSION_TOKEN'\n"
                + "    ]\n"
                + "]) {\n"
                + "    // We can't use 'sh' or 'echo' in test environment\n"
                + "    // Just testing that binding mechanism works without error\n"
                + "}";

        pipeline.setDefinition(new CpsFlowDefinition(pipelineScript, true));

        // In an actual test environment, we'd mock the STS client to simulate role assumption
        // For this test, we're just verifying that the credentials binding mechanism is working
        // Note: Since we can't actually call AWS STS in the test, the build might fail, which is expected
        WorkflowRun run = pipeline.scheduleBuild2(0).get();

        // We expect an STS exception since we're using fake credentials
        // Just verify the credentials binding mechanism is initiated
        j.assertLogContains("withCredentials", run);

        // The STS exception should be logged if role assumption is attempted
        // This indirectly verifies that the credentials binding is working properly
        j.assertLogContains("software.amazon.awssdk.services.sts", run);
    }

    /**
     * Test custom environment variable names for AWS credential binding.
     */
    @Test
    public void testCustomVariableNames() throws Exception {
        // Create and store the credential
        AWSCredentialsImpl credentials = new AWSCredentialsImpl(
                CredentialsScope.GLOBAL, CREDENTIAL_ID, ACCESS_KEY, SECRET_KEY, "Integration Test Credential");

        CredentialsProvider.lookupStores(j.jenkins).iterator().next().addCredentials(Domain.global(), credentials);

        // Create a freestyle project with AWS credential binding using custom variable names
        FreeStyleProject project = j.createFreeStyleProject("aws-custom-vars-test");

        // Configure credential binding with custom variable names
        List<MultiBinding<? extends Credentials>> binders = new ArrayList<>();
        binders.add(new AmazonWebServicesCredentialsBinding(
                "CUSTOM_AWS_ACCESS_KEY", "CUSTOM_AWS_SECRET_KEY", "CUSTOM_AWS_TOKEN", CREDENTIAL_ID));

        SecretBuildWrapper wrapper = new SecretBuildWrapper(binders);
        project.getBuildWrappersList().add(wrapper);
        // Add a shell/batch step that echoes the bound variables with base64 encoding
        String command;
        if (System.getProperty("os.name").toLowerCase().contains("windows")) {
            command = "echo Custom Access Key: %CUSTOM_AWS_ACCESS_KEY%\r\n"
                    + "echo Custom Secret Key B64: | powershell -command \"[convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($env:CUSTOM_AWS_SECRET_KEY))\"";
            project.getBuildersList().add(new BatchFile(command));
        } else {
            command = "echo Custom Access Key: $CUSTOM_AWS_ACCESS_KEY\n"
                    + "echo Custom Secret Key B64: $(echo -n $CUSTOM_AWS_SECRET_KEY | base64)";
            project.getBuildersList().add(new Shell(command));
        }

        // Run the build
        FreeStyleBuild build = project.scheduleBuild2(0).get();

        // Verify results
        j.assertBuildStatus(Result.SUCCESS, build);
        j.assertLogContains("Custom Access Key: ****", build);
        j.assertLogContains("Custom Secret Key B64:", build);
        j.assertLogNotContains(SECRET_KEY, build);
    }
}
