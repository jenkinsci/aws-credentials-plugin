package com.cloudbees.jenkins.plugins.awscredentials;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Set;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * Simple unit tests for AmazonWebServicesCredentialsBinding that don't require the Jenkins infrastructure.
 */
@RunWith(MockitoJUnitRunner.class)
public class AWSCredentialsBindingTest {

    @Test
    public void testCustomSessionTokenVariable() {
        AmazonWebServicesCredentialsBinding binding = new AmazonWebServicesCredentialsBinding(
                "CUSTOM_ACCESS_KEY", "CUSTOM_SECRET_KEY", "CUSTOM_SESSION_TOKEN", "credentials-id");

        assertEquals("CUSTOM_ACCESS_KEY", binding.getAccessKeyVariable());
        assertEquals("CUSTOM_SECRET_KEY", binding.getSecretKeyVariable());
        assertEquals("CUSTOM_SESSION_TOKEN", binding.getSessionTokenVariable());

        Set<String> variables = binding.variables();
        assertTrue("Should contain access key variable", variables.contains("CUSTOM_ACCESS_KEY"));
        assertTrue("Should contain secret key variable", variables.contains("CUSTOM_SECRET_KEY"));
        assertTrue("Should contain session token variable", variables.contains("CUSTOM_SESSION_TOKEN"));
    }

    @Test
    public void testDefaultValues() {
        AmazonWebServicesCredentialsBinding binding =
                new AmazonWebServicesCredentialsBinding(null, null, null, "credentials-id");

        assertEquals("AWS_ACCESS_KEY_ID", binding.getAccessKeyVariable());
        assertEquals("AWS_SECRET_ACCESS_KEY", binding.getSecretKeyVariable());
        assertEquals("AWS_SESSION_TOKEN", binding.getSessionTokenVariable());
    }

    @Test
    public void testRoleProperties() {
        AmazonWebServicesCredentialsBinding binding = new AmazonWebServicesCredentialsBinding(
                "CUSTOM_ACCESS_KEY", "CUSTOM_SECRET_KEY", "CUSTOM_SESSION_TOKEN", "credentials-id");

        assertNull(binding.getRoleArn());
        assertNull(binding.getRoleSessionName());
        assertEquals(0, binding.getRoleSessionDurationSeconds());

        String roleArn = "arn:aws:iam::123456789012:role/test-role";
        String sessionName = "test-session";
        int duration = 3600;

        binding.setRoleArn(roleArn);
        binding.setRoleSessionName(sessionName);
        binding.setRoleSessionDurationSeconds(duration);

        assertEquals(roleArn, binding.getRoleArn());
        assertEquals(sessionName, binding.getRoleSessionName());
        assertEquals(duration, binding.getRoleSessionDurationSeconds());
    }

    @Test
    public void testType() {
        AmazonWebServicesCredentialsBinding binding =
                new AmazonWebServicesCredentialsBinding(null, null, null, "credentials-id");

        assertEquals(AmazonWebServicesCredentials.class, binding.type());
    }

    @Test
    public void testVariables() {
        AmazonWebServicesCredentialsBinding binding = new AmazonWebServicesCredentialsBinding(
                "AWS_ACCESS_KEY_ID_VAR", "AWS_SECRET_KEY_VAR", "AWS_SESSION_TOKEN_VAR", "credentials-id");

        Set<String> variables = binding.variables();
        assertEquals(3, variables.size());
        assertTrue(variables.contains("AWS_ACCESS_KEY_ID_VAR"));
        assertTrue(variables.contains("AWS_SECRET_KEY_VAR"));
        assertTrue(variables.contains("AWS_SESSION_TOKEN_VAR"));
    }

    @Test
    public void testAssumeRoleProvider() {
        // This method is private and would need integration tests or refactoring to be properly tested
        // For now, we'll just check if the assumeRole setter methods work correctly
        AmazonWebServicesCredentialsBinding binding =
                new AmazonWebServicesCredentialsBinding(null, null, null, "credentials-id");

        binding.setRoleArn("arn:aws:iam::123456789012:role/role-name");
        binding.setRoleSessionName("customSession");
        binding.setRoleSessionDurationSeconds(900);

        assertEquals("arn:aws:iam::123456789012:role/role-name", binding.getRoleArn());
        assertEquals("customSession", binding.getRoleSessionName());
        assertEquals(900, binding.getRoleSessionDurationSeconds());
    }
}
