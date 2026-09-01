package com.cloudbees.jenkins.plugins.awscredentials;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class AmazonWebServicesCredentialsBindingTest {

    @Test
    public void sessionTokenVariableDefaultsWhenNotSet() {
        AmazonWebServicesCredentialsBinding binding =
                new AmazonWebServicesCredentialsBinding(null, null, "credentialsId");

        assertEquals("AWS_SESSION_TOKEN", binding.getSessionTokenVariable());
        assertTrue(binding.variables().contains("AWS_SESSION_TOKEN"));
    }

    @Test
    public void sessionTokenVariableDefaultsWhenBlank() {
        AmazonWebServicesCredentialsBinding binding =
                new AmazonWebServicesCredentialsBinding(null, null, "credentialsId");
        binding.setSessionTokenVariable("   ");

        assertEquals("AWS_SESSION_TOKEN", binding.getSessionTokenVariable());
    }

    @Test
    public void sessionTokenVariableCanBeCustomized() {
        AmazonWebServicesCredentialsBinding binding =
                new AmazonWebServicesCredentialsBinding(null, null, "credentialsId");
        binding.setSessionTokenVariable("MY_SESSION_TOKEN");

        assertEquals("MY_SESSION_TOKEN", binding.getSessionTokenVariable());
        assertTrue(binding.variables().contains("MY_SESSION_TOKEN"));
        assertFalse(binding.variables().contains("AWS_SESSION_TOKEN"));
    }
}
