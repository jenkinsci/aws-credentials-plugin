package com.cloudbees.jenkins.plugins.awscredentials;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import hudson.security.ACL;
import io.jenkins.plugins.casc.misc.RoundTripAbstractTest;
import org.jvnet.hudson.test.RestartableJenkinsRule;

public class ConfigurationAsCodeTest extends RoundTripAbstractTest {

    @Override
    protected void assertConfiguredAsExpected(RestartableJenkinsRule restartableJenkinsRule, String s) {
        AWSCredentialsImpl credentials = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentials(
                        AWSCredentialsImpl.class, r.j.jenkins, ACL.SYSTEM, (DomainRequirement) null),
                CredentialsMatchers.withId("aws-credentials-casc"));
        assertNotNull(credentials);
        assertEquals(credentials.getAccessKey(), "foo");
        assertEquals(credentials.getDescription(), "foo-description");
        assertEquals(credentials.getIamMfaSerialNumber(), "arn:aws:iam::123456789012:mfa/user");
        assertEquals(credentials.getIamRoleArn(), "arn:aws:iam::123456789012:role/MyIAMRoleName");
        assertEquals(credentials.getIamExternalId(), "123456");
        assertEquals(credentials.getId(), "aws-credentials-casc");
        assertEquals(credentials.getScope(), CredentialsScope.GLOBAL);
        assertEquals(credentials.getSecretKey().getPlainText(), "bar");
    }

    @Override
    protected String stringInLogExpected() {
        return "AWSCredentialsImpl";
    }
}
