package com.cloudbees.jenkins.plugins.awscredentials;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import hudson.security.ACL;
import io.jenkins.plugins.casc.misc.RoundTripAbstractTest;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assume.assumeThat;

public class ConfigurationAsCodeTest extends RoundTripAbstractTest {

    @Override
    protected void assertConfiguredAsExpected(RestartableJenkinsRule restartableJenkinsRule, String s) {
        AWSCredentialsImpl credentials = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentials(AWSCredentialsImpl.class,
                        r.j.jenkins, ACL.SYSTEM, (DomainRequirement) null),
                CredentialsMatchers.withId("aws-credentials-casc"));
        assumeThat("AWS credentials are not null", credentials, notNullValue());
        assumeThat("access key is configured", credentials.getAccessKey(),
                equalTo("foo"));
        assumeThat("description is configured", credentials.getDescription(),
                equalTo("foo-description"));
        assumeThat("mfa serial is configured", credentials.getIamMfaSerialNumber(),
                equalTo("arn:aws:iam::123456789012:mfa/user"));
        assumeThat("role arn is configured", credentials.getIamRoleArn(),
                equalTo("arn:aws:iam::123456789012:role/MyIAMRoleName"));
        assumeThat("id is configured", credentials.getId(),
                equalTo("aws-credentials-casc"));
        assumeThat("scope is configured", credentials.getScope(),
                equalTo(CredentialsScope.GLOBAL));
        assumeThat("secret key is configured", credentials.getSecretKey().getPlainText(),
                equalTo("bar"));
    }

    @Override
    protected String stringInLogExpected() {
        return "AWSCredentialsImpl";
    }
}
