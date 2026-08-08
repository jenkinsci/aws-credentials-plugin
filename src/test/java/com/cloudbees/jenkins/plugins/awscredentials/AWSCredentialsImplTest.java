package com.cloudbees.jenkins.plugins.awscredentials;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

import org.junit.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

public class AWSCredentialsImplTest {

    @Test
    public void assumeRoleRequestUsesSuppliedSessionName() {
        AssumeRoleRequest request = AWSCredentialsImpl.createAssumeRoleRequest(
                        "arn:aws:iam::123456789012:role/example", "external-id", "custom-session")
                .build();

        assertEquals("arn:aws:iam::123456789012:role/example", request.roleArn());
        assertEquals("external-id", request.externalId());
        assertEquals("custom-session", request.roleSessionName());
    }

    @Test
    public void ordinaryResolutionUsesJenkinsSessionName() {
        SessionNameCapturingCredentials credentials = new SessionNameCapturingCredentials();
        AwsCredentials resolved = credentials.resolveCredentials();

        assertSame(credentials.resolved, resolved);
        assertEquals("Jenkins", credentials.roleSessionName);
    }

    @Test
    public void assumeRoleRequestUsesJenkinsForMfaResolution() {
        AssumeRoleRequest request = AWSCredentialsImpl.createAssumeRoleRequest(
                        "arn:aws:iam::123456789012:role/example", "external-id")
                .serialNumber("arn:aws:iam::123456789012:mfa/example")
                .tokenCode("123456")
                .build();

        assertEquals("Jenkins", request.roleSessionName());
        assertEquals("arn:aws:iam::123456789012:mfa/example", request.serialNumber());
        assertEquals("123456", request.tokenCode());
    }

    private static class SessionNameCapturingCredentials extends AWSCredentialsImpl {

        private final AwsCredentials resolved = AwsBasicCredentials.create("access-key", "secret-key");
        private String roleSessionName;

        SessionNameCapturingCredentials() {
            super(null, null, null, null, null);
        }

        @Override
        AwsCredentials resolveCredentialsWithRoleSessionName(String roleSessionName) {
            this.roleSessionName = roleSessionName;
            return resolved;
        }
    }
}
