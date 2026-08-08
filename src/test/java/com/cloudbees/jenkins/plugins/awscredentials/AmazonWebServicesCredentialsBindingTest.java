package com.cloudbees.jenkins.plugins.awscredentials;

import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Test;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

public class AmazonWebServicesCredentialsBindingTest {

    @Test
    public void customSessionNameIsUsedForStoredRole() {
        AmazonWebServicesCredentialsBinding binding = binding();
        binding.setRoleSessionName("custom-session");
        AWSCredentialsImpl provider = mock(AWSCredentialsImpl.class);
        AwsCredentials credentials = mock(AwsCredentials.class);
        when(provider.getIamRoleArn()).thenReturn("arn:aws:iam::123456789012:role/example");
        when(provider.resolveCredentialsWithRoleSessionName("custom-session")).thenReturn(credentials);

        assertSame(credentials, binding.resolveCredentials(provider));

        verify(provider).resolveCredentialsWithRoleSessionName("custom-session");
        verify(provider, never()).resolveCredentials();
    }

    @Test
    public void blankSessionNameUsesOrdinaryResolution() {
        AmazonWebServicesCredentialsBinding binding = binding();
        binding.setRoleSessionName("   ");
        AWSCredentialsImpl provider = mock(AWSCredentialsImpl.class);
        AwsCredentials credentials = mock(AwsCredentials.class);
        when(provider.getIamRoleArn()).thenReturn("arn:aws:iam::123456789012:role/example");
        when(provider.resolveCredentials()).thenReturn(credentials);

        assertSame(credentials, binding.resolveCredentials(provider));

        verify(provider).resolveCredentials();
        verify(provider, never()).resolveCredentialsWithRoleSessionName("   ");
    }

    @Test
    public void credentialWithoutStoredRoleUsesOrdinaryResolution() {
        AmazonWebServicesCredentialsBinding binding = binding();
        binding.setRoleSessionName("custom-session");
        AWSCredentialsImpl provider = mock(AWSCredentialsImpl.class);
        AwsCredentials credentials = mock(AwsCredentials.class);
        when(provider.getIamRoleArn()).thenReturn(null);
        when(provider.resolveCredentials()).thenReturn(credentials);

        assertSame(credentials, binding.resolveCredentials(provider));

        verify(provider).resolveCredentials();
        verify(provider, never()).resolveCredentialsWithRoleSessionName("custom-session");
    }

    @Test
    public void otherProviderUsesOrdinaryResolution() {
        AmazonWebServicesCredentialsBinding binding = binding();
        binding.setRoleSessionName("custom-session");
        AwsCredentialsProvider provider = mock(AwsCredentialsProvider.class);
        AwsCredentials credentials = mock(AwsCredentials.class);
        when(provider.resolveCredentials()).thenReturn(credentials);

        assertSame(credentials, binding.resolveCredentials(provider));

        verify(provider).resolveCredentials();
    }

    private static AmazonWebServicesCredentialsBinding binding() {
        return new AmazonWebServicesCredentialsBinding(null, null, "credentials-id");
    }
}
