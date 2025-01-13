/*
 * The MIT License
 *
 *  Copyright (c) 2016, CloudBees, Inc.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 *
 */

package com.cloudbees.jenkins.plugins.awscredentials;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

/**
 * @author <a href="mailto:nicolas.deloof@gmail.com">Nicolas De Loof</a>
 */
public class AmazonWebServicesCredentialsBinding extends MultiBinding<AmazonWebServicesCredentials> {

    public static final String DEFAULT_ACCESS_KEY_ID_VARIABLE_NAME = "AWS_ACCESS_KEY_ID";
    private static final String DEFAULT_SECRET_ACCESS_KEY_VARIABLE_NAME = "AWS_SECRET_ACCESS_KEY";
    private static final String SESSION_TOKEN_VARIABLE_NAME = "AWS_SESSION_TOKEN";

    @NonNull
    private final String accessKeyVariable;

    @NonNull
    private final String secretKeyVariable;

    private String roleArn;
    private String roleSessionName;
    private int roleSessionDurationSeconds;

    /**
     *
     * @param accessKeyVariable if {@code null}, {@value DEFAULT_ACCESS_KEY_ID_VARIABLE_NAME} will be used.
     * @param secretKeyVariable if {@code null}, {@value DEFAULT_SECRET_ACCESS_KEY_VARIABLE_NAME} will be used.
     * @param credentialsId identifier which should be referenced when accessing the credentials from a job/pipeline.
     */
    @DataBoundConstructor
    public AmazonWebServicesCredentialsBinding(
            @Nullable String accessKeyVariable, @Nullable String secretKeyVariable, String credentialsId) {
        super(credentialsId);
        this.accessKeyVariable = StringUtils.defaultIfBlank(accessKeyVariable, DEFAULT_ACCESS_KEY_ID_VARIABLE_NAME);
        this.secretKeyVariable = StringUtils.defaultIfBlank(secretKeyVariable, DEFAULT_SECRET_ACCESS_KEY_VARIABLE_NAME);
    }

    @NonNull
    public String getAccessKeyVariable() {
        return accessKeyVariable;
    }

    @NonNull
    public String getSecretKeyVariable() {
        return secretKeyVariable;
    }

    @Nullable
    public String getRoleArn() {
        return roleArn;
    }

    @Nullable
    public String getRoleSessionName() {
        return roleSessionName;
    }

    public int getRoleSessionDurationSeconds() {
        return roleSessionDurationSeconds;
    }

    @DataBoundSetter
    public void setRoleArn(String roleArn) {
        this.roleArn = roleArn;
    }

    @DataBoundSetter
    public void setRoleSessionName(String roleSessionName) {
        this.roleSessionName = roleSessionName;
    }

    @DataBoundSetter
    public void setRoleSessionDurationSeconds(int roleSessionDurationSeconds) {
        this.roleSessionDurationSeconds = roleSessionDurationSeconds;
    }

    @Override
    protected Class<AmazonWebServicesCredentials> type() {
        return AmazonWebServicesCredentials.class;
    }

    @Override
    public MultiEnvironment bind(@NonNull Run<?, ?> build, FilePath workspace, Launcher launcher, TaskListener listener)
            throws IOException, InterruptedException {
        AwsCredentialsProvider provider = getCredentials(build);
        if (!StringUtils.isEmpty(this.roleArn)) {
            provider = this.assumeRoleProvider(provider);
        }

        AwsCredentials credentials = provider.resolveCredentials();

        Map<String, String> m = new HashMap<String, String>();
        if (Objects.isNull(credentials)) {
            // the empty strings retain functionality present before the AWS SDK migration
            m.put(accessKeyVariable, "");
            m.put(secretKeyVariable, "");
        } else {
            m.put(accessKeyVariable, credentials.accessKeyId());
            m.put(secretKeyVariable, credentials.secretAccessKey());
        }

        // If role has been assumed, STS requires AWS_SESSION_TOKEN variable set too.
        if (credentials instanceof AwsSessionCredentials) {
            m.put(SESSION_TOKEN_VARIABLE_NAME, ((AwsSessionCredentials) credentials).sessionToken());
        }
        return new MultiEnvironment(m);
    }

    private AwsCredentialsProvider assumeRoleProvider(AwsCredentialsProvider baseProvider) {
        StsClient stsClient = AWSCredentialsImpl.buildStsClient(baseProvider);

        String roleSessionName = StringUtils.defaultIfBlank(this.roleSessionName, "Jenkins");

        AssumeRoleRequest.Builder assumeRoleRequest =
                AssumeRoleRequest.builder().roleArn(this.roleArn).roleSessionName(roleSessionName);

        if (this.roleSessionDurationSeconds > 0) {
            assumeRoleRequest.durationSeconds(this.roleSessionDurationSeconds);
        }

        return StsAssumeRoleCredentialsProvider.builder()
                .stsClient(stsClient)
                .refreshRequest(assumeRoleRequest.build())
                .build();
    }

    @Override
    public Set<String> variables() {
        return new HashSet<String>(Arrays.asList(accessKeyVariable, secretKeyVariable, SESSION_TOKEN_VARIABLE_NAME));
    }

    @Symbol("aws")
    @Extension
    public static class DescriptorImpl extends BindingDescriptor<AmazonWebServicesCredentials> {

        @Override
        protected Class<AmazonWebServicesCredentials> type() {
            return AmazonWebServicesCredentials.class;
        }

        @Override
        public String getDisplayName() {
            return "AWS access key and secret";
        }

        @Override
        public boolean requiresWorkspace() {
            return false;
        }
    }
}
