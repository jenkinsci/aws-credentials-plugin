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

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSSessionCredentialsProvider;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:nicolas.deloof@gmail.com">Nicolas De Loof</a>
 */
public class AmazonWebServicesCredentialsBinding extends MultiBinding<AmazonWebServicesCredentials> {

    public final static String DEFAULT_ACCESS_KEY_ID_VARIABLE_NAME = "AWS_ACCESS_KEY_ID";
    private final static String DEFAULT_SECRET_ACCESS_KEY_VARIABLE_NAME = "AWS_SECRET_ACCESS_KEY";
    private final static String DEFAULT_SESSION_TOKEN_VARIABLE_NAME = "AWS_SESSION_TOKEN";

    @NonNull
    private final String accessKeyVariable;
    @NonNull
    private final String secretKeyVariable;
    @NonNull
    private String sessionTokenVariable = DEFAULT_SESSION_TOKEN_VARIABLE_NAME;

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
    public AmazonWebServicesCredentialsBinding(@Nullable String accessKeyVariable, @Nullable String secretKeyVariable, String credentialsId) {
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

    @NonNull
    public String getSessionTokenVariable() {
        return sessionTokenVariable;
    }

    @DataBoundSetter
    public void setSessionTokenVariable(String sessionTokenVariable) {
        this.sessionTokenVariable = StringUtils.defaultIfBlank(sessionTokenVariable, DEFAULT_SESSION_TOKEN_VARIABLE_NAME);
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
    public MultiEnvironment bind(@NonNull Run<?, ?> build, FilePath workspace, Launcher launcher, TaskListener listener) throws IOException,
                                                                                                                                InterruptedException {
        AWSCredentialsProvider provider = getCredentials(build);
        if (!StringUtils.isEmpty(this.roleArn)) {
            provider = this.assumeRoleProvider(provider);
        }

        AWSCredentials credentials = provider.getCredentials();

        Map<String,String> m = new HashMap<String,String>();
        m.put(accessKeyVariable, credentials.getAWSAccessKeyId());
        m.put(secretKeyVariable, credentials.getAWSSecretKey());

        // If role has been assumed, STS requires AWS_SESSION_TOKEN variable set too.
        if(credentials instanceof AWSSessionCredentials) {
            m.put(sessionTokenVariable, ((AWSSessionCredentials) credentials).getSessionToken());
        }
        return new MultiEnvironment(m);
    }

    private AWSSessionCredentialsProvider assumeRoleProvider(AWSCredentialsProvider baseProvider) {
        AWSSecurityTokenService stsClient = AWSCredentialsImpl.buildStsClient(baseProvider);

        String roleSessionName = StringUtils.defaultIfBlank(this.roleSessionName, "Jenkins");

        STSAssumeRoleSessionCredentialsProvider.Builder assumeRoleProviderBuilder =
                new STSAssumeRoleSessionCredentialsProvider.Builder(this.roleArn, roleSessionName)
                .withStsClient(stsClient);

        if (this.roleSessionDurationSeconds > 0) {
            assumeRoleProviderBuilder = assumeRoleProviderBuilder
                .withRoleSessionDurationSeconds(this.roleSessionDurationSeconds);
        }

        return assumeRoleProviderBuilder.build();
    }

    @Override
    public Set<String> variables() {
        return new HashSet<String>(Arrays.asList(accessKeyVariable, secretKeyVariable, sessionTokenVariable));
    }

    @Symbol("aws")
    @Extension
    public static class DescriptorImpl extends BindingDescriptor<AmazonWebServicesCredentials> {

        @Override protected Class<AmazonWebServicesCredentials> type() {
            return AmazonWebServicesCredentials.class;
        }

        @Override public String getDisplayName() {
            return "AWS access key and secret";
        }

        @Override public boolean requiresWorkspace() {
            return false;
        }
    }

}
