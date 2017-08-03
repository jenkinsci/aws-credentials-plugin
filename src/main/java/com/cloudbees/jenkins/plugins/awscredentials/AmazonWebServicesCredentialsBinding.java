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
import com.amazonaws.auth.BasicSessionCredentials;

import edu.umd.cs.findbugs.annotations.CheckForNull;
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
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nonnull;
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
    private final static String SESSION_TOKEN_VARIABLE_NAME = "AWS_SESSION_TOKEN";

    @NonNull
    private final String accessKeyVariable;
    @NonNull
    private final String secretKeyVariable;

    /**
     *
     * @param accessKeyVariable if {@code null}, {@value DEFAULT_ACCESS_KEY_ID_VARIABLE_NAME} will be used.
     * @param secretKeyVariable if {@code null}, {@value DEFAULT_SECRET_ACCESS_KEY_VARIABLE_NAME} will be used.
     * @param credentialsId
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

    @Override
    protected Class<AmazonWebServicesCredentials> type() {
        return AmazonWebServicesCredentials.class;
    }

    @Override
    public MultiEnvironment bind(@Nonnull Run<?, ?> build, FilePath workspace, Launcher launcher, TaskListener listener) throws IOException, InterruptedException {
        AWSCredentials credentials = getCredentials(build).getCredentials();
        Map<String,String> m = new HashMap<String,String>();
        m.put(accessKeyVariable, credentials.getAWSAccessKeyId());
        m.put(secretKeyVariable, credentials.getAWSSecretKey());

        // If role has been assumed, STS requires AWS_SESSION_TOKEN variable set too.
        if(credentials instanceof AWSSessionCredentials) {
            m.put(SESSION_TOKEN_VARIABLE_NAME, ((AWSSessionCredentials) credentials).getSessionToken());
        }
        return new MultiEnvironment(m);
    }

    @Override
    public Set<String> variables() {
        return new HashSet<String>(Arrays.asList(accessKeyVariable, secretKeyVariable));
    }

    @Extension
    public static class DescriptorImpl extends BindingDescriptor<AmazonWebServicesCredentials> {

        @Override protected Class<AmazonWebServicesCredentials> type() {
            return AmazonWebServicesCredentials.class;
        }

        @Override public String getDisplayName() {
            return "AWS access key and secret";
        }
    }

}
