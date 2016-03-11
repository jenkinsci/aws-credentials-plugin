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
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
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


    private final String accessKeyVariable;
    private final String secretKeyVariable;

    @DataBoundConstructor
    public AmazonWebServicesCredentialsBinding(String accessKeyVariable, String secretKeyVariable, String credentialsId) {
        super(credentialsId);
        this.accessKeyVariable = accessKeyVariable;
        this.secretKeyVariable = secretKeyVariable;
    }

    public String getAccessKeyVariable() {
        return accessKeyVariable;
    }

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
