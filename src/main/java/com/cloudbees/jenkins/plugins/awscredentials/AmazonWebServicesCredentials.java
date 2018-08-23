/*
 * The MIT License
 *
 *  Copyright (c) 2015, CloudBees, Inc.
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
import com.amazonaws.auth.AWSCredentialsProvider;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;

/**
 * A {@link AWSCredentialsProvider} that is bound to the Jenkins {@link Credentials} api.
 */
@NameWith(value = AmazonWebServicesCredentials.NameProvider.class, priority = 1)
public interface AmazonWebServicesCredentials extends StandardCredentials, AWSCredentialsProvider {
    /** Serial UID from 1.16. */
    long serialVersionUID = -8931505925778535681L;

    String getDisplayName();

    AWSCredentials getCredentialsWithReqParams(String roleSessioName, int roleSessionDurationSeconds);
    AWSCredentials getCredentials(String mfaToken);

    /**
     * Our name provider.
     */
    public static class NameProvider extends CredentialsNameProvider<AmazonWebServicesCredentials> {

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public String getName(@NonNull AmazonWebServicesCredentials c) {
            String description = Util.fixEmptyAndTrim(c.getDescription());
            return c.getDisplayName() + (description != null ? " (" + description + ")" : "");
        }
    }

}
