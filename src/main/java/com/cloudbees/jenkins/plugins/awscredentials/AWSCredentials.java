package com.cloudbees.jenkins.plugins.awscredentials;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;

/**
 * A {@link AWSCredentialsProvider} that is bound to the Jenkins {@link Credentials} api.
 *
 * @since 1.11
 */
@NameWith(value = AWSCredentials.NameProvider.class, priority = 1)
public interface AWSCredentials extends StandardCredentials, AWSCredentialsProvider {
    String getDisplayName();

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
