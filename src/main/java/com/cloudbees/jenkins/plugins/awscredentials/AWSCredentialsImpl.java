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

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.DescribeAvailabilityZonesResult;
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.util.FormValidation;
import hudson.util.Secret;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.net.HttpURLConnection;

// Implement AmazonWebServicesCredentials for backward compatibility of plugins that consume AmazonWebServicesCredentials
// And did not yet migrate to AWSCredentials
public class AWSCredentialsImpl extends BaseAWSCredentials implements AmazonWebServicesCredentials, com.cloudbees.jenkins.plugins.awscredentials.AWSCredentials {

    private final String accessKey;

    private final Secret secretKey;

    @DataBoundConstructor
    public AWSCredentialsImpl(@CheckForNull CredentialsScope scope, @CheckForNull String id,
                              @CheckForNull String accessKey, @CheckForNull String secretKey, @CheckForNull String description) {
        super(scope, id, description);
        this.accessKey = Util.fixNull(accessKey);
        this.secretKey = Secret.fromString(secretKey);
    }

    public String getAccessKey() {
        return accessKey;
    }

    public Secret getSecretKey() {
        return secretKey;
    }

    public AWSCredentials getCredentials() {
        return new BasicAWSCredentials(accessKey, secretKey.getPlainText());
    }

    public void refresh() {
        // no-op
    }

    public String getDisplayName() {
        return accessKey;
    }

    @Extension
    public static class DescriptorImpl extends CredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return Messages.AWSCredentialsImpl_DisplayName();
        }

        public FormValidation doCheckSecretKey(@QueryParameter("accessKey") final String accessKey, @QueryParameter
        final String value) {
            if (StringUtils.isBlank(accessKey) && StringUtils.isBlank(value)) {
                return FormValidation.ok();
            }
            if (StringUtils.isBlank(accessKey)) {
                return FormValidation.error(Messages.AWSCredentialsImpl_SpecifyAccessKeyId());
            }
            if (StringUtils.isBlank(value)) {
                return FormValidation.error(Messages.AWSCredentialsImpl_SpecifySecretAccessKey());
            }
            AmazonEC2 ec2 =
                    new AmazonEC2Client(new BasicAWSCredentials(accessKey, Secret.fromString(value).getPlainText()));
            // TODO better/smarter validation of the credentials instead of verifying the permission on EC2.READ in us-east-1
            String region = "us-east-1";
            try {
                DescribeAvailabilityZonesResult zonesResult = ec2.describeAvailabilityZones();
                return FormValidation
                        .ok(Messages.AWSCredentialsImpl_CredentialsValidWithAccessToNZones(
                                zonesResult.getAvailabilityZones().size()));
            } catch (AmazonServiceException e) {
                if (HttpURLConnection.HTTP_UNAUTHORIZED == e.getStatusCode()) {
                    return FormValidation.warning(Messages.AWSCredentialsImpl_CredentialsInValid(e.getMessage()));
                } else if (HttpURLConnection.HTTP_FORBIDDEN == e.getStatusCode()) {
                    return FormValidation.ok(Messages.AWSCredentialsImpl_CredentialsValidWithoutAccessToAwsServiceInZone(e.getServiceName(), region, e.getErrorMessage() + " (" + e.getErrorCode() + ")"));
                } else {
                    return FormValidation.error(e.getMessage());
                }
            } catch (AmazonClientException e) {
                return FormValidation.error(e.getMessage());
            }
        }

    }

}
