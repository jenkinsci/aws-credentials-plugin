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
import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.InstanceProfileCredentialsProvider;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.DescribeAvailabilityZonesResult;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.Extension;
import hudson.ProxyConfiguration;
import hudson.Util;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.net.HttpURLConnection;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AWSCredentialsImpl extends BaseAmazonWebServicesCredentials implements AmazonWebServicesCredentials {

    private static final long serialVersionUID = -3167989896315282034L;

    private static final Logger LOGGER = Logger.getLogger(BaseAmazonWebServicesCredentials.class.getName());

    public static final int STS_CREDENTIALS_DURATION_SECONDS = 3600;
    private final String accessKey;

    private final Secret secretKey;

    private final String iamRoleArn;
    private final String iamMfaSerialNumber;

    /**
     * Old data bound constructor. It is maintained to keep binary compatibility with clients that were using it directly.
     */
    public AWSCredentialsImpl(@CheckForNull CredentialsScope scope, @CheckForNull String id,
                              @CheckForNull String accessKey, @CheckForNull String secretKey, @CheckForNull String description) {
        this(scope, id, accessKey, secretKey, description, null, null);
    }

    @DataBoundConstructor
    public AWSCredentialsImpl(@CheckForNull CredentialsScope scope, @CheckForNull String id,
                              @CheckForNull String accessKey, @CheckForNull String secretKey, @CheckForNull String description,
                              @CheckForNull String iamRoleArn, @CheckForNull String iamMfaSerialNumber) {
        super(scope, id, description);
        this.accessKey = Util.fixNull(accessKey);
        this.secretKey = Secret.fromString(secretKey);
        this.iamRoleArn = Util.fixNull(iamRoleArn);
        this.iamMfaSerialNumber = Util.fixNull(iamMfaSerialNumber);
    }

    public String getAccessKey() {
        return accessKey;
    }

    public Secret getSecretKey() {
        return secretKey;
    }

    public String getIamRoleArn() {
        return iamRoleArn;
    }

    public String getIamMfaSerialNumber() {
        return iamMfaSerialNumber;
    }

    public boolean requiresToken() {
        return !StringUtils.isBlank(iamMfaSerialNumber);
    }

    public AWSCredentials getCredentials() {
        AWSCredentials initialCredentials = new BasicAWSCredentials(accessKey, secretKey.getPlainText());

        if (StringUtils.isBlank(iamRoleArn)) {
            return initialCredentials;
        } else {
            // Handle the case of delegation to instance profile
            if (StringUtils.isBlank(accessKey) && StringUtils.isBlank(secretKey.getPlainText()) ) {
                initialCredentials = (new InstanceProfileCredentialsProvider()).getCredentials();
            }

            AssumeRoleRequest assumeRequest = createAssumeRoleRequest(iamRoleArn);

            AssumeRoleResult assumeResult = new AWSSecurityTokenServiceClient(initialCredentials).assumeRole(assumeRequest);

            return new BasicSessionCredentials(
                    assumeResult.getCredentials().getAccessKeyId(),
                    assumeResult.getCredentials().getSecretAccessKey(),
                    assumeResult.getCredentials().getSessionToken());
        }
    }

    public AWSCredentials getCredentials(String mfaToken) {
        AWSCredentials initialCredentials = new BasicAWSCredentials(accessKey, secretKey.getPlainText());

        AssumeRoleRequest assumeRequest = createAssumeRoleRequest(iamRoleArn)
                .withSerialNumber(iamMfaSerialNumber)
                .withTokenCode(mfaToken);

        AssumeRoleResult assumeResult = new AWSSecurityTokenServiceClient(initialCredentials).assumeRole(assumeRequest);

        return new BasicSessionCredentials(
                assumeResult.getCredentials().getAccessKeyId(),
                assumeResult.getCredentials().getSecretAccessKey(),
                assumeResult.getCredentials().getSessionToken());
    }

    public void refresh() {
        // no-op
    }

    public String getDisplayName() {
        if (StringUtils.isBlank(iamRoleArn)) {
            return accessKey;
        }
        return accessKey + ":" + iamRoleArn;
    }

    private static AssumeRoleRequest createAssumeRoleRequest(@QueryParameter("iamRoleArn") String iamRoleArn) {
        return new AssumeRoleRequest()
                .withRoleArn(iamRoleArn)
                .withDurationSeconds(STS_CREDENTIALS_DURATION_SECONDS)
                .withRoleSessionName(Jenkins.getActiveInstance().getDisplayName());
    }

    @Extension
    public static class DescriptorImpl extends CredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return Messages.AWSCredentialsImpl_DisplayName();
        }

        public FormValidation doCheckSecretKey(@QueryParameter("accessKey") final String accessKey,
                                               @QueryParameter("iamRoleArn") final String iamRoleArn,
                                               @QueryParameter("iamMfaSerialNumber") final String iamMfaSerialNumber,
                                               @QueryParameter("iamMfaToken") final String iamMfaToken,
                                               @QueryParameter final String secretKey) {
            if (StringUtils.isBlank(accessKey) && StringUtils.isBlank(secretKey)) {
                return FormValidation.ok();
            }
            if (StringUtils.isBlank(accessKey)) {
                return FormValidation.error(Messages.AWSCredentialsImpl_SpecifyAccessKeyId());
            }
            if (StringUtils.isBlank(secretKey)) {
                return FormValidation.error(Messages.AWSCredentialsImpl_SpecifySecretAccessKey());
            }

            ProxyConfiguration proxy = Jenkins.getActiveInstance().proxy;
            ClientConfiguration clientConfiguration = new ClientConfiguration();
            if(proxy != null) {
            	clientConfiguration.setProxyHost(proxy.name);
            	clientConfiguration.setProxyPort(proxy.port);
            	clientConfiguration.setProxyUsername(proxy.getUserName());
            	clientConfiguration.setProxyPassword(proxy.getPassword());
            }

            AWSCredentials awsCredentials = new BasicAWSCredentials(accessKey, Secret.fromString(secretKey).getPlainText());

            // If iamRoleArn is specified, swap out the credentials.
            if (!StringUtils.isBlank(iamRoleArn)) {

                AssumeRoleRequest assumeRequest = createAssumeRoleRequest(iamRoleArn);

                if(!StringUtils.isBlank(iamMfaSerialNumber)) {
                    if(StringUtils.isBlank(iamMfaToken)) {
                        return FormValidation.error(Messages.AWSCredentialsImpl_SpecifyMFAToken());
                    }
                    assumeRequest = assumeRequest
                            .withSerialNumber(iamMfaSerialNumber)
                            .withTokenCode(iamMfaToken);
                }

                try {
                    AssumeRoleResult assumeResult = new AWSSecurityTokenServiceClient(awsCredentials).assumeRole(assumeRequest);

                    awsCredentials = new BasicSessionCredentials(
                            assumeResult.getCredentials().getAccessKeyId(),
                            assumeResult.getCredentials().getSecretAccessKey(),
                            assumeResult.getCredentials().getSessionToken());
                } catch(AmazonServiceException e) {
                    LOGGER.log(Level.WARNING, "Unable to assume role [" + iamRoleArn + "] with request [" + assumeRequest + "]", e);
                    return FormValidation.error(Messages.AWSCredentialsImpl_NotAbleToAssumeRole());
                }

            }

            AmazonEC2 ec2 = new AmazonEC2Client(awsCredentials,clientConfiguration);

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
