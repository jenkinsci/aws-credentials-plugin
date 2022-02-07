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
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.regions.DefaultAwsRegionProviderChain;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.DescribeAvailabilityZonesResult;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ProxyConfiguration;
import hudson.Util;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
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
    private final String iamExternalId;
    private final String iamMfaSerialNumber;

    private volatile Integer stsTokenDuration;

    // Old data bound constructor. It is maintained to keep binary compatibility with clients that were using it directly.
    public AWSCredentialsImpl(@CheckForNull CredentialsScope scope, @CheckForNull String id,
                              @CheckForNull String accessKey, @CheckForNull String secretKey, @CheckForNull String description) {
        this(scope, id, accessKey, secretKey, description, null, null, null);
    }

    // Old data bound constructor. It is maintained to keep binary compatibility with clients that were using it directly.
    public AWSCredentialsImpl(@CheckForNull CredentialsScope scope, @CheckForNull String id,
                              @CheckForNull String accessKey, @CheckForNull String secretKey, @CheckForNull String description,
                              @CheckForNull String iamRoleArn, @CheckForNull String iamMfaSerialNumber) {
        this(scope, id, accessKey, secretKey, description, iamRoleArn, iamMfaSerialNumber, null);
    }

    @DataBoundConstructor
    public AWSCredentialsImpl(@CheckForNull CredentialsScope scope, @CheckForNull String id,
                              @CheckForNull String accessKey, @CheckForNull String secretKey, @CheckForNull String description,
                              @CheckForNull String iamRoleArn, @CheckForNull String iamMfaSerialNumber,
                              String iamExternalId) {
        super(scope, id, description);
        this.accessKey = Util.fixNull(accessKey);
        this.secretKey = Secret.fromString(secretKey);
        this.iamRoleArn = Util.fixNull(iamRoleArn);
        this.iamExternalId = Util.fixNull(iamExternalId);
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

    public String getIamExternalId() {
        return iamExternalId;
    }

    public String getIamMfaSerialNumber() {
        return iamMfaSerialNumber;
    }

    @NonNull
    public Integer getStsTokenDuration() {
        return stsTokenDuration == null ? DescriptorImpl.DEFAULT_STS_TOKEN_DURATION : stsTokenDuration;
    }

    @DataBoundSetter
    public void setStsTokenDuration(Integer stsTokenDuration) {
        this.stsTokenDuration = stsTokenDuration == null || stsTokenDuration.equals(DescriptorImpl.DEFAULT_STS_TOKEN_DURATION) ? null : stsTokenDuration;
    }

    public boolean requiresToken() {
        return !StringUtils.isBlank(iamMfaSerialNumber);
    }

    public AWSCredentials getCredentials() {
        AWSCredentials initialCredentials = new BasicAWSCredentials(accessKey, secretKey.getPlainText());

        if (StringUtils.isBlank(iamRoleArn)) {
            return initialCredentials;
        } else {
            AWSCredentialsProvider baseProvider;
            // Handle the case of delegation to instance profile
            if (StringUtils.isBlank(accessKey) && StringUtils.isBlank(secretKey.getPlainText())) {
                baseProvider = null;
            } else {
               baseProvider = new AWSStaticCredentialsProvider(initialCredentials);
            }

            AWSSecurityTokenService client = buildStsClient(baseProvider);

            AssumeRoleRequest assumeRequest = createAssumeRoleRequest(iamRoleArn, iamExternalId)
                    .withDurationSeconds(this.getStsTokenDuration());

            AssumeRoleResult assumeResult = client.assumeRole(assumeRequest);

            return new BasicSessionCredentials(
                    assumeResult.getCredentials().getAccessKeyId(),
                    assumeResult.getCredentials().getSecretAccessKey(),
                    assumeResult.getCredentials().getSessionToken());
        }
    }

    private static String determineClientRegion() {
        // Check for available region from the SDK, otherwise specify default
        String clientRegion = null;
        DefaultAwsRegionProviderChain sdkRegionLookup = new DefaultAwsRegionProviderChain();
        try {
            clientRegion = sdkRegionLookup.getRegion();
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Could not find default region using SDK lookup.", e);
        }
        if (clientRegion == null) {
            clientRegion = Regions.DEFAULT_REGION.getName();
        }
        return clientRegion;
    }

    public AWSCredentials getCredentials(String mfaToken) {
        AWSCredentials initialCredentials = new BasicAWSCredentials(accessKey, secretKey.getPlainText());

        AssumeRoleRequest assumeRequest = createAssumeRoleRequest(iamRoleArn, iamExternalId)
                .withSerialNumber(iamMfaSerialNumber)
                .withTokenCode(mfaToken)
                .withDurationSeconds(this.getStsTokenDuration());

        AWSSecurityTokenService awsSecurityTokenService = getAWSSecurityTokenService(initialCredentials);
        AssumeRoleResult assumeResult = awsSecurityTokenService.assumeRole(assumeRequest);

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

    /*package*/ static AWSSecurityTokenService buildStsClient(AWSCredentialsProvider provider) {
        // Check for available region from the SDK, otherwise specify default
        String clientRegion = determineClientRegion();

        AWSSecurityTokenServiceClientBuilder builder = AWSSecurityTokenServiceClientBuilder.standard()
                        .withRegion(clientRegion)
                        .withClientConfiguration(getClientConfiguration());

        if (provider != null) {
            builder = builder.withCredentials(provider);
        }

        return builder.build();
    }

    private static AssumeRoleRequest createAssumeRoleRequest(String iamRoleArn, String iamExternalId) {
        AssumeRoleRequest retval = new AssumeRoleRequest()
                .withRoleArn(iamRoleArn)
                .withRoleSessionName("Jenkins");
       if (iamExternalId != null && !iamExternalId.isEmpty()) {
           return retval.withExternalId(iamExternalId);
       }
       return retval;
    }

    /**
     * Provides the {@link AWSSecurityTokenService} for a given {@link AWSCredentials}
     *
     * @param awsCredentials
     * @return {@link AWSSecurityTokenService}
     */
    private static AWSSecurityTokenService getAWSSecurityTokenService(AWSCredentials awsCredentials) {
        ClientConfiguration clientConfiguration = getClientConfiguration();
        String clientRegion = determineClientRegion();
        return AWSSecurityTokenServiceClientBuilder.standard()
                .withRegion(clientRegion)
                .withCredentials(new AWSStaticCredentialsProvider(awsCredentials))
                .withClientConfiguration(clientConfiguration)
                .build();
    }

    /**
     * Provides the {@link ClientConfiguration}
     *
     * @return {@link ClientConfiguration}
     */
    private static ClientConfiguration getClientConfiguration() {
        Jenkins instance = Jenkins.getInstanceOrNull();

        ProxyConfiguration proxy = instance != null ? instance.proxy : null;
        ClientConfiguration clientConfiguration = new ClientConfiguration();
        if (proxy != null && proxy.name != null && !proxy.name.isEmpty()) {
            clientConfiguration.setProxyHost(proxy.name);
            clientConfiguration.setProxyPort(proxy.port);
            clientConfiguration.setProxyUsername(proxy.getUserName());
            clientConfiguration.setProxyPassword(proxy.getPassword());
        }
        return clientConfiguration;
    }

    @Extension
    public static class DescriptorImpl extends CredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return Messages.AWSCredentialsImpl_DisplayName();
        }

        public static final Integer DEFAULT_STS_TOKEN_DURATION = STS_CREDENTIALS_DURATION_SECONDS;

        public FormValidation doCheckSecretKey(@QueryParameter("accessKey") final String accessKey,
                                               @QueryParameter("iamRoleArn") final String iamRoleArn,
                                               @QueryParameter("iamExternalId") final String iamExternalId,
                                               @QueryParameter("iamMfaSerialNumber") final String iamMfaSerialNumber,
                                               @QueryParameter("iamMfaToken") final String iamMfaToken,
                                               @QueryParameter("stsTokenDuration") final Integer stsTokenDuration,
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

            AWSCredentials awsCredentials = new BasicAWSCredentials(accessKey, Secret.fromString(secretKey).getPlainText());

            // If iamRoleArn is specified, swap out the credentials.
            if (!StringUtils.isBlank(iamRoleArn)) {

                AssumeRoleRequest assumeRequest = createAssumeRoleRequest(iamRoleArn, iamExternalId)
                        .withDurationSeconds(stsTokenDuration);

                if (!StringUtils.isBlank(iamMfaSerialNumber)) {
                    if (StringUtils.isBlank(iamMfaToken)) {
                        return FormValidation.error(Messages.AWSCredentialsImpl_SpecifyMFAToken());
                    }
                    assumeRequest = assumeRequest
                            .withSerialNumber(iamMfaSerialNumber)
                            .withTokenCode(iamMfaToken);
                }

                try {
                    AWSSecurityTokenService awsSecurityTokenService = getAWSSecurityTokenService(awsCredentials);
                    AssumeRoleResult assumeResult = awsSecurityTokenService.assumeRole(assumeRequest);

                    awsCredentials = new BasicSessionCredentials(
                            assumeResult.getCredentials().getAccessKeyId(),
                            assumeResult.getCredentials().getSecretAccessKey(),
                            assumeResult.getCredentials().getSessionToken());
                } catch (RuntimeException e) {
                    LOGGER.log(Level.WARNING, "Unable to assume role [" + iamRoleArn + "] with request [" + assumeRequest + "]", e);
                    return FormValidation.error(Messages.AWSCredentialsImpl_NotAbleToAssumeRole() + " Check the Jenkins log for more details");
                }
            }

            AmazonEC2 ec2 = new AmazonEC2Client(awsCredentials, getClientConfiguration());

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
