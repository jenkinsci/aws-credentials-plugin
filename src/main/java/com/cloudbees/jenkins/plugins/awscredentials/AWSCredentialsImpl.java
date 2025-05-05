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

import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ProxyConfiguration;
import hudson.Util;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.AwsRegionProvider;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeAvailabilityZonesResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.StsClientBuilder;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;

public class AWSCredentialsImpl extends BaseAmazonWebServicesCredentials {

    private static final long serialVersionUID = -3167989896315282034L;

    private static final Logger LOGGER = Logger.getLogger(BaseAmazonWebServicesCredentials.class.getName());

    public static final int STS_CREDENTIALS_DURATION_SECONDS = 3600;

    private final String accessKey;

    private final Secret secretKey;

    private final String iamRoleArn;
    private final String iamExternalId;
    private final String iamMfaSerialNumber;

    private volatile Integer stsTokenDuration;

    // Old data bound constructor. It is maintained to keep binary compatibility with clients that were using it
    // directly.
    public AWSCredentialsImpl(
            @CheckForNull CredentialsScope scope,
            @CheckForNull String id,
            @CheckForNull String accessKey,
            @CheckForNull String secretKey,
            @CheckForNull String description) {
        this(scope, id, accessKey, secretKey, description, null, null, null);
    }

    // Old data bound constructor. It is maintained to keep binary compatibility with clients that were using it
    // directly.
    public AWSCredentialsImpl(
            @CheckForNull CredentialsScope scope,
            @CheckForNull String id,
            @CheckForNull String accessKey,
            @CheckForNull String secretKey,
            @CheckForNull String description,
            @CheckForNull String iamRoleArn,
            @CheckForNull String iamMfaSerialNumber) {
        this(scope, id, accessKey, secretKey, description, iamRoleArn, iamMfaSerialNumber, null);
    }

    @DataBoundConstructor
    public AWSCredentialsImpl(
            @CheckForNull CredentialsScope scope,
            @CheckForNull String id,
            @CheckForNull String accessKey,
            @CheckForNull String secretKey,
            @CheckForNull String description,
            @CheckForNull String iamRoleArn,
            @CheckForNull String iamMfaSerialNumber,
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
        this.stsTokenDuration =
                stsTokenDuration == null || stsTokenDuration.equals(DescriptorImpl.DEFAULT_STS_TOKEN_DURATION)
                        ? null
                        : stsTokenDuration;
    }

    public boolean requiresToken() {
        return !StringUtils.isBlank(iamMfaSerialNumber);
    }

    @Override
    public AwsCredentials resolveCredentials() {

        if (StringUtils.isBlank(iamRoleArn)) {
            if (StringUtils.isBlank(accessKey) && StringUtils.isBlank(secretKey.getPlainText())) {
                // AWS SDK v2 does not allow blank accessKey and secretKey
                return null;
            } else {
                return AwsBasicCredentials.create(accessKey, secretKey.getPlainText());
            }
        } else {
            AwsCredentialsProvider baseProvider;
            // Handle the case of delegation to instance profile
            if (StringUtils.isBlank(accessKey) && StringUtils.isBlank(secretKey.getPlainText())) {
                baseProvider = null;
            } else {
                baseProvider = StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(accessKey, secretKey.getPlainText()));
            }

            StsClient client = buildStsClient(baseProvider);

            AssumeRoleRequest.Builder assumeRequest =
                    createAssumeRoleRequest(iamRoleArn, iamExternalId).durationSeconds(this.getStsTokenDuration());

            AssumeRoleResponse assumeResult = client.assumeRole(assumeRequest.build());

            return AwsSessionCredentials.create(
                    assumeResult.credentials().accessKeyId(),
                    assumeResult.credentials().secretAccessKey(),
                    assumeResult.credentials().sessionToken());
        }
    }

    private static Region determineClientRegion() {
        // Check for available region from the SDK, otherwise specify default
        Region clientRegion = null;
        AwsRegionProvider sdkRegionLookup = new DefaultAwsRegionProviderChain();
        try {
            clientRegion = sdkRegionLookup.getRegion();
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Could not find default region using SDK lookup.", e);
        }
        if (clientRegion == null) {
            clientRegion = Region.US_WEST_2;
        }
        return clientRegion;
    }

    @Override
    public AwsCredentials resolveCredentials(String mfaToken) {
        AwsCredentials initialCredentials = AwsBasicCredentials.create(accessKey, secretKey.getPlainText());

        AssumeRoleRequest.Builder assumeRequest = createAssumeRoleRequest(iamRoleArn, iamExternalId)
                .serialNumber(iamMfaSerialNumber)
                .tokenCode(mfaToken)
                .durationSeconds(this.getStsTokenDuration());

        StsClient stsClient = getStsClient(initialCredentials);
        AssumeRoleResponse assumeResult = stsClient.assumeRole(assumeRequest.build());

        return AwsSessionCredentials.create(
                assumeResult.credentials().accessKeyId(),
                assumeResult.credentials().secretAccessKey(),
                assumeResult.credentials().sessionToken());
    }

    @Override
    public String getDisplayName() {
        if (StringUtils.isBlank(iamRoleArn)) {
            return accessKey;
        }
        return accessKey + ":" + iamRoleArn;
    }

    /*package*/ static StsClient buildStsClient(AwsCredentialsProvider provider) {
        // Check for available region from the SDK, otherwise specify default
        Region clientRegion = determineClientRegion();

        StsClientBuilder builder = StsClient.builder().region(clientRegion).httpClient(getHttpClient());

        if (provider != null) {
            builder = builder.credentialsProvider(provider);
        }

        return builder.build();
    }

    private static AssumeRoleRequest.Builder createAssumeRoleRequest(String iamRoleArn, String iamExternalId) {
        AssumeRoleRequest.Builder retval =
                AssumeRoleRequest.builder().roleArn(iamRoleArn).roleSessionName("Jenkins");
        if (iamExternalId != null && !iamExternalId.isEmpty()) {
            return retval.externalId(iamExternalId);
        }
        return retval;
    }

    /**
     * Provides the {@link StsClient} for a given {@link AwsCredentials}
     *
     * @param awsCredentials
     * @return {@link StsClient}
     */
    private static StsClient getStsClient(AwsCredentials awsCredentials) {
        SdkHttpClient clientConfiguration = getHttpClient();
        Region clientRegion = determineClientRegion();
        return StsClient.builder()
                .region(clientRegion)
                .credentialsProvider(StaticCredentialsProvider.create(awsCredentials))
                .httpClient(clientConfiguration)
                .build();
    }

    /**
     * Provides the {@link SdkHttpClient}
     *
     * @return {@link SdkHttpClient}
     */
    private static SdkHttpClient getHttpClient() {
        Jenkins instance = Jenkins.getInstanceOrNull();

        ProxyConfiguration proxy = instance != null ? instance.proxy : null;
        ApacheHttpClient.Builder builder = ApacheHttpClient.builder();
        if (proxy != null && proxy.name != null && !proxy.name.isEmpty()) {
            software.amazon.awssdk.http.apache.ProxyConfiguration.Builder proxyConfiguration =
                    software.amazon.awssdk.http.apache.ProxyConfiguration.builder()
                            .endpoint(URI.create(String.format("http://%s:%s", proxy.name, proxy.port)));
            if (proxy.getUserName() != null) {
                proxyConfiguration.username(proxy.getUserName());
                proxyConfiguration.password(Secret.toString(proxy.getSecretPassword()));
            }
            builder.proxyConfiguration(proxyConfiguration.build());
        }
        return builder.build();
    }

    @Extension
    public static class DescriptorImpl extends CredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return Messages.AWSCredentialsImpl_DisplayName();
        }

        public static final Integer DEFAULT_STS_TOKEN_DURATION = STS_CREDENTIALS_DURATION_SECONDS;

        @POST
        public FormValidation doCheckSecretKey(
                @QueryParameter("accessKey") final String accessKey,
                @QueryParameter("iamRoleArn") final String iamRoleArn,
                @QueryParameter("iamExternalId") final String iamExternalId,
                @QueryParameter("iamMfaSerialNumber") final String iamMfaSerialNumber,
                @QueryParameter("iamMfaToken") final String iamMfaToken,
                @QueryParameter("stsTokenDuration") final Integer stsTokenDuration,
                @QueryParameter final String secretKey) {
            if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                // for security reasons, do not perform any check if the user is not an admin
                return FormValidation.ok();
            }
            if (StringUtils.isBlank(accessKey) && StringUtils.isBlank(secretKey)) {
                return FormValidation.ok();
            }
            if (StringUtils.isBlank(accessKey)) {
                return FormValidation.error(Messages.AWSCredentialsImpl_SpecifyAccessKeyId());
            }
            if (StringUtils.isBlank(secretKey)) {
                return FormValidation.error(Messages.AWSCredentialsImpl_SpecifySecretAccessKey());
            }

            AwsCredentials awsCredentials = AwsBasicCredentials.create(
                    accessKey, Secret.fromString(secretKey).getPlainText());

            // If iamRoleArn is specified, swap out the credentials.
            if (!StringUtils.isBlank(iamRoleArn)) {

                AssumeRoleRequest.Builder assumeRequest =
                        createAssumeRoleRequest(iamRoleArn, iamExternalId).durationSeconds(stsTokenDuration);

                if (!StringUtils.isBlank(iamMfaSerialNumber)) {
                    if (StringUtils.isBlank(iamMfaToken)) {
                        return FormValidation.error(Messages.AWSCredentialsImpl_SpecifyMFAToken());
                    }
                    assumeRequest =
                            assumeRequest.serialNumber(iamMfaSerialNumber).tokenCode(iamMfaToken);
                }

                try {
                    StsClient stsClient = getStsClient(awsCredentials);
                    AssumeRoleResponse assumeResult = stsClient.assumeRole(assumeRequest.build());

                    awsCredentials = AwsSessionCredentials.create(
                            assumeResult.credentials().accessKeyId(),
                            assumeResult.credentials().secretAccessKey(),
                            assumeResult.credentials().sessionToken());
                } catch (RuntimeException e) {
                    LOGGER.log(
                            Level.WARNING,
                            "Unable to assume role [" + iamRoleArn + "] with request [" + assumeRequest + "]",
                            e);
                    return FormValidation.error(Messages.AWSCredentialsImpl_NotAbleToAssumeRole()
                            + " Check the Jenkins log for more details");
                }
            }

            Ec2Client ec2 = Ec2Client.builder()
                    .credentialsProvider(StaticCredentialsProvider.create(awsCredentials))
                    .httpClient(getHttpClient())
                    .build();

            // TODO better/smarter validation of the credentials instead of verifying the permission on EC2.READ in
            // us-east-1
            String region = "us-east-1";
            try {
                DescribeAvailabilityZonesResponse zonesResult = ec2.describeAvailabilityZones();
                return FormValidation.ok(Messages.AWSCredentialsImpl_CredentialsValidWithAccessToNZones(
                        zonesResult.availabilityZones().size()));
            } catch (AwsServiceException e) {
                if (HttpURLConnection.HTTP_UNAUTHORIZED
                        == e.awsErrorDetails().sdkHttpResponse().statusCode()) {
                    return FormValidation.warning(Messages.AWSCredentialsImpl_CredentialsInValid(e.getMessage()));
                } else if (HttpURLConnection.HTTP_FORBIDDEN
                        == e.awsErrorDetails().sdkHttpResponse().statusCode()) {
                    return FormValidation.ok(
                            Messages.AWSCredentialsImpl_CredentialsValidWithoutAccessToAwsServiceInZone(
                                    e.awsErrorDetails().serviceName(),
                                    region,
                                    e.awsErrorDetails().errorMessage() + " ("
                                            + e.awsErrorDetails().errorCode() + ")"));
                } else {
                    return FormValidation.error(e.getMessage());
                }
            } catch (SdkException e) {
                return FormValidation.error(e.getMessage());
            }
        }
    }
}
