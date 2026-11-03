package com.cloudbees.jenkins.plugins.awscredentials;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collection;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.MockedConstruction;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.services.sts.StsClient;

@RunWith(Parameterized.class)
public class AWSCredentialsImplTest {
    @Parameterized.Parameters(name = "configured={0}, role={1}, expected={2}")
    public static Collection<Object[]> regions() {
        String commercialRole = "arn:aws:iam::123456789012:role/test";
        String chinaRole = "arn:aws-cn:iam::123456789012:role/test";
        String govCloudRole = "arn:aws-us-gov:iam::123456789012:role/test";
        return Arrays.asList(new Object[][] {
            {null, commercialRole, Region.US_EAST_1},
            {null, chinaRole, Region.CN_NORTH_1},
            {null, govCloudRole, Region.US_GOV_WEST_1},
            {Region.EU_WEST_1, commercialRole, Region.EU_WEST_1},
            {Region.US_EAST_1, chinaRole, Region.CN_NORTH_1},
            {Region.US_EAST_1, govCloudRole, Region.US_GOV_WEST_1},
            {Region.CN_NORTHWEST_1, chinaRole, Region.CN_NORTHWEST_1},
            {Region.US_GOV_EAST_1, govCloudRole, Region.US_GOV_EAST_1},
            {Region.CN_NORTH_1, govCloudRole, Region.US_GOV_WEST_1},
            {Region.US_GOV_WEST_1, chinaRole, Region.CN_NORTH_1},
            {Region.CN_NORTH_1, commercialRole, Region.US_EAST_1},
            {Region.US_GOV_WEST_1, commercialRole, Region.US_EAST_1},
            {Region.EU_WEST_1, null, Region.EU_WEST_1},
            {Region.EU_WEST_1, "", Region.EU_WEST_1},
            {Region.EU_WEST_1, "invalid", Region.EU_WEST_1},
            {Region.EU_WEST_1, "arn:unknown:iam::123456789012:role/test", Region.EU_WEST_1},
            {null, null, Region.US_EAST_1}
        });
    }

    private final Region configuredRegion;
    private final String roleArn;
    private final Region expectedRegion;

    public AWSCredentialsImplTest(Region configuredRegion, String roleArn, Region expectedRegion) {
        this.configuredRegion = configuredRegion;
        this.roleArn = roleArn;
        this.expectedRegion = expectedRegion;
    }

    @Test
    public void selectsRegionInRolePartition() {
        try (MockedConstruction<DefaultAwsRegionProviderChain> ignored = mockConstruction(
                        DefaultAwsRegionProviderChain.class, (lookup, context) -> {
                            if (configuredRegion == null) {
                                when(lookup.getRegion()).thenThrow(SdkClientException.create("No configured region"));
                            } else {
                                when(lookup.getRegion()).thenReturn(configuredRegion);
                            }
                        });
                StsClient client = AWSCredentialsImpl.buildStsClient(
                        StaticCredentialsProvider.create(AwsBasicCredentials.create("test-access", "test-secret")),
                        roleArn)) {
            assertEquals(expectedRegion, client.serviceClientConfiguration().region());
        }
    }
}
