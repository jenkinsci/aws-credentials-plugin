package com.cloudbees.jenkins.plugins.awscredentials;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * Unit tests for the {@link AWSDeclarativeCredentialsHandler} class.
 */
@RunWith(MockitoJUnitRunner.class)
public class AWSDeclarativeCredentialsHandlerTest {

    private AWSDeclarativeCredentialsHandler handler;

    @Before
    public void setUp() {
        handler = new AWSDeclarativeCredentialsHandler();
    }

    @Test
    public void testType() {
        // Verify that the handler returns the correct credential type
        assertEquals(AmazonWebServicesCredentials.class, handler.type());
    }

    @Test
    public void testGetWithCredentialsParameters() {
        // Test credential ID
        String credentialsId = "test-credentials-id";

        // Get parameters
        List<Map<String, Object>> parameters = handler.getWithCredentialsParameters(credentialsId);

        // Verify the result is not null and has exactly one entry
        assertNotNull("Parameters should not be null", parameters);
        assertEquals("Should return a singleton list", 1, parameters.size());

        // Get the map from the list
        Map<String, Object> paramMap = parameters.get(0);

        // Verify the class name
        assertEquals(
                "Class name should match AmazonWebServicesCredentialsBinding",
                AmazonWebServicesCredentialsBinding.class.getName(),
                paramMap.get("$class"));

        // Verify credentials ID
        assertEquals("Credentials ID should match the provided value", credentialsId, paramMap.get("credentialsId"));

        // Verify key format variables
        assertTrue("Should contain keyIdVariable", paramMap.containsKey("keyIdVariable"));
        assertTrue("Should contain secretVariable", paramMap.containsKey("secretVariable"));
        assertTrue("Should contain sessionTokenVariable", paramMap.containsKey("sessionTokenVariable"));

        // Verify the EnvVarResolver objects (we can only test that they're not null, as we don't have access to the
        // EnvVarResolver class)
        assertNotNull("keyIdVariable should not be null", paramMap.get("keyIdVariable"));
        assertNotNull("secretVariable should not be null", paramMap.get("secretVariable"));
        assertNotNull("sessionTokenVariable should not be null", paramMap.get("sessionTokenVariable"));
    }
}
