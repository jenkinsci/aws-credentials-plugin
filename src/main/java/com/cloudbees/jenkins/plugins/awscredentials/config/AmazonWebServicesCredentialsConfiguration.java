package com.cloudbees.jenkins.plugins.awscredentials.config;

import hudson.Extension;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;

@Extension
public final class AmazonWebServicesCredentialsConfiguration extends GlobalConfiguration {
    private boolean validateAgainstAWS = true;

    public AmazonWebServicesCredentialsConfiguration() {
        load();
    }

    public static AmazonWebServicesCredentialsConfiguration get() {
        return (AmazonWebServicesCredentialsConfiguration) Jenkins.get().getDescriptor(AmazonWebServicesCredentialsConfiguration.class);
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
        validateAgainstAWS = json.getBoolean("validateAgainstAWS");
        save();
        return super.configure(req, json);
    }

    public boolean isValidateAgainstAWS() {
        return validateAgainstAWS;
    }

    public void setValidateAgainstAWS(boolean validateAgainstAWS) {
        this.validateAgainstAWS = validateAgainstAWS;
    }
}
