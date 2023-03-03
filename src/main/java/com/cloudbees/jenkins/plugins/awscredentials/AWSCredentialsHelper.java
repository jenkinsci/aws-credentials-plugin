package com.cloudbees.jenkins.plugins.awscredentials;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.AbstractIdCredentialsListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.security.ACL;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;

import java.util.Collections;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * @author <a href="mailto:nicolas.deloof@gmail.com">Nicolas De Loof</a>
 */
public class AWSCredentialsHelper {

    private AWSCredentialsHelper() {}

    @CheckForNull
    public static AmazonWebServicesCredentials getCredentials(@Nullable String credentialsId, ItemGroup context) {
        if (StringUtils.isBlank(credentialsId)) {
            return null;
        }
        return (AmazonWebServicesCredentials) CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentials(AmazonWebServicesCredentials.class, context,
                        ACL.SYSTEM, Collections.EMPTY_LIST),
                CredentialsMatchers.withId(credentialsId));
    }

    private static boolean hasPermission(ItemGroup context) {
        if (context instanceof Item) {
            return ((Item) context).hasPermission(Item.CONFIGURE);
        } else {
            return Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER);
        }
    }

    public static ListBoxModel doFillCredentialsIdItems(ItemGroup context) {
        AbstractIdCredentialsListBoxModel result = new StandardListBoxModel().includeEmptyValue();
        if (hasPermission(context)) {
            result = result.withMatching(
                            CredentialsMatchers.always(),
                            CredentialsProvider.lookupCredentials(AmazonWebServicesCredentials.class,
                                    context,
                                    ACL.SYSTEM,
                                    Collections.EMPTY_LIST));
        }
        return result;
    }
}
