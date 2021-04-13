/*
 * The MIT License
 *
 * Copyright (c) 2018, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.cloudbees.jenkins.plugins.awscredentials;

import com.cloudbees.plugins.credentials.common.StandardCredentials;
import org.jenkinsci.plugins.variant.OptionalExtension;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.jenkinsci.plugins.pipeline.modeldefinition.model.CredentialsBindingHandler;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@OptionalExtension(requirePlugins = "pipeline-model-extensions")
public class AWSDeclarativeCredentialsHandler extends CredentialsBindingHandler<AmazonWebServicesCredentials> {

    @Nonnull
    @Override
    public List<MultiBinding<AmazonWebServicesCredentials>> toBindings(String varName, String credentialsId) {
        return Collections.singletonList(new AmazonWebServicesCredentialsBinding(varName + "_AWS_KEY_ID",
                varName + "_AWS_SECRET",
                varName + "_AWS_SESSION_TOKEN",
                credentialsId));
    }

    @Nonnull
    @Override
    public Class<? extends StandardCredentials> type() {
        return AmazonWebServicesCredentials.class;
    }

    @Nonnull
    @Override
    public List<Map<String, Object>> getWithCredentialsParameters(String credentialsId) {
        Map<String, Object> map = new HashMap<>();
        map.put("$class", AmazonWebServicesCredentialsBinding.class.getName());
        map.put("keyIdVariable", new EnvVarResolver("%s_AWS_KEY_ID"));
        map.put("secretVariable", new EnvVarResolver("%s_AWS_SECRET"));
        map.put("sessionTokenVariable", new EnvVarResolver("%s_AWS_SESSION_TOKEN"));
        map.put("credentialsId", credentialsId);
        return Collections.singletonList(map);
    }
}
