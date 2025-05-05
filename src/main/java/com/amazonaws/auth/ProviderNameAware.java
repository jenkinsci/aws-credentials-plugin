/*
 * Copyright 2011-2024 Amazon Technologies, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *    http://aws.amazon.com/apache2.0
 *
 * This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and
 * limitations under the License.
 */
package com.amazonaws.auth;

/**
 * Interface to represent the name of the entity that resolved these credentials.
 */
@Deprecated(forRemoval = true)
public interface ProviderNameAware {
    /**
     * The name of the source that resolved these credentials, normally a credentials provider.
     *
     * @return The name of the source that resolved these credentials, normally a credentials provider.
     */
    String getProviderName();
}
