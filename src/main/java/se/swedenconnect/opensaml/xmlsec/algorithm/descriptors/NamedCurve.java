/*
 * Copyright 2019-2021 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.opensaml.xmlsec.algorithm.descriptors;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * A representation of a named elliptic curve.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface NamedCurve {

  /**
   * Gets the Object Identifier (OID) for the named curve.
   * 
   * @return the object identifier
   */
  @Nonnull
  @NotEmpty
  String getObjectIdentifier();

  /**
   * Gets the name for the curve.
   * 
   * @return the name of the curve
   */
  @Nonnull
  @NotEmpty
  String getName();

  /**
   * Gets the URI for the curve.
   * 
   * @return the URI for the curve
   */
  @Nonnull
  @NotEmpty
  String getURI();

  /**
   * Gets the key length for the curve.
   * 
   * @return the key length
   */
  @Nonnull
  Integer getKeyLength();

}
