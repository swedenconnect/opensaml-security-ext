/*
 * Copyright 2019-2023 Sweden Connect
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

import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.StringSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A registry for all supported Elliptic curves.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class NamedCurveRegistry {

  /** Logger. */
  private Logger log = LoggerFactory.getLogger(NamedCurveRegistry.class);

  /** Map of registered curves. */
  private Map<String, NamedCurve> curves;

  /**
   * Constructor.
   */
  public NamedCurveRegistry() {
    this.curves = new HashMap<>();
  }

  /**
   * Get the curve associated with the specified object identifier.
   *
   * @param oid
   *          the OID for the curve to resolve
   *
   * @return the resolved curve or {@code null}
   */
  @Nullable
  public NamedCurve get(final String oid) {
    final String trimmedOid = StringSupport.trimOrNull(oid);
    if (trimmedOid == null) {
      return null;
    }
    return this.curves.get(trimmedOid);
  }

  /**
   * Clear all registered curves.
   */
  public void clear() {
    this.curves.clear();
  }

  /**
   * Register a curve.
   *
   * @param curve
   *          the curve
   */
  public void register(@Nonnull final NamedCurve curve) {
    Constraint.isNotNull(curve, "curve must not be null");

    log.debug("Registering curve with OID: {} ({})", curve.getObjectIdentifier(), curve.getName());

    final NamedCurve old = this.curves.get(curve.getObjectIdentifier());
    if (old != null) {
      log.debug("Registry contained existing curve, removing old instance and re-registering: {}", curve.getObjectIdentifier());
    }
    this.curves.put(curve.getObjectIdentifier(), curve);
  }

  /**
   * Deregister a curve.
   *
   * @param curve
   *          the curve
   */
  public void deregister(@Nonnull final NamedCurve curve) {
    Constraint.isNotNull(curve, "curve must not be null");
    if (this.curves.containsKey(curve.getObjectIdentifier())) {
      this.curves.remove(curve.getObjectIdentifier());
      log.debug("Re-registered curve {}", curve.getObjectIdentifier());
    }
    else {
      log.debug("Registry did not contain curve with OID '{}', nothing to do", curve.getObjectIdentifier());
    }
  }

  /**
   * Deregister a curve.
   *
   * @param oid
   *          the OID for the curve
   */
  public void deregister(@Nonnull final String oid) {
    Constraint.isNotNull(oid, "oid must not be null");
    final NamedCurve curve = this.get(oid);
    if (curve != null) {
      this.deregister(curve);
    }
  }

}
