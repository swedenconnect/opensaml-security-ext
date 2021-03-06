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
package se.swedenconnect.opensaml.xmlsec.algorithm.descriptors.curves;

/**
 * Definition of named curve brainpoolP192r1.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class NamedCurve_brainpoolP192r1 extends AbstractNamedCurve {

  /** {@inheritDoc} */
  @Override
  public String getObjectIdentifier() {
    return "1.3.36.3.3.2.8.1.1.3";
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return "brainpoolP192r1";
  }

  /** {@inheritDoc} */
  @Override
  public Integer getKeyLength() {
    return 192;
  }

}
