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
package se.swedenconnect.opensaml.xmlsec.signature.support.provider.padding;

/**
 * Interface for Mask Generation Function.
 * 
 * @author Stefan Santesson (stefan@idsec.se)
 * @author Martin Lindström (martin@idsec.se)
 */
public interface MGF {

  /**
   * Generates mask data.
   * 
   * @param seed
   *          the input seed
   * @param length
   *          the mask data length (in bytes)
   * @return the generated mask data
   */
  byte[] getMask(byte[] seed, int length);

}
