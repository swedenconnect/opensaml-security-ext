/*
 * Copyright 2019 Sweden Connect
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
package se.swedenconnect.opensaml;

/**
 * Interface for customized initialization and configuration of OpenSAML. {@code OpenSAMLInitializerConfig} instance are
 * supplied to {@link OpenSAMLInitializer#initialize(OpenSAMLInitializerConfig...)} in order to extend the core
 * initialization.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface OpenSAMLInitializerConfig {

  /**
   * The name of this configurer. Used for logging only.
   * 
   * @return the name of the configurer
   */
  String getName();

  /**
   * Method that is called before OpenSAML is initialized. The implementation typically perform steps necessary before
   * the OpenSAML library is initialized.
   * 
   * @throws Exception
   *           for init errors
   */
  void preInitialize() throws Exception;

  /**
   * Called after OpenSAML has been initialized. The implementation typically contains code for additional configuration
   * such as algorithm support.
   * 
   * @throws Exception
   *           for init errors
   */
  void postInitialize() throws Exception;

}
