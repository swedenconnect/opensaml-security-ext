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
package se.swedenconnect.opensaml.xmlsec.signature.support.provider.padding;

import java.security.MessageDigest;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.opensaml.OpenSAMLTestBase;

/**
 * Test cases for {@code SCPSSPadding}.
 *
 * @author Stefan Santesson (stefan@idsec.se)
 * @author Martin Lindström (martin@idsec.se)
 */
public class SCPSSPaddingTest extends OpenSAMLTestBase {

  /** Salt value */
  private static final String SALT = "a8b55f4f42b3d20165afae54becbfc9bd85d437eb2e3eaf535555b262380688b";

  /** Message value */
  private static final String MESSAGE = "Message01234";

  /** Output encoded message from PSS padding for modulus 4096 */
  private static final String PSSPadding =
      "2348e7b8504e54ee39d2a47a2759e8a554099b4a82536d03f7ab0614ba396cf9f409363fd3669db9769a24ab37580e1b49f08343f02e2d7f044e62ca0c8ceed0ae1618c74fa631d2da39be3f9cd3bbc0c993df505addecfc5809a72f11f9a83a553c8312c70ffde789b5540def34bd464c13595faf3c3e57fa940055821c40689bc5526ed5393cd800b6336d5be90c74adecdda7a95fb1cc0376c2cd43a9d560cc498166d9b1b85c3899d5c9f86c88405c527dc54dc15f8002a79a4d85d2ea6b13d32e8e07fe784a3607eeb76bff4063314d5b00de0939adbf1510a56f557eb72ac5174362294370fb74db12d75ac53948b965d73c9110eb7918bf1bc943899263f98934298a6ff3a51ff4164234ca3b339dfb2f3a9d16d5d6e694dd511749390750a08553d75751ea9e75d3c3e604d3535b3e0ee4077c93861d3590936e079ad58c87d7740e402cd0e5aee536618a525a4def9027673eb23a39f05c7e28e9d14d8ebf854da83c967d5f8fa337ea5be56e8b7226a2f5a66d80511947e8a2851a286fc831dc7d26809ac4b553ca7a599d0169d4a2ea6d747317b606e4aca0ffb055f6614272eb1dbd95863c8320d0d8df24405647a921070ce615d57aa4701590760f84bbcc9c40e2d98e7287beab275b128c24111b83782e4478b311b731e74cce3d9c42023bd2d57bce0b7cb7780235b4d54a896913960bd1f6496bb1869abc";

  /**
   * Test that generation of RSA PSS padding using a fixed message and a fixed salt generates the expected output
   *
   * @throws Exception exception
   */
  @Test
  public void testPSSPadding() throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    SCPSSPadding pssPadding = new SCPSSPadding(digest, 4096);
    pssPadding.setSalt(getSalt());
    byte[] pssPaddingFromMessage = pssPadding.getPaddingFromMessage(getMessage());
    Assertions.assertArrayEquals(getEm(), pssPaddingFromMessage);
  }

  /**
   * Test that an attempt to provide padding for too small RSA modulus is rejected.
   */
  @Test
  public void testIllegalPadding() throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    // 522 bit modulus would be OK but 521 is 1 bit to small.
    SCPSSPadding pssPadding = new SCPSSPadding(digest, 521);
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      pssPadding.getPaddingFromMessage(getMessage());
    });
  }

  private static byte[] getSalt() {
    return Hex.decode(SALT);
  }

  private static byte[] getMessage() {
    return MESSAGE.getBytes();
  }

  private static byte[] getEm() {
    return Hex.decode(PSSPadding);
  }

}
