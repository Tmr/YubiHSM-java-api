/*
 * Copyright (c) 2011 United ID. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author Stefan Wold <stefan.wold@unitedid.org>
 */

package org.unitedid.yhsm.internal;

import static org.unitedid.yhsm.internal.Defines.*;
import static org.unitedid.yhsm.utility.Utils.*;

/** <code>AESECBCmd</code> implements AES ECB block cipher commands for the YubiHSM. */
public class AESECBCmd {

    /** Private constructor */
    private AESECBCmd() {}

    /**
     * AES ECB encrypt one block with size of YSM_BLOCK_SIZE bytes using a specific key handle.
     *
     * @param deviceHandler the device handler
     * @param keyHandle the key handle to use when encrypting AES ECB
     * @param bytes the bytes to encrypt
     * @return a hash string in hex format
     * @throws YubiHSMInputException if an argument does not validate
     * @throws YubiHSMErrorException if validation fail for some values returned by the YubiHSM
     * @throws YubiHSMCommandFailedException if the YubiHSM fail to execute the command
     */

    public static byte[] encryptBlock(DeviceHandler deviceHandler, int keyHandle, byte[] bytes) throws YubiHSMInputException, YubiHSMErrorException, YubiHSMCommandFailedException {
        byte[] cmdBuffer = concatAllArrays(leIntToBA(keyHandle), validateByteArray("bytes", bytes, YSM_BLOCK_SIZE, 0, YSM_BLOCK_SIZE));
        byte[] result = CommandHandler.execute(deviceHandler, YSM_AES_ECB_BLOCK_ENCRYPT, cmdBuffer, true);

        return parseResult(result, keyHandle, YSM_AES_ECB_BLOCK_ENCRYPT);
    }

    /**
     * AES ECB decrypt a cipher array of bytes of size YSM_BLOCK_SIZE using a specific key handle.
     *
     * @param deviceHandler the device handler
     * @param keyHandle the key handle to use when decrypting AES ECB
     * @param cipherBytes the cipher string
     * @return a plaintext string
     * @throws YubiHSMInputException if an argument does not validate
     * @throws YubiHSMErrorException if validation fail for some values returned by the YubiHSM
     * @throws YubiHSMCommandFailedException if the YubiHSM fail to execute the command
     */
    public static byte[] decryptBlock(DeviceHandler deviceHandler, int keyHandle, byte[] cipherBytes) throws YubiHSMErrorException, YubiHSMInputException, YubiHSMCommandFailedException {
        byte[] cmdBuffer = concatAllArrays(leIntToBA(keyHandle), validateByteArray("cipherBytes", cipherBytes, 0, YSM_BLOCK_SIZE, 0));
        byte[] result = CommandHandler.execute(deviceHandler, YSM_AES_ECB_BLOCK_DECRYPT, cmdBuffer, true);

        return parseResult(result, keyHandle, YSM_AES_ECB_BLOCK_DECRYPT);
    }

    /**
     * AES ECB decrypt a cipher text using a specific key handle, and then compare it with the supplied plaintext.
     *
     * @param deviceHandler the device handler
     * @param keyHandle the key handle to use when comparing AES ECB cipher with plaintext
     * @param cipherText the cipher string
     * @param plaintext the plaintext string
     * @return true if successful, false if not successful
     * @throws YubiHSMInputException if an argument does not validate
     * @throws YubiHSMErrorException if validation fail for some values returned by the YubiHSM
     * @throws YubiHSMCommandFailedException if the YubiHSM fail to execute the command
     */
    public static boolean compare(DeviceHandler deviceHandler, int keyHandle, String cipherText, String plaintext) throws YubiHSMInputException, YubiHSMErrorException, YubiHSMCommandFailedException {
        byte[] cipherTextBA = validateByteArray("cipherText", hexToByteArray(cipherText), 0, YSM_BLOCK_SIZE, 0);
        byte[] plaintextBA = validateByteArray("plaintext", plaintext.getBytes(), YSM_BLOCK_SIZE, 0, YSM_BLOCK_SIZE);
        byte[] keyHandleBA = leIntToBA(keyHandle);
        byte[] cmdBuffer = concatAllArrays(keyHandleBA, cipherTextBA, plaintextBA);
        byte[] result = CommandHandler.execute(deviceHandler, YSM_AES_ECB_BLOCK_DECRYPT_CMP, cmdBuffer, true);

        validateCmdResponseBA("keyHandle", rangeOfByteArray(result, 0, 4), keyHandleBA);

        if (result[4] == YSM_STATUS_OK) {
            return true;
        } else if (result[4] == YSM_MISMATCH) {
            return false;
        } else {
            throw new YubiHSMCommandFailedException("Command " + getCommandString(YSM_AES_ECB_BLOCK_DECRYPT_CMP) + " failed: " + getCommandStatus(result[4]));
        }
    }

    /**
     * Parse the response from the YubiHSM for a previous command.
     *
     * @param data the YubiHSM response data
     * @param keyHandle the key handle used for the command
     * @param command the YubiHSM command executed
     * @return an array of bytes with operation result
     * @throws YubiHSMErrorException if validation fail for some values returned by the YubiHSM
     * @throws YubiHSMCommandFailedException if the YubiHSM fail to execute the command
     */
    private static byte[] parseResult(byte[] data, int keyHandle, byte command) throws YubiHSMErrorException, YubiHSMCommandFailedException {
        validateCmdResponseBA("keyHandle", rangeOfByteArray(data, 0, 4), leIntToBA(keyHandle));
        byte[] result = rangeOfByteArray(data, 4, YSM_BLOCK_SIZE);

        if (data[20] == YSM_STATUS_OK) {
            return result;
        } else {
            throw new YubiHSMCommandFailedException("Command " + getCommandString(command) + " failed: " + getCommandStatus(data[20]));
        }
    }
}
