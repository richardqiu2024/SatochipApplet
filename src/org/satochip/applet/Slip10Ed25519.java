package org.satochip.applet;

import javacard.framework.Util;

final class Slip10Ed25519 {
    static final short KEY_SIZE = (short) 32;
    static final short CHAINCODE_SIZE = (short) 32;
    static final short NODE_SIZE = (short) (KEY_SIZE + CHAINCODE_SIZE);
    static final byte MAX_PATH_DEPTH = (byte) 10;

    private static final short OFFSET_TMP_DATA = NODE_SIZE;
    private static final short OFFSET_TMP_OUT = (short) (OFFSET_TMP_DATA + 37);
    static final short REQUIRED_BUFFER_SIZE = (short) (OFFSET_TMP_OUT + NODE_SIZE);

    private static final byte[] ED25519_SEED = {
            (byte) 'e', (byte) 'd', (byte) '2', (byte) '5', (byte) '5', (byte) '1',
            (byte) '9', (byte) ' ', (byte) 's', (byte) 'e', (byte) 'e', (byte) 'd'
    };

    private Slip10Ed25519() {
    }

    static void deriveMaster(byte[] seed, short seedOffset, short seedLength, byte[] workBuffer, short workOffset) {
        HmacSha512.computeHmacSha512(
                ED25519_SEED, (short) 0, (short) ED25519_SEED.length,
                seed, seedOffset, seedLength,
                workBuffer, workOffset);
    }

    static void derivePath(byte[] workBuffer, short workOffset, byte[] path, short pathOffset, byte depth) {
        short cursor = pathOffset;
        for (byte i = 0; i < depth; i++) {
            deriveChild(workBuffer, workOffset, path, cursor);
            cursor += (short) 4;
        }
    }

    static boolean isHardenedPath(byte[] path, short pathOffset, byte depth) {
        short cursor = pathOffset;
        for (byte i = 0; i < depth; i++) {
            if ((path[cursor] & (byte) 0x80) == 0) {
                return false;
            }
            cursor += (short) 4;
        }
        return true;
    }

    private static void deriveChild(byte[] workBuffer, short workOffset, byte[] index, short indexOffset) {
        short tmpDataOffset = (short) (workOffset + OFFSET_TMP_DATA);
        short tmpOutOffset = (short) (workOffset + OFFSET_TMP_OUT);
        short keyOffset = workOffset;
        short chaincodeOffset = (short) (workOffset + KEY_SIZE);

        workBuffer[tmpDataOffset] = (byte) 0x00;
        Util.arrayCopyNonAtomic(workBuffer, keyOffset, workBuffer, (short) (tmpDataOffset + 1), KEY_SIZE);
        Util.arrayCopyNonAtomic(index, indexOffset, workBuffer, (short) (tmpDataOffset + 33), (short) 4);

        HmacSha512.computeHmacSha512(
                workBuffer, chaincodeOffset, CHAINCODE_SIZE,
                workBuffer, tmpDataOffset, (short) 37,
                workBuffer, tmpOutOffset);

        Util.arrayCopyNonAtomic(workBuffer, tmpOutOffset, workBuffer, keyOffset, NODE_SIZE);
    }
}
