package org.satochip.applet;

import javacard.framework.CardRuntimeException;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.framework.SystemException;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;
import org.satochip.applet.jcmathlib.*;

final class Ed25519Service {
    private static final short CARD_PROFILE = OperationSupport.JCOP4_P71;
    private static final byte ALLOCATOR_STRATEGY = ObjectAllocator.ALLOCATOR_STRATEGY_TRADEOFF;
    private static final byte WORK_BUFFER_STRATEGY_SHARED_RECV = (byte) 0x03;
    private static final short CURVE_BITS = (short) 256;
    private static final short KEY_SIZE = (short) 32;
    private static final short HASH_SIZE = (short) 64;
    private static final byte WORK_BIGNAT_MEMORY = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
    private static final short OFFSET_RAM = (short) 64;
    private static final short OFFSET_PREFIX = (short) 129;
    private static final short OFFSET_PUBLIC_KEY = (short) 161;
    private static final short OFFSET_PUBLIC_NONCE = (short) 193;
    static final short REQUIRED_WORK_BUFFER_SIZE = (short) 225;

    private final ResourceManager rm;
    private final ECCurve curve;
    private final BigNat privateKey;
    private final BigNat privateNonce;
    private final BigNat signature;
    private final BigNat transformC;
    private final BigNat transformA3;
    private final BigNat transformX;
    private final BigNat transformY;
    private final BigNat eight;
    private final ECPoint point;
    private final MessageDigest hasher;
    private final byte[] workBuffer;

    Ed25519Service(byte[] workBuffer) {
        short initStage = (short) 0;
        try {
            initStage = (short) 1;
            OperationSupport.getInstance().setCard(CARD_PROFILE);

            initStage = (short) 2;
            hasher = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);

            initStage = (short) 3;
            rm = new ResourceManager(CURVE_BITS, ALLOCATOR_STRATEGY);

            initStage = (short) 4;
            privateKey = new BigNat(KEY_SIZE, WORK_BIGNAT_MEMORY, rm);
            privateNonce = new BigNat(HASH_SIZE, WORK_BIGNAT_MEMORY, rm);
            signature = new BigNat(HASH_SIZE, WORK_BIGNAT_MEMORY, rm);

            initStage = (short) 5;
            transformC = new BigNat(KEY_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
            transformC.fromByteArray(Ed25519Consts.TRANSFORM_C, (short) 0, (short) Ed25519Consts.TRANSFORM_C.length);
            transformA3 = new BigNat(KEY_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
            transformA3.fromByteArray(Ed25519Consts.TRANSFORM_A3, (short) 0, (short) Ed25519Consts.TRANSFORM_A3.length);
            transformX = new BigNat(KEY_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
            transformY = new BigNat(KEY_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);

            initStage = (short) 6;
            eight = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
            eight.setValue((byte) 8);

            initStage = (short) 7;
            curve = new ECCurve(Wei25519.p, Wei25519.a, Wei25519.b, Wei25519.G, Wei25519.r, Wei25519.k, rm);
            point = new ECPoint(curve);

            initStage = (short) 8;
            if (workBuffer == null || workBuffer.length < REQUIRED_WORK_BUFFER_SIZE)
                ISOException.throwIt((short) 0xE608);
            this.workBuffer = workBuffer;
        } catch (ISOException e) {
            throw e;
        } catch (CryptoException e) {
            ISOException.throwIt((short) ((short) 0xE300 + initStage));
            throw e;
        } catch (SystemException e) {
            ISOException.throwIt((short) ((short) 0xE400 + initStage));
            throw e;
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) ((short) 0xE500 + initStage));
            throw e;
        }
    }

    static byte getAllocatorStrategyCode() {
        return ALLOCATOR_STRATEGY;
    }

    static byte getWorkBufferStrategyCode() {
        return WORK_BUFFER_STRATEGY_SHARED_RECV;
    }

    void afterReset() {
        curve.updateAfterReset();
        clearWorkingState();
    }

    void clearWorkingState() {
        privateKey.zero();
        privateNonce.zero();
        signature.zero();
        Util.arrayFillNonAtomic(workBuffer, OFFSET_RAM, (short) (REQUIRED_WORK_BUFFER_SIZE - OFFSET_RAM), (byte) 0x00);
    }

    void loadSeed(byte[] seed, short seedOffset) {
        hasher.reset();
        hasher.doFinal(seed, seedOffset, KEY_SIZE, workBuffer, OFFSET_RAM);
        workBuffer[OFFSET_RAM] &= (byte) 0xf8;
        workBuffer[(short) (OFFSET_RAM + 31)] &= (byte) 0x7f;
        workBuffer[(short) (OFFSET_RAM + 31)] |= (byte) 0x40;
        changeEndianity(workBuffer, OFFSET_RAM, KEY_SIZE);

        Util.arrayCopyNonAtomic(workBuffer, (short) (OFFSET_RAM + KEY_SIZE), workBuffer, OFFSET_PREFIX, KEY_SIZE);

        privateKey.fromByteArray(workBuffer, OFFSET_RAM, KEY_SIZE);
        privateKey.shiftRight((short) 3);
        point.setW(curve.G, (short) 0, curve.POINT_SIZE);
        point.multiplication(privateKey);
        privateKey.fromByteArray(workBuffer, OFFSET_RAM, KEY_SIZE);
        privateKey.mod(curve.rBN);

        point.multiplication(eight);
        encodeEd25519(point, workBuffer, OFFSET_PUBLIC_KEY);
        Util.arrayFillNonAtomic(workBuffer, OFFSET_RAM, HASH_SIZE, (byte) 0x00);
    }

    short getPublicKey(byte[] outBuffer, short outOffset) {
        Util.arrayCopyNonAtomic(workBuffer, OFFSET_PUBLIC_KEY, outBuffer, outOffset, KEY_SIZE);
        return KEY_SIZE;
    }

    short sign(byte[] msg, short msgOffset, short msgLength, byte[] outBuffer, short outOffset) {
        deterministicNonce(msg, msgOffset, msgLength);

        point.setW(curve.G, (short) 0, curve.POINT_SIZE);
        point.multiplication(privateNonce);
        encodeEd25519(point, workBuffer, OFFSET_PUBLIC_NONCE);

        hasher.reset();
        hasher.update(workBuffer, OFFSET_PUBLIC_NONCE, KEY_SIZE);
        hasher.update(workBuffer, OFFSET_PUBLIC_KEY, KEY_SIZE);
        hasher.doFinal(msg, msgOffset, msgLength, workBuffer, OFFSET_RAM);
        changeEndianity(workBuffer, OFFSET_RAM, HASH_SIZE);
        signature.fromByteArray(workBuffer, OFFSET_RAM, HASH_SIZE);
        signature.mod(curve.rBN);
        signature.resize(KEY_SIZE);

        signature.modMult(privateKey, curve.rBN);
        signature.modAdd(privateNonce, curve.rBN);

        Util.arrayCopyNonAtomic(workBuffer, OFFSET_PUBLIC_NONCE, outBuffer, outOffset, KEY_SIZE);
        signature.prependZeros(KEY_SIZE, outBuffer, (short) (outOffset + KEY_SIZE));
        changeEndianity(outBuffer, (short) (outOffset + KEY_SIZE), KEY_SIZE);
        Util.arrayFillNonAtomic(workBuffer, OFFSET_RAM, HASH_SIZE, (byte) 0x00);
        return (short) (KEY_SIZE + KEY_SIZE);
    }

    private void encodeEd25519(ECPoint pointValue, byte[] buffer, short offset) {
        pointValue.getW(workBuffer, OFFSET_RAM);

        transformX.fromByteArray(workBuffer, (short) (OFFSET_RAM + 1), KEY_SIZE);
        transformY.fromByteArray(workBuffer, (short) (OFFSET_RAM + 33), KEY_SIZE);
        transformX.modSub(transformA3, curve.pBN);
        transformX.modMult(transformC, curve.pBN);
        transformY.modInv(curve.pBN);
        transformX.modMult(transformY, curve.pBN);

        boolean xBit = transformX.isOdd();

        transformX.fromByteArray(workBuffer, (short) (OFFSET_RAM + 1), KEY_SIZE);
        transformX.modSub(transformA3, curve.pBN);
        transformY.clone(transformX);
        transformX.decrement();
        transformY.increment();
        transformY.mod(curve.pBN);
        transformY.modInv(curve.pBN);
        transformX.modMult(transformY, curve.pBN);
        transformX.prependZeros(KEY_SIZE, buffer, offset);

        buffer[offset] |= xBit ? (byte) 0x80 : (byte) 0x00;
        changeEndianity(buffer, offset, KEY_SIZE);
    }

    private void deterministicNonce(byte[] msg, short offset, short len) {
        hasher.reset();
        hasher.update(workBuffer, OFFSET_PREFIX, KEY_SIZE);
        hasher.doFinal(msg, offset, len, workBuffer, OFFSET_RAM);
        changeEndianity(workBuffer, OFFSET_RAM, HASH_SIZE);
        privateNonce.fromByteArray(workBuffer, OFFSET_RAM, HASH_SIZE);
        privateNonce.mod(curve.rBN);
        privateNonce.resize(KEY_SIZE);
    }

    private void changeEndianity(byte[] array, short offset, short len) {
        for (short i = 0; i < (short) (len / 2); i++) {
            short left = (short) (offset + i);
            short right = (short) (offset + len - i - 1);
            byte tmp = array[right];
            array[right] = array[left];
            array[left] = tmp;
        }
    }
}
