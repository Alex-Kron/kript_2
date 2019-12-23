package safer;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

public class Safer {
    private byte[] information;
    private double encodeBit;
    private double decodeBit;
    private ArrayList<Byte[]> blocks;
    private int round = 6;
    private ArrayList<Byte[]> keys;
    private Byte[] byteFirstKey;
    private int blockSize = 8;
    private BigInteger koef = new BigInteger("45");

    Safer(String filename) {
        information = FileWorker.read(filename);
        blocks = new ArrayList<>();
        keys = new ArrayList<>();
        byte[] firstKey = new byte[blockSize];
        byteFirstKey = new Byte[blockSize];
        Random r = new Random();
        r.nextBytes(firstKey);
        for (int i = 0; i < firstKey.length; i++) {
            byteFirstKey[i] = firstKey[i];
        }
    }

    public static void main(String[] args) {
        Safer test = new Safer("/home/kron/Labs/Crypto2/test2.bmp");
        test.breakIntoBlocks();
        test.keyFiller();
        test.encoding();
        test.write("/home/kron/Labs/Crypto2/encode.bmp");
        double cor = test.correlation();
        System.out.println("Correlation: " + cor + "\nDecode distribution of units = " + test.decodeBit + "\nEncode distribution of units = " + test.encodeBit);
        test.decoding();
        test.write("/home/kron/Labs/Crypto2/res.bmp");
    }

    private void keyFiller() {
        for (int k = 0; k < round; k++) {
            if (keys.isEmpty()) {
                keys.add(byteFirstKey);
                keys.add(keyGen());
            } else {
                keys.add(keyGen());
                keys.add(keyGen());
            }
        }
    }

    private double correlation() {
        int corBit = 0;
        int notBit = 0;
        int encZero = 0;
        int encUnit = 0;
        int decZero = 0;
        int decUnit = 0;
        int cor = 0;
        for (int j = 0; j < blocks.size(); j++)
            for(int i = 0; i < 8; i++) {
                if (8 * j + i  >= information.length) {
                    break;
                }
                Byte[] tmp = blocks.get(j);
                String inf = Integer.toBinaryString(information[8 * j + i] & 0xff);
                String blc = Integer.toBinaryString(tmp[i] & 0xff);
                if (inf.length() < 8) {
                    int len1 = inf.length();
                    for (int f = 0; f < (8 - len1); f++) {
                        inf = "0" + inf;
                    }
                }
                if (blc.length() < 8) {
                    int len2 = blc.length();
                    for (int f = 0; f < (8 - len2); f++) {
                        blc = "0" + blc;
                    }
                }
                for (int t = 0; t < 8; t++) {
                    if (blc.charAt(t) == '0') {
                        encZero++;
                    }
                    if (blc.charAt(t) == '1') {
                        encUnit++;
                    }
                    if (inf.charAt(t) == '0') {
                        decZero++;
                    }
                    if (inf.charAt(t) == '1') {
                        decUnit++;
                    }
                    if (inf.charAt(t) == blc.charAt(t)) {
                        corBit++;
                    } else {
                        notBit++;
                    }
                    int x = 0;
                    int y = 0;
                    if (blc.charAt(t) == '1') {
                        x = 1;
                    } else {
                        x = 0;
                    }
                    if (inf.charAt(t) == '1') {
                        y = 1;
                    } else {
                        y = 0;
                    }
                    cor += (2 * x - 1)*(2 * y - 1);
                }
            }
            encodeBit = (double)encUnit / encZero;
            decodeBit = (double)decUnit/ decZero;
            double res = (double) cor / (information.length * 8);
            return res;
    }

    private void encoding() {
        for (Byte[] block : blocks) {
            for (int t = 0; t < round * 2; t += 2) {
                for (int i = 0; i < blockSize; i++) {
                    switch (i) {
                        case (0):
                        case (4):
                        case (7):
                        case (3):
                            block[i] = (byte) ((block[i].intValue() ^ keys.get(t)[i]));
                            BigInteger tmp = new BigInteger(String.valueOf(block[i].intValue()));
                            block[i] = (koef.modPow(tmp, new BigInteger("257"))).byteValue();
                            block[i] = (byte) (block[i].intValue() + keys.get(t + 1)[i]);
                            break;

                        case (1):
                        case (2):
                        case (5):
                        case (6):
                            block[i] = (byte) (block[i].intValue() + keys.get(t)[i]);
                            int f = block[i] & 0xff;
                            if (f == 0) {
                                block[i] =(byte) -128;
                            } else {
                                block[i] = (byte) log(f);
                            }
                            block[i] = (byte) ((block[i].intValue() ^ keys.get(t + 1)[i]));
                            break;
                    }
                }
                Byte[] pht = new Byte[blockSize];
                for (int j = 0; j < 2; j++) {
                    for (int i = 0; i < blockSize; i += 2) {
                        byte b1 = (byte) ((2 * (block[i] & 0xff) + (block[i + 1] & 0xff)) % 256);
                        byte b2 = (byte) (((block[i] & 0xff) + (block[i + 1] & 0xff)) % 256);
                        pht[i] = b1;
                        pht[i + 1] = b2;
                    }
                    block[0] = pht[0];
                    block[4] = pht[1];
                    block[1] = pht[2];
                    block[5] = pht[3];
                    block[2] = pht[4];
                    block[6] = pht[5];
                    block[3] = pht[6];
                    block[7] = pht[7];
                }
                for (int i = 0; i < blockSize; i += 2) {
                    byte b1 = (byte) ((2 * (block[i] & 0xff) + (block[i + 1] & 0xff)) % 256);
                    byte b2 = (byte) (((block[i] & 0xff) + (block[i + 1] & 0xff)) % 256);
                    block[i] = b1;
                    block[i + 1] = b2;
                }
            }
        }
    }

    private void decoding() {
        for (Byte[] block : blocks) {
            for (int t = round * 2 - 1; t >= 0; t -= 2) {
                Byte[] pht = new Byte[blockSize];
                for (int j = 0; j < 2; j++) {
                    for (int i = 0; i < blockSize; i += 2) {
                        byte b1 = (byte) (((block[i] & 0xff) - (block[i + 1] & 0xff)) % 256);
                        byte b2 = (byte) (((-block[i] & 0xff) + 2 * (block[i + 1] & 0xff)) % 256);
                        pht[i] = b1;
                        pht[i + 1] = b2;
                    }
                    block[0] = pht[0];
                    block[1] = pht[4];
                    block[2] = pht[1];
                    block[3] = pht[5];
                    block[4] = pht[2];
                    block[5] = pht[6];
                    block[6] = pht[3];
                    block[7] = pht[7];
                }
                for (int i = 0; i < blockSize; i += 2) {
                    byte b1 = (byte) (((block[i] & 0xff) - (block[i + 1] & 0xff)) % 256);
                    byte b2 = (byte) (((-block[i] & 0xff) + 2 * (block[i + 1] & 0xff)) % 256);
                    block[i] = b1;
                    block[i + 1] = b2;
                }
                for (int i = 0; i < blockSize; i++) {
                    switch (i) {
                        case (0):
                        case (4):
                        case (7):
                        case (3):
                            block[i] = (byte) (block[i].intValue() - keys.get(t)[i]);
                            int f = block[i] & 0xff;
                            if (f == 0) {
                                block[i] =(byte) -128;
                            } else {
                                block[i] = (byte) log(f);
                            }
                            block[i] = (byte) ((block[i].intValue() ^ keys.get(t - 1)[i]));
                            break;

                        case (1):
                        case (2):
                        case (5):
                        case (6):
                            block[i] = (byte) ((block[i].intValue() ^ keys.get(t)[i]));
                            BigInteger tmp = new BigInteger(String.valueOf(block[i].intValue()));
                            block[i] = (koef.modPow(tmp, new BigInteger("257"))).byteValue();
                            block[i] = (byte) (block[i].intValue() - keys.get(t - 1)[i]);
                            break;
                    }
                }
            }
        }
    }

    private void write(String filename) {
        Byte[] res = blocks.get(0);
        for (int i = 1; i < blocks.size(); i++) {
            res = concatenate(res, blocks.get(i));
        }
        int bound = res.length;
        while (res[bound - 1] != 1) {
            bound--;
        }
        bound--;
        byte[] result = new byte[bound];
        for (int j = 0; j < bound; j++) {
            result[j] = res[j];
        }
        FileWorker.write(filename, result);
    }

    private void breakIntoBlocks() {
        for (int i = 0; i < information.length; i += blockSize) {
            Byte[] block = new Byte[blockSize];
            for (int j = 0; j < blockSize; j++) {
                if (i + j < information.length) {
                    block[j] = information[i + j];
                } else {
                    if (i + j == information.length) {
                        block[j] = 1;
                    } else {
                        block[j] = 0;
                    }
                }
            }
            blocks.add(block);
        }
    }

    private int log(int x) {
        int res = 45;
        int y = 1;
        while (res != x) {
            res = (res * 45) % 257;
            y++;
        }
        return y;
    }

    private Byte[] keyGen() {
        Byte[] ref = keys.get(keys.size() - 1).clone();
        for (int i = 0; i < blockSize; i++) {
            byte tmp = (byte) (ref[i].intValue() / 32);
            ref[i] = (byte) (ref[i] << 3);
            ref[i] = (byte) (ref[i] + tmp);

            BigInteger a = new BigInteger("45");
            BigInteger b = new BigInteger("45");
            int index = 9 * (keys.size() - 1) + i;
            BigInteger c = a.modPow(b.modPow(new BigInteger(String.valueOf(index)), new BigInteger("256")), new BigInteger("257"));
            c = c.mod(new BigInteger("257"));
            ref[i] = (byte) ((ref[i] + c.intValue()) % 256);
        }
        return ref;
    }

    public <T> T[] concatenate(T[] A, T[] B) {
        int aLen = A.length;
        int bLen = B.length;

        @SuppressWarnings("unchecked")
        T[] C = (T[]) Array.newInstance(A.getClass().getComponentType(), aLen + bLen);
        System.arraycopy(A, 0, C, 0, aLen);
        System.arraycopy(B, 0, C, aLen, bLen);

        return C;
    }


}
