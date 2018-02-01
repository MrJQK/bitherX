package net.bither.test;

import org.spongycastle.math.ec.ECConstants;
import net.bither.bitherj.crypto.ECKey;

import java.math.BigInteger;

/**
 * Created by Administrator on 2018/1/29.
 */

public class Test {
    public static BigInteger getN(){
        ECConstants cs;
       return ECKey.CURVE.getN();
    }
}
