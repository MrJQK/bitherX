package net.bither.bitherj.test;

import net.bither.bitherj.crypto.ECKey;

import org.spongycastle.math.ec.ECConstants;

import java.math.BigInteger;

/**
 * Created by Administrator on 2018/1/29.
 */

public class Test {
    public static BigInteger getN(){
        ECConstants constants;
       return ECKey.CURVE.getN();
    }
}
