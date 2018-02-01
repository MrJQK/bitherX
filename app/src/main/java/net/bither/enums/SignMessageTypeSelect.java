package net.bither.enums;

/**
 * Created by ltq on 2017/7/21.
 */

public enum SignMessageTypeSelect {
    HdReceive(0), HdChange(1), Hot(2);

    private int value;

    SignMessageTypeSelect(int value) {
        this.value = value;
    }

    public int value() {
        return value;
    }

}
