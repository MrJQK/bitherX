/*
 *
 *  * Copyright 2014 http://Bither.net
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *    http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package net.bither.runnable;

import net.bither.bitherj.core.Address;
import net.bither.bitherj.core.Tx;

import java.util.List;

/**
 * Created by songchenwen on 14-10-20.
 */
public class RCheckRunnable extends BaseRunnable {
    private Address address;
    private Tx tx;
    private List<Tx> txs;

    public RCheckRunnable(Address address, Tx tx) {
        this.address = address;
        this.tx = tx;
    }

    public RCheckRunnable(Address address, List<Tx> txs) {
        this.address = address;
        this.txs = txs;
    }

    @Override
    public void run() {
        obtainMessage(HandlerMessage.MSG_PREPARE);
        if (tx != null) {
            obtainMessage(HandlerMessage.MSG_SUCCESS, tx);
        } else if (txs != null) {
            obtainMessage(HandlerMessage.MSG_SUCCESS, txs);
        }
    }
}
