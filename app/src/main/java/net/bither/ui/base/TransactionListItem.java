/*
 * Copyright 2014 http://Bither.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bither.ui.base;

import android.content.Context;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.TextView;

import net.bither.BitherSetting;
import net.bither.R;
import net.bither.activity.hot.AddressDetailActivity;
import net.bither.bitherj.core.Address;
import net.bither.bitherj.core.HDAccount;
import net.bither.bitherj.core.Out;
import net.bither.bitherj.core.PeerManager;
import net.bither.bitherj.core.Tx;
import net.bither.bitherj.exception.ScriptException;
import net.bither.bitherj.utils.Utils;
import net.bither.ui.base.dialog.DialogAddressFull;
import net.bither.ui.base.dialog.DialogAddressFullForHD;
import net.bither.ui.base.dialog.DialogConfirmTask;
import net.bither.ui.base.dialog.DialogTransactionConfidence;
import net.bither.util.DateTimeUtil;
import net.bither.util.ThreadUtil;

import java.util.Calendar;
import java.util.Date;
import java.util.LinkedHashMap;

public class TransactionListItem extends FrameLayout implements MarketTickerChangedObserver,
        View.OnLongClickListener {

    private AddressDetailActivity activity;
    private TransactionImmutureConfidenceIconView vConfidenceIcon;
    private ImageButton ibtnAddressFull;
    private TextView tvTransactionAddress;
    private BtcToMoneyButton btnBtc;
    private TextView tvTime;

    private Tx transaction;
    private Address address;

    public TransactionListItem(AddressDetailActivity activity) {
        super(activity);
        this.activity = activity;
        initView();
    }

    private void initView() {
        removeAllViews();
        addView(LayoutInflater.from(activity).inflate(R.layout
                .list_item_address_detail_transaction, null), LayoutParams.MATCH_PARENT,
                LayoutParams.WRAP_CONTENT);
        vConfidenceIcon = (TransactionImmutureConfidenceIconView) findViewById(R.id
                .fl_confidence_icon);
        tvTransactionAddress = (TextView) findViewById(R.id.tv_transaction_address);
        btnBtc = (BtcToMoneyButton) findViewById(R.id.btn_btc);
        tvTime = (TextView) findViewById(R.id.tv_time);
        ibtnAddressFull = (ImageButton) findViewById(R.id.ibtn_address_full);
        ibtnAddressFull.setOnClickListener(addressFullClick);
        vConfidenceIcon.setOnClickListener(confidenceClick);
        setOnLongClickListener(this);
    }

    private TransactionListItem(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    private TransactionListItem(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
    }

    public void setTransaction(Tx transaction, Address address) {
        this.transaction = transaction;
        this.address = address;
        showTransaction();
    }

    private void showTransaction() {
        if (this.transaction == null || address == null) {
            return;
        }
        long value;
        try {
            value = transaction.deltaAmountFrom(address);
        } catch (Exception e) {
            return;
        }
        vConfidenceIcon.setTx(transaction);
        boolean isReceived = value >= 0;
        btnBtc.setAmount(value);
        Date time = transaction.getTxDate();
        if (time.equals(new Date(0))) {
            tvTime.setText("");
        } else {
            tvTime.setText(DateTimeUtil.getDateTimeString(time));
        }
        if (isReceived) {
            if (transaction.isCoinBase()) {
                tvTransactionAddress.setText(R.string.input_coinbase);
            } else {
                try {
                    String subAddress = transaction.getFromAddress();
                    if (Utils.isEmpty(subAddress)) {
                        tvTransactionAddress.setText(BitherSetting.UNKONW_ADDRESS_STRING);
                    } else {
                        tvTransactionAddress.setText(Utils.shortenAddress(subAddress));
                    }
                } catch (ScriptException e) {
                    e.printStackTrace();
                    tvTransactionAddress.setText(BitherSetting.UNKONW_ADDRESS_STRING);
                }
            }
        } else {
            String subAddress = transaction.getFirstOutAddress();
            if (subAddress != null) {
                tvTransactionAddress.setText(Utils.shortenAddress(subAddress));
            } else {
                tvTransactionAddress.setText(BitherSetting.UNKONW_ADDRESS_STRING);
            }
        }
    }

    public void onPause() {
        vConfidenceIcon.onPause();
        btnBtc.onPause();
    }

    public void onResume() {
        vConfidenceIcon.onResume();
        btnBtc.onResume();
    }

    @Override
    public void onMarketTickerChanged() {
        btnBtc.onMarketTickerChanged();
    }

    private OnClickListener confidenceClick = new OnClickListener() {

        @Override
        public void onClick(View v) {
            if (transaction != null) {
                DialogTransactionConfidence dialog = new DialogTransactionConfidence(getContext()
                        , transaction, address);
                dialog.show(v);
            }
        }
    };

    private OnClickListener addressFullClick = new OnClickListener() {

        @Override
        public void onClick(View v) {
            if (address instanceof HDAccount) {
                new DialogAddressFullForHD(activity, transaction, (HDAccount) address).show(v);
                return;
            }
            LinkedHashMap<String, Long> addresses = new LinkedHashMap<String, Long>();
            boolean isIncoming = true;
            try {
                isIncoming = transaction.deltaAmountFrom(address) >= 0;
            } catch (ScriptException e) {
                e.printStackTrace();
            }
            int subCount = isIncoming ? transaction.getIns().size() : transaction.getOuts().size();
            String subAddress = null;
            long value;
            for (int i = 0;
                 i < subCount;
                 i++) {
                subAddress = null;
                if (isIncoming) {
                    if (transaction.isCoinBase()) {
                        subAddress = getContext().getResources().getString(R.string.input_coinbase);
                    } else {
                        try {
                            subAddress = transaction.getIns().get(i).getFromAddress();
                        } catch (ScriptException e) {
                            e.printStackTrace();
                        }
                    }
                    value = transaction.getIns().get(i).getValue();
                } else {
                    Out out = transaction.getOuts().get(i);
                    value = out.getOutValue();
                    try {
                        subAddress = out.getOutAddress();
                    } catch (ScriptException e) {
                        e.printStackTrace();
                    }
                }
                if (subAddress == null) {
                    subAddress = getContext().getResources().getString(R.string
                            .address_cannot_be_parsed);
                }
                if (Utils.compareString(subAddress, address.getAddress())) {
                    subAddress = getContext().getString(R.string.address_mine);
                }
                addresses.put(subAddress, value);
            }
            DialogAddressFull dialog = new DialogAddressFull(activity, addresses);
            dialog.show(v);
        }
    };

    @Override
    public boolean onLongClick(View v) {
        if (PeerManager.instance().isRunning() && !PeerManager.instance().isSynchronizing() &&
                transaction != null && address != null) {
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.DATE, -2);
            if (transaction.getConfirmationCount() <= 0 && transaction.getTxDate().before(cal
                    .getTime())) {
                DialogConfirmTask dialog = new DialogConfirmTask(getContext(),
                        getContext().getString(R.string.manual_delete_transaction_warning),
                        new Runnable() {
                    @Override
                    public void run() {
                        address.removeTx(transaction);
                        ThreadUtil.runOnMainThread(new Runnable() {
                            @Override
                            public void run() {
                                activity.loadData();
                            }
                        });
                    }
                });
                dialog.show();
                return true;
            }
        }
        return false;
    }
}
