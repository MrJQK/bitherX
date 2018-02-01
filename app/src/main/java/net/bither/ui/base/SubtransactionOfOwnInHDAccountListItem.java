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

package net.bither.ui.base;

import android.app.Activity;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.TextView;

import net.bither.R;
import net.bither.bitherj.core.AbstractHD;
import net.bither.util.StringUtil;
import net.bither.util.UIUtil;
import net.bither.util.WalletUtils;

/**
 * Created by songchenwen on 15/7/2.
 */
public class SubtransactionOfOwnInHDAccountListItem extends FrameLayout implements View
        .OnClickListener {
    public static final int Height = UIUtil.dip2pix(70);

    private View parent;
    private TextView tvAddress;
    private TextView tvBtc;
    private TextView tvMessage;
    private FrameLayout flAddress;
    private String address;
    private Activity activity;

    public SubtransactionOfOwnInHDAccountListItem(Activity context) {
        super(context);
        activity = context;
        removeAllViews();
        parent = LayoutInflater.from(context).inflate(R.layout.list_item_transaction_address, null);
        addView(parent, LayoutParams.MATCH_PARENT, Height);
        tvAddress = (TextView) findViewById(R.id.tv_subtransaction_address);
        tvBtc = (TextView) findViewById(R.id.tv_subtransaction_btc);
        tvMessage = (TextView) findViewById(R.id.tv_message);
        flAddress = (FrameLayout) findViewById(R.id.fl_address);
        flAddress.setOnClickListener(this);
    }

    public void setTextColor(int color) {
        tvAddress.setTextColor(color);
        tvMessage.setTextColor(color);
        tvBtc.setTextColor(color);
    }

    public void setContent(String address, long value, AbstractHD.PathType pathType) {
        this.address = address;
        parent.getLayoutParams().height = Height;
        tvAddress.setText(WalletUtils.formatHash(address, 4, 12));
        tvMessage.setVisibility(View.GONE);
        flAddress.setVisibility(View.VISIBLE);
        if (value > 0) {
            if (pathType == AbstractHD.PathType.EXTERNAL_ROOT_PATH) {
                tvBtc.setText(R.string.address_full_for_hd_type_receiving);
            } else {
                tvBtc.setText(R.string.address_full_for_hd_type_changing);
            }
        } else {
            tvBtc.setText(R.string.address_full_for_hd_type_sending);
        }
    }

    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.fl_address) {
            if (address != null) {
                StringUtil.copyString(address);
                DropdownMessage.showDropdownMessage(activity, R.string.copy_address_success);
            }
        }
    }
}
