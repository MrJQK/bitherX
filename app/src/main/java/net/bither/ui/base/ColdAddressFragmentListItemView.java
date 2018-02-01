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

import android.app.Activity;
import android.app.Dialog;
import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;

import net.bither.R;
import net.bither.bitherj.core.Address;
import net.bither.bitherj.utils.Utils;
import net.bither.ui.base.dialog.DialogAddressAlias;
import net.bither.ui.base.dialog.DialogAddressWithShowPrivateKey;
import net.bither.ui.base.dialog.DialogXRandomInfo;
import net.bither.util.StringUtil;
import net.bither.util.UIUtil;
import net.bither.util.WalletUtils;

public class ColdAddressFragmentListItemView extends FrameLayout implements DialogAddressAlias
        .DialogAddressAliasDelegate {
    private Activity activity;
    private Address address;
    private FrameLayout flAddress;
    private TextView tvAddress;
    private QrCodeImageView ivQr;
    private ImageView ivType;
    private ImageButton ibtnXRandomLabel;
    private Button btnAlias;

    public ColdAddressFragmentListItemView(Activity context) {
        super(context);
        activity = context;
        View v = LayoutInflater.from(activity).inflate(R.layout.list_item_address_fragment_cold,
                null);
        addView(v, LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT);
        initView();
    }

    private void initView() {
        flAddress = (FrameLayout) findViewById(R.id.fl_address);
        ivQr = (QrCodeImageView) findViewById(R.id.iv_qrcode);
        tvAddress = (TextView) findViewById(R.id.tv_address);
        ivType = (ImageView) findViewById(R.id.iv_type);
        btnAlias = (Button) findViewById(R.id.btn_address_alias);
        ibtnXRandomLabel = (ImageButton) findViewById(R.id.ibtn_xrandom_label);
        ibtnXRandomLabel.setOnLongClickListener(DialogXRandomInfo.InfoLongClick);
        flAddress.setOnClickListener(copyClick);
        ivQr.setOnClickListener(qrClick);
        ivType.setOnLongClickListener(typeClick);
        btnAlias.setOnClickListener(aliasClick);
    }

    public void showAddress(final Address address) {
        this.address = address;
        tvAddress.setText(WalletUtils.formatHash(address.getAddress(), 4, 12));
        ivQr.setContent(address.getAddress());
        if (address.isFromXRandom()) {
            ibtnXRandomLabel.setVisibility(View.VISIBLE);
        } else {
            ibtnXRandomLabel.setVisibility(View.GONE);
        }
        if (!Utils.isEmpty(address.getAlias())) {
            btnAlias.setVisibility(View.VISIBLE);
            btnAlias.setText(address.getAlias());
        } else {
            btnAlias.setText("");
            btnAlias.setVisibility(View.INVISIBLE);
        }
    }

    private OnLongClickListener typeClick = new OnLongClickListener() {
        @Override
        public boolean onLongClick(View v) {
            DialogAddressWithShowPrivateKey dialog = new DialogAddressWithShowPrivateKey(activity, address, ColdAddressFragmentListItemView.this);
            dialog.show();
            return true;
        }
    };

    private OnClickListener copyClick = new OnClickListener() {

        @Override
        public void onClick(View v) {
            if (address != null) {
                String text = address.getAddress();
                StringUtil.copyString(text);
                DropdownMessage.showDropdownMessage(activity, R.string.copy_address_success);
            }
        }
    };

    private OnClickListener qrClick = new OnClickListener() {

        @Override
        public void onClick(View v) {
            if (address != null) {
                int size = Math.min(UIUtil.getScreenHeight(), UIUtil.getScreenWidth());
                QrCodeImageView iv = new QrCodeImageView(getContext());
                iv.setBackgroundColor(Color.WHITE);
                int margin = UIUtil.dip2pix(18);
                final Dialog dialog = new Dialog(getContext(), R.style.tipsDialog);
                dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
                dialog.getWindow().getAttributes().dimAmount = 0.85f;
                dialog.setCanceledOnTouchOutside(true);
                dialog.setContentView(iv, new LayoutParams(size, size));
                dialog.show();
                iv.setOnClickListener(new OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        dialog.dismiss();
                    }
                });
                iv.setContent(address.getAddress(), Color.BLACK, Color.WHITE, margin);
            }
        }
    };

    private OnClickListener aliasClick = new OnClickListener() {
        @Override
        public void onClick(View v) {
            new DialogAddressAlias(getContext(), address, ColdAddressFragmentListItemView.this)
                    .show();
        }
    };

    @Override
    public void onAddressAliasChanged(Address address, String alias) {
        if (!Utils.isEmpty(alias)) {
            btnAlias.setText(alias);
            btnAlias.setVisibility(View.VISIBLE);
        } else {
            btnAlias.setText("");
            btnAlias.setVisibility(View.INVISIBLE);
        }
    }
}
