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

package net.bither.ui.base.dialog;

import android.app.Activity;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.net.Uri;
import android.view.View;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;

import net.bither.BitherSetting;
import net.bither.R;
import net.bither.bitherj.qrcode.QRCodeUtil;
import net.bither.runnable.FancyQrCodeThread;
import net.bither.ui.base.DropdownMessage;
import net.bither.util.FileUtil;
import net.bither.util.ThreadUtil;
import net.bither.util.UIUtil;
import net.bither.util.WalletUtils;


public class DialogPrivateKeyQrCode extends Dialog implements View.OnClickListener,
        DialogInterface.OnDismissListener, FancyQrCodeThread.FancyQrCodeListener {
    private Activity activity;
    private ImageView ivQr;
    private TextView tvAddress;
    private ProgressBar pb;
    private String content;
    private String address;
    private Bitmap qrCode;
    private int clickedView = 0;

    public DialogPrivateKeyQrCode(Activity context, String keyString, String address){
        this(context, keyString, BitherSetting.QRCodeType.Bither, address);
    }

    public DialogPrivateKeyQrCode(Activity context, String keyString,
                                  BitherSetting.QRCodeType type, String address) {
        super(context, R.style.tipsDialog);
        this.activity = context;
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
        getWindow().getAttributes().dimAmount = 0.8f;
        setCanceledOnTouchOutside(true);
        if (type == BitherSetting.QRCodeType.Bither) {
            this.content = QRCodeUtil.encodeQrCodeString(keyString);
        } else {
            this.content = keyString;
        }
        this.address = address;
        setContentView(R.layout.dialog_private_key_qr_code);
        setOnDismissListener(this);
        initView();
        getWindow().setLayout(WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.MATCH_PARENT);
        new FancyQrCodeThread(this.content, ivQr.getLayoutParams().width, Color.BLACK,
                Color.WHITE, this, false).start();
    }

    private void initView() {
        ivQr = (ImageView) findViewById(R.id.iv_qrcode);
        tvAddress = (TextView) findViewById(R.id.tv_address);
        pb = (ProgressBar) findViewById(R.id.pb);
        findViewById(R.id.ll_container).setOnClickListener(this);
        findViewById(R.id.ll_back_up).setOnClickListener(this);
        tvAddress.setText(WalletUtils.formatHash(address, 4, 20));
        ivQr.setOnClickListener(this);
        int size = Math.min(UIUtil.getScreenWidth(), UIUtil.getScreenHeight());
        ivQr.getLayoutParams().width = ivQr.getLayoutParams().height = size;
    }

    @Override
    public void show() {
        clickedView = 0;
        super.show();
    }

    @Override
    public void onClick(View v) {
        clickedView = v.getId();
        dismiss();
    }

    @Override
    public void onDismiss(DialogInterface dialog) {
        switch (clickedView) {
            case R.id.ll_back_up:
                share();
                break;
            default:
                break;
        }
    }

    private void share() {
        if (qrCode != null) {
            new ShareThread().start();
        }
    }

    @Override
    public void generated(Bitmap bmp) {
        pb.setVisibility(View.GONE);
        qrCode = bmp;
        ivQr.setImageBitmap(bmp);
    }

    private class ShareThread extends Thread {
        @Override
        public void run() {
            final Uri uri = FileUtil.saveShareImage(qrCode);
            if (uri == null) {
                DropdownMessage.showDropdownMessage(activity, R.string.market_share_failed);
                return;
            }
            ThreadUtil.runOnMainThread(new Runnable() {
                @Override
                public void run() {
                    Intent intent = new Intent(android.content.Intent.ACTION_SEND);
                    intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    intent.putExtra(Intent.EXTRA_STREAM, uri);
                    intent.setType("image/jpg");
                    try {
                        getContext().startActivity(intent);
                    } catch (Exception e) {
                        e.printStackTrace();
                        DropdownMessage.showDropdownMessage(activity, R.string.market_share_failed);
                    }
                }
            });
        }
    }
}
