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

package net.bither.ui.base.dialog;

import android.content.Context;
import android.content.DialogInterface;
import android.view.View;

import net.bither.R;
import net.bither.bitherj.core.Address;

/**
 * Created by songchenwen on 14/12/15.
 */
public class DialogSendOption extends CenterDialog implements View.OnClickListener,
        DialogInterface.OnDismissListener {
    public static interface DialogSendOptionListener {
        public void onSelectChangeAddress();
    }

    private DialogSendOptionListener listener;
    private Address address;
    private int clickedId;

    public DialogSendOption(Context context, Address address, DialogSendOptionListener listener) {
        super(context);
        this.listener = listener;
        this.address = address;
        setContentView(R.layout.dialog_send_option);
        setOnDismissListener(this);
        findViewById(R.id.tv_close).setOnClickListener(this);
        findViewById(R.id.tv_select_change_address).setOnClickListener(this);
    }

    @Override
    public void show() {
        clickedId = 0;
        super.show();
    }

    @Override
    public void onClick(View v) {
        clickedId = v.getId();
        dismiss();
    }

    @Override
    public void onDismiss(DialogInterface dialog) {
        switch (clickedId) {
            case R.id.tv_select_change_address:
                if (listener != null) {
                    listener.onSelectChangeAddress();
                }
                return;
            default:
        }
    }
}
