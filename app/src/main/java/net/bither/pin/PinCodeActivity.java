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

package net.bither.pin;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

import net.bither.R;
import net.bither.preference.AppSharedPreference;

/**
 * Created by songchenwen on 14-11-5.
 */
public class PinCodeActivity extends Activity implements PinCodeEnterView.PinCodeEnterViewListener {
    private PinCodeEnterView pv;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pin_code);
        initView();
    }

    private void initView() {
        pv = (PinCodeEnterView) findViewById(R.id.pv);
        pv.setListener(this);
    }

    @Override
    public void onEntered(CharSequence code) {
        if (AppSharedPreference.getInstance().checkPinCode(code)) {
            super.finish();
            overridePendingTransition(0, R.anim.pin_out_exit);
        } else {
            pv.shakeToClear();
        }
    }

    @Override
    public void finish() {
        Intent i = new Intent();
        i.setAction(Intent.ACTION_MAIN);
        i.addCategory(Intent.CATEGORY_HOME);
        startActivity(i);
    }
}
