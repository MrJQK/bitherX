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

package net.bither.fragment.cold;

import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.CompoundButton;

import net.bither.R;
import net.bither.activity.hot.AddHotAddressActivity;
import net.bither.bitherj.core.HDAccount;
import net.bither.bitherj.core.HDAccountCold;
import net.bither.bitherj.crypto.SecureCharSequence;
import net.bither.bitherj.crypto.mnemonic.MnemonicCode;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.preference.AppSharedPreference;
import net.bither.runnable.ThreadNeedService;
import net.bither.service.BlockchainService;
import net.bither.ui.base.AddPrivateKeyActivity;
import net.bither.ui.base.DialogFragmentHDMSingularColdSeed;
import net.bither.ui.base.dialog.DialogConfirmTask;
import net.bither.ui.base.dialog.DialogPassword;
import net.bither.ui.base.dialog.DialogProgress;
import net.bither.ui.base.dialog.DialogXRandomInfo;
import net.bither.util.BackupUtil;
import net.bither.util.ThreadUtil;
import net.bither.xrandom.HDAccountColdUEntropyActivity;

import java.security.SecureRandom;
import java.util.ArrayList;

/**
 * Created by songchenwen on 15/6/25.
 */
public class AddAddressColdHDAccountFragment extends Fragment implements AddHotAddressActivity
        .AddAddress {
    private CheckBox cbxXRandom;
    private DialogProgress dp;
    private HDAccountCold hdAccount;


    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle
            savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_add_address_hot_hd_account, container, false);
        cbxXRandom = (CheckBox) v.findViewById(R.id.cbx_xrandom);
        cbxXRandom.setOnCheckedChangeListener(xRandomCheck);
        v.findViewById(R.id.ibtn_xrandom_info).setOnClickListener(DialogXRandomInfo.GuideClick);
        v.findViewById(R.id.btn_add).setOnClickListener(addClick);
        dp = new DialogProgress(v.getContext(), R.string.please_wait);
        dp.setCancelable(false);
        return v;
    }

    private View.OnClickListener addClick = new View.OnClickListener() {
        @Override
        public void onClick(final View v) {
            if (cbxXRandom.isChecked()) {
                final Runnable run = new Runnable() {
                    @Override
                    public void run() {
                        Intent intent = new Intent(getActivity(), HDAccountColdUEntropyActivity
                                .class);
                        intent.setFlags(Intent.FLAG_ACTIVITY_FORWARD_RESULT);
                        getActivity().startActivity(intent);
                        getActivity().finish();
                    }
                };
                if (AppSharedPreference.getInstance().shouldAutoShowXRandomInstruction()) {
                    DialogXRandomInfo dialog = new DialogXRandomInfo(getActivity(), true, true);
                    dialog.setOnDismissListener(new DialogInterface.OnDismissListener() {
                        @Override
                        public void onDismiss(DialogInterface dialog) {
                            run.run();
                        }
                    });
                    dialog.show();
                } else {
                    run.run();
                }
            } else {
                final DialogPassword.PasswordGetter passwordGetter = new DialogPassword
                        .PasswordGetter(getActivity());
                new ThreadNeedService(null, getActivity()) {
                    @Override
                    public void runWithService(BlockchainService service) {
                        SecureCharSequence password = passwordGetter.getPassword();
                        if (password == null) {
                            return;
                        }
                        if (service != null) {
                            service.stopAndUnregister();
                        }
                        ThreadUtil.runOnMainThread(new Runnable() {
                            @Override
                            public void run() {
                                v.setKeepScreenOn(true);
                                AddAddressColdHDAccountFragment.this.dp.show();
                            }
                        });

                        final ArrayList<String> words = new ArrayList<String>();
                        try {
                            hdAccount = new HDAccountCold(MnemonicCode.instance(), new SecureRandom(), password);
                            words.addAll(hdAccount.getSeedWords(password));
                        } catch (MnemonicException.MnemonicLengthException e) {
                            throw new RuntimeException(e);
                        }
                        password.wipe();
                        BackupUtil.backupColdKey(false);
                        if (service != null) {
                            service.startAndRegister();
                        }
                        ThreadUtil.runOnMainThread(new Runnable() {
                            @Override
                            public void run() {
                                v.setKeepScreenOn(false);
                                AddAddressColdHDAccountFragment.this.dp.dismiss();
                                DialogFragmentHDMSingularColdSeed.newInstance(words, hdAccount
                                        .getQRCodeFullEncryptPrivKey(), R.string
                                        .add_hd_account_show_seed_label, R.string
                                        .add_hd_account_show_seed_button, new
                                        DialogFragmentHDMSingularColdSeed
                                                .DialogFragmentHDMSingularColdSeedListener() {
                                    @Override
                                    public void HDMSingularColdSeedRemembered() {
                                        if (getActivity() instanceof AddPrivateKeyActivity) {
                                            AddPrivateKeyActivity activity =
                                                    (AddPrivateKeyActivity) getActivity();
                                            activity.save();
                                        } else {
                                            getActivity().finish();
                                        }
                                    }
                                }).show(getActivity().getSupportFragmentManager(),
                                        DialogFragmentHDMSingularColdSeed.FragmentTag);
                            }
                        });
                    }
                }.start();
            }
        }
    };

    @Override
    public ArrayList<String> getAddresses() {
        ArrayList<String> addresses = new ArrayList<String>();
        if (hdAccount != null) {
            addresses.add(HDAccount.HDAccountPlaceHolder);
        }
        return addresses;
    }

    private CompoundButton.OnCheckedChangeListener xRandomCheck = new CompoundButton
            .OnCheckedChangeListener() {
        private boolean ignoreListener = false;
        private DialogConfirmTask dialog;

        @Override
        public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
            if (!isChecked && !ignoreListener) {
                cbxXRandom.setChecked(true);
                getDialog().show();
            }
        }

        private DialogConfirmTask getDialog() {
            if (dialog == null) {
                dialog = new DialogConfirmTask(getActivity(), getResources().getString(R.string
                        .xrandom_uncheck_warn), new Runnable() {
                    @Override
                    public void run() {
                        cbxXRandom.post(new Runnable() {
                            @Override
                            public void run() {
                                ignoreListener = true;
                                cbxXRandom.setChecked(false);
                                ignoreListener = false;
                            }
                        });
                    }
                });
            }
            return dialog;
        }
    };
}
