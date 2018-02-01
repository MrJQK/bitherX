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
import android.support.v4.app.FragmentActivity;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;

import net.bither.R;
import net.bither.bitherj.utils.Utils;
import net.bither.model.Market;
import net.bither.model.Ticker;
import net.bither.preference.AppSharedPreference;
import net.bither.util.ExchangeUtil;

public class MarketFragmentListItemView extends FrameLayout implements
        MarketTickerChangedObserver {
    private Market market;
    private TextView tvMarketName;
    private TextView tvPrice;
    private ImageView ivPriceAlert;

    public MarketFragmentListItemView(FragmentActivity activity) {
        super(activity);
        View v = LayoutInflater.from(activity).inflate(
                R.layout.list_item_market_fragment, null);
        addView(v, LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT);
        initView();
    }

    private void initView() {
        tvMarketName = (TextView) findViewById(R.id.tv_market_name);
        tvPrice = (TextView) findViewById(R.id.tv_price);
        ivPriceAlert = (ImageView) findViewById(R.id.iv_price_alert);
    }

    private MarketFragmentListItemView(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    private MarketFragmentListItemView(Context context, AttributeSet attrs,
                                       int defStyle) {
        super(context, attrs, defStyle);
    }

    public void setMarket(Market market, int loaderPosition) {
        this.market = market;
        if (market != null) {
            showTickerInfo();
        }
    }

    private void showTickerInfo() {
        if (market != null) {
            tvMarketName.setText(market.getName());
            tvMarketName.setTextColor(market.getMarketColor());
        }
        if (market.getTicker() == null) {
            return;
        }
        Ticker ticker = market.getTicker();
        if (ExchangeUtil.getCurrenciesRate() != null) {
            tvPrice.setText(AppSharedPreference.getInstance()
                    .getDefaultExchangeType().getSymbol()
                    + Utils.formatDoubleToMoneyString(ticker
                    .getDefaultExchangePrice()));
        } else {
            tvPrice.setText(ExchangeUtil
                    .getExchangeType(market.getMarketType()).getSymbol()
                    + Utils.formatDoubleToMoneyString(ticker.getPrice()));
        }
        if (market.getPriceAlert() == null) {
            ivPriceAlert.setVisibility(View.INVISIBLE);
        } else {
            ivPriceAlert.setVisibility(View.VISIBLE);
        }
    }

    public void onResume() {
        showTickerInfo();
    }

    public void onPause() {
    }

    @Override
    public void onMarketTickerChanged() {

        showTickerInfo();

    }
}
