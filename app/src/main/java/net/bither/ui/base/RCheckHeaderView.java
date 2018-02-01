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
import android.content.Context;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.nineoldandroids.animation.ArgbEvaluator;
import com.nineoldandroids.animation.ObjectAnimator;

import net.bither.R;
import net.bither.bitherj.core.AddressManager;
import net.bither.ui.base.dialog.DialogRCheckInfo;

/**
 * Created by songchenwen on 14-10-20.
 */
public class RCheckHeaderView extends FrameLayout {
    public static interface RCheckHeaderViewListener {
        public void beginCheck();
    }

    private static final int TransitionDuration = 600;
    private static final int ScaleUpAnimDuraion = 300;
    private static final int ScaleDownAnimDuration = 600;
    private static final int LightScanInterval = 1200;

    private View ivLight;
    private TextView tvStatus;
    private ImageButton ibtnCheck;
    private LinearLayout llPoints;
    private TextView tvPoints;
    private FrameLayout flBottom;

    private int totalCheckCount;
    private int passedCheckCount;

    private int bgBeginColor;
    private int bgEndColor;
    private int bgMiddleColor;

    private float percent;

    private ArgbEvaluator bgEvaluator;

    private RCheckHeaderViewListener listener;

    public RCheckHeaderView(Context context) {
        super(context);
        initView();
    }

    public RCheckHeaderView(Context context, AttributeSet attrs) {
        super(context, attrs);
        initView();
    }

    public RCheckHeaderView(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
        initView();
    }


    private void initView() {
        removeAllViews();
        addView(LayoutInflater.from(getContext()).inflate(R.layout.layout_r_check_header, null),
                LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT);
        ivLight = findViewById(R.id.iv_light);
        tvStatus = (TextView) findViewById(R.id.tv_check_status);
        ibtnCheck = (ImageButton) findViewById(R.id.ibtn_check);
        llPoints = (LinearLayout) findViewById(R.id.ll_points);
        tvPoints = (TextView) findViewById(R.id.tv_points);
        flBottom = (FrameLayout) findViewById(R.id.fl_bottom);
        findViewById(R.id.ibtn_rcheck_info).setOnClickListener(infoClick);
        ibtnCheck.setOnClickListener(checkClick);
        bgBeginColor = getResources().getColor(R.color.check_points_begin);
        bgEndColor = getResources().getColor(R.color.rcheck_end);
        bgMiddleColor = getResources().getColor(R.color.check_points_middle);
        bgEvaluator = new ArgbEvaluator();
        setPassedCheckCount(0);
    }

    public void start() {
        flBottom.setVisibility(View.INVISIBLE);
        Animation scaleAnim = AnimationUtils.loadAnimation(getContext(),
                R.anim.check_points_scale_up);
        scaleAnim.setDuration(ScaleUpAnimDuraion);
        scaleAnim.setAnimationListener(scaleUpListener);
        llPoints.startAnimation(scaleAnim);
    }

    public void stop() {
        if (passedCheckCount < totalCheckCount) {
            tvStatus.setText(R.string.rcheck_danger);
        } else {
            tvStatus.setText(R.string.rcheck_safe);
        }
        Animation anim = AnimationUtils.loadAnimation(getContext(), R.anim.check_points_scale_down);
        anim.setDuration(ScaleDownAnimDuration);
        anim.setAnimationListener(scaleDownListener);
        llPoints.startAnimation(anim);
        ivLight.clearAnimation();
        ivLight.setVisibility(View.GONE);
    }

    private OnClickListener checkClick = new OnClickListener() {

        @Override
        public void onClick(View v) {
            check();
        }
    };

    public void check() {
        if (AddressManager.getInstance().getAllAddresses() == null || AddressManager.getInstance
                ().getAllAddresses().size() == 0) {
            DropdownMessage.showDropdownMessage((Activity) getContext(), R.string
                    .rcheck_no_address);
            return;
        }
        start();
    }

    public int getTotalCheckCount() {
        return totalCheckCount;
    }

    public void setTotalCheckCount(int totalCheckCount) {
        this.totalCheckCount = totalCheckCount;
    }

    public int addPassedCheckCount() {
        int count = getPassedCheckCount() + 1;
        setPassedCheckCount(count);
        return count;
    }

    public int getPassedCheckCount() {
        return passedCheckCount;
    }

    public void setPassedCheckCount(int passedCheckCount) {
        this.passedCheckCount = passedCheckCount;
        if (totalCheckCount <= 0 || passedCheckCount < 0) {
            setPercent(1);
        } else {
            ObjectAnimator animator = ObjectAnimator.ofFloat(this, "percent",
                    (float) passedCheckCount / (float) totalCheckCount).setDuration
                    (TransitionDuration);
            animator.start();
        }
    }

    public void setPercent(float percent) {
        this.percent = percent;
        int points = (int) (percent * 100);
        tvPoints.setText(String.valueOf(points));
        if (percent <= 0.5f) {
            setBackgroundColor((Integer) bgEvaluator.evaluate(percent / 0.5f, bgBeginColor,
                    bgMiddleColor));
        } else {
            setBackgroundColor((Integer) bgEvaluator.evaluate((percent - 0.5f) / 0.5f,
                    bgMiddleColor, bgEndColor));
        }
    }

    public float getPercent() {
        return percent;
    }

    public void setListener(RCheckHeaderViewListener listener) {
        this.listener = listener;
    }

    private Animation.AnimationListener scaleUpListener = new Animation.AnimationListener() {

        @Override
        public void onAnimationStart(Animation animation) {
        }

        @Override
        public void onAnimationRepeat(Animation animation) {
        }

        @Override
        public void onAnimationEnd(Animation animation) {
            if (listener != null) {
                listener.beginCheck();
            }
            tvStatus.setText(R.string.rchecking);
            Animation scanAnim = AnimationUtils.loadAnimation(getContext(),
                    R.anim.check_light_scan);
            scanAnim.setDuration(LightScanInterval);
            ivLight.setVisibility(View.VISIBLE);
            ivLight.startAnimation(scanAnim);
        }
    };

    private Animation.AnimationListener scaleDownListener = new Animation.AnimationListener() {

        @Override
        public void onAnimationStart(Animation animation) {

        }

        @Override
        public void onAnimationRepeat(Animation animation) {

        }

        @Override
        public void onAnimationEnd(Animation animation) {
            flBottom.setVisibility(View.VISIBLE);
        }
    };

    private OnClickListener infoClick = new OnClickListener() {
        @Override
        public void onClick(View v) {
            new DialogRCheckInfo(getContext()).show();
        }
    };
}
