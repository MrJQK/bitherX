/*
 * ColoredSlipStickChart.java
 * Android-Charts
 *
 * Created by limc on 2014.
 *
 * Copyright 2011 limc.cn All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bither.charts.view;

import net.bither.charts.entity.ColoredStickEntity;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.util.AttributeSet;

public class ColoredSlipStickChart extends SlipStickChart {

    public static final int DEFAULT_COLORED_STICK_STYLE_WITH_BORDER = 0;
    public static final int DEFAULT_COLORED_STICK_STYLE_NO_BORDER = 1;
    public static final int DEFAULT_COLORED_STICK_STYLE = DEFAULT_COLORED_STICK_STYLE_NO_BORDER;

    private int coloredStickStyle = DEFAULT_COLORED_STICK_STYLE_NO_BORDER;

    public ColoredSlipStickChart(Context context) {
        super(context);
    }

    public ColoredSlipStickChart(Context context, AttributeSet attrs,
                                 int defStyle) {
        super(context, attrs, defStyle);
    }

    public ColoredSlipStickChart(Context context, AttributeSet attrs) {
        super(context, attrs);

    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
    }

    @Override
    protected void drawSticks(Canvas canvas) {
        if (null == stickData) {
            return;
        }
        if (stickData.size() == 0) {
            return;
        }

        float stickWidth = getDataQuadrantPaddingWidth() / displayNumber
                - stickSpacing;
        float stickX = getDataQuadrantPaddingStartX();

        Paint mPaintStick = new Paint();
        for (int i = displayFrom;
             i < displayFrom + displayNumber;
             i++) {
            ColoredStickEntity entity = (ColoredStickEntity) stickData.get(i);

            float highY = (float) ((1f - (entity.getHigh() - minValue)
                    / (maxValue - minValue))
                    * (getDataQuadrantPaddingHeight()) + getDataQuadrantPaddingStartY());
            float lowY = (float) ((1f - (entity.getLow() - minValue)
                    / (maxValue - minValue))
                    * (getDataQuadrantPaddingHeight()) + getDataQuadrantPaddingStartY());

            mPaintStick.setColor(entity.getColor());
            // stick or line?
            if (stickWidth >= 2f) {
                canvas.drawRect(stickX, highY, stickX + stickWidth, lowY,
                        mPaintStick);
            } else {
                canvas.drawLine(stickX, highY, stickX, lowY, mPaintStick);
            }

            // next x
            stickX = stickX + stickSpacing + stickWidth;
        }
    }

    public int getColoredStickStyle() {
        return coloredStickStyle;
    }

    public void setColoredStickStyle(int coloredStickStyle) {
        this.coloredStickStyle = coloredStickStyle;
    }
}
