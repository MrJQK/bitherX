/*
 * MASlipCandleStickChart.java
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

import java.util.List;

import net.bither.charts.entity.DateValueEntity;
import net.bither.charts.entity.LineEntity;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PointF;
import android.util.AttributeSet;

public class MASlipCandleStickChart extends SlipCandleStickChart {

    private List<LineEntity<DateValueEntity>> linesData;

    public MASlipCandleStickChart(Context context, AttributeSet attrs,
                                  int defStyle) {
        super(context, attrs, defStyle);
    }

    public MASlipCandleStickChart(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public MASlipCandleStickChart(Context context) {
        super(context);
    }

    @Override
    protected void calcDataValueRange() {
        super.calcDataValueRange();

        double maxValue = this.maxValue;
        double minValue = this.minValue;
        for (int i = 0;
             i < this.linesData.size();
             i++) {
            LineEntity<DateValueEntity> line = this.linesData.get(i);
            if (line != null && line.getLineData().size() > 0) {
                for (int j = displayFrom;
                     j < displayFrom + displayNumber;
                     j++) {
                    DateValueEntity lineData = line.getLineData().get(j);
                    if (lineData.getValue() < minValue) {
                        minValue = lineData.getValue();
                    }

                    if (lineData.getValue() > maxValue) {
                        maxValue = lineData.getValue();
                    }

                }
            }
        }
        this.maxValue = maxValue;
        this.minValue = minValue;
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);

        // draw lines
        if (null != this.linesData) {
            if (0 != this.linesData.size()) {
                drawLines(canvas);
            }
        }
    }

    protected void drawLines(Canvas canvas) {
        if (null == stickData) {
            return;
        }
        if (stickData.size() <= 0) {
            return;
        }
        // distance between two points
        float lineLength = getDataQuadrantPaddingWidth() / displayNumber - 1;
        // start point‘s X
        float startX;

        // draw MA lines
        for (int i = 0;
             i < linesData.size();
             i++) {
            LineEntity<DateValueEntity> line = (LineEntity<DateValueEntity>) linesData
                    .get(i);
            if (line == null) {
                continue;
            }
            if (line.isDisplay() == false) {
                continue;
            }
            List<DateValueEntity> lineData = line.getLineData();
            if (lineData == null) {
                continue;
            }

            Paint mPaint = new Paint();
            mPaint.setColor(line.getLineColor());
            mPaint.setAntiAlias(true);
            // set start point’s X
            startX = getDataQuadrantPaddingStartX() + lineLength / 2;
            // start point
            PointF ptFirst = null;
            for (int j = super.getDisplayFrom();
                 j < super.getDisplayFrom()
                         + super.getDisplayNumber();
                 j++) {
                float value = lineData.get(j).getValue();
                // calculate Y
                float valueY = (float) ((1f - (value - minValue)
                        / (maxValue - minValue)) * getDataQuadrantPaddingHeight())
                        + getDataQuadrantPaddingStartY();

                // if is not last point connect to previous point
                if (j > super.getDisplayFrom()) {
                    canvas.drawLine(ptFirst.x, ptFirst.y, startX, valueY,
                            mPaint);
                }
                // reset
                ptFirst = new PointF(startX, valueY);
                startX = startX + 1 + lineLength;
            }
        }
    }

    public List<LineEntity<DateValueEntity>> getLinesData() {
        return linesData;
    }

    public void setLinesData(List<LineEntity<DateValueEntity>> linesData) {
        this.linesData = linesData;
    }

}
