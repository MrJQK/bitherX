/*
 * BOLLMASlipCandleStickChart.java
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
import android.graphics.Path;
import android.graphics.PointF;
import android.util.AttributeSet;

public class BOLLMASlipCandleStickChart extends MASlipCandleStickChart {

    private List<LineEntity<DateValueEntity>> bandData;

    public BOLLMASlipCandleStickChart(Context context, AttributeSet attrs,
                                      int defStyle) {
        super(context, attrs, defStyle);
    }

    public BOLLMASlipCandleStickChart(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public BOLLMASlipCandleStickChart(Context context) {
        super(context);
    }

    @Override
    protected void calcDataValueRange() {
        super.calcDataValueRange();

        double maxValue = this.maxValue;
        double minValue = this.minValue;
        for (int i = 0;
             i < this.bandData.size();
             i++) {
            LineEntity<DateValueEntity> line = this.bandData.get(i);
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
        if (null != bandData && bandData.size() >= 2) {
            drawAreas(canvas);
            drawBandBorder(canvas);
        }
    }

    protected void drawAreas(Canvas canvas) {
        if (null == bandData) {
            return;
        }
        // distance between two points
        float lineLength = getDataQuadrantPaddingWidth() / displayNumber - 1;
        // start point‘s X
        float startX;
        float lastY = 0;
        float lastX = 0;

        LineEntity<DateValueEntity> line1 = (LineEntity<DateValueEntity>) bandData
                .get(0);
        LineEntity<DateValueEntity> line2 = (LineEntity<DateValueEntity>) bandData
                .get(1);
        List<DateValueEntity> line1Data = line1.getLineData();
        List<DateValueEntity> line2Data = line2.getLineData();

        if (line1.isDisplay() == false || line2.isDisplay() == false) {
            return;
        }
        if (line1Data == null || line2Data == null) {
            return;
        }

        Paint mPaint = new Paint();
        mPaint.setColor(line1.getLineColor());
        mPaint.setAlpha(70);
        mPaint.setAntiAlias(true);
        // set start point’s X
        startX = getDataQuadrantPaddingStartX() + lineLength / 2f;
        Path areaPath = new Path();
        for (int j = displayFrom;
             j < displayFrom + displayNumber;
             j++) {
            float value1 = line1Data.get(j).getValue();
            float value2 = line2Data.get(j).getValue();

            // calculate Y
            float valueY1 = (float) ((1f - (value1 - minValue)
                    / (maxValue - minValue)) * getDataQuadrantPaddingHeight())
                    + getDataQuadrantPaddingStartY();
            float valueY2 = (float) ((1f - (value2 - minValue)
                    / (maxValue - minValue)) * getDataQuadrantPaddingHeight())
                    + getDataQuadrantPaddingStartY();

            // 绘制线条路径
            if (j == displayFrom) {
                areaPath.moveTo(startX, valueY1);
                areaPath.lineTo(startX, valueY2);
                areaPath.moveTo(startX, valueY1);
            } else {
                areaPath.lineTo(startX, valueY1);
                areaPath.lineTo(startX, valueY2);
                areaPath.lineTo(lastX, lastY);

                areaPath.close();
                areaPath.moveTo(startX, valueY1);
            }

            lastX = startX;
            lastY = valueY2;
            startX = startX + 1 + lineLength;
        }
        areaPath.close();
        canvas.drawPath(areaPath, mPaint);
    }

    protected void drawBandBorder(Canvas canvas) {

        if (null == this.bandData) {
            return;
        }

        if (bandData.size() <= 0) {
            return;
        }
        // distance between two points
        float lineLength = getDataQuadrantPaddingWidth() / displayNumber - 1;
        // start point‘s X
        float startX;

        // draw lines
        for (int i = 0;
             i < bandData.size();
             i++) {
            LineEntity<DateValueEntity> line = (LineEntity<DateValueEntity>) bandData
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
            for (int j = displayFrom;
                 j < displayFrom + displayNumber;
                 j++) {
                float value = lineData.get(j).getValue();
                // calculate Y
                float valueY = (float) ((1f - (value - minValue)
                        / (maxValue - minValue)) * getDataQuadrantPaddingHeight())
                        + getDataQuadrantPaddingStartY();

                // if is not last point connect to previous point
                if (j > displayFrom) {
                    canvas.drawLine(ptFirst.x, ptFirst.y, startX, valueY,
                            mPaint);
                }
                // reset
                ptFirst = new PointF(startX, valueY);
                startX = startX + 1 + lineLength;
            }
        }
    }

    public List<LineEntity<DateValueEntity>> getBandData() {
        return bandData;
    }

    public void setBandData(List<LineEntity<DateValueEntity>> bandData) {
        this.bandData = bandData;
    }

}
