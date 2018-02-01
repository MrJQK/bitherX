/*
 * MACandleStickChart.java
 * Android-Charts
 *
 * Created by limc on 2011/05/29.
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

import static net.bither.charts.utils.Utils.formatDoubleToString;

import java.util.List;

import net.bither.charts.entity.BitherOHLCEntity;
import net.bither.charts.entity.DateValueEntity;
import net.bither.charts.entity.LineEntity;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PointF;
import android.util.AttributeSet;

/**
 * <p>
 * MACandleStickChart is inherits from CandleStickChart which can display moving
 * average lines on this graph.
 * </p>
 * <p>
 * MACandleStickChartはグラフの一種です、移動平均線など分析線がこのグラフで表示は可能です。
 * </p>
 * <p>
 * MACandleStickChart继承于CandleStickChart的，可以在CandleStickChart基础上
 * 显示移动平均等各种分析指标数据。
 * </p>
 *
 * @author limc
 * @version v1.0 2011/05/30 14:49:02
 * @see CandleStickChart
 * @see StickChart
 */
public class MACandleStickChart extends CandleStickChart {

    /**
     * <p>
     * data to draw lines
     * </p>
     * <p>
     * ラインを書く用データ
     * </p>
     * <p>
     * 绘制线条用的数据
     * </p>
     */
    private List<LineEntity<DateValueEntity>> linesData;

    /*
     * (non-Javadoc)
     *
     * @param context
     *
     * @see cn.limc.androidcharts.view.GridChart#GridChart(Context)
     */
    public MACandleStickChart(Context context) {
        super(context);
    }

    /*
     * (non-Javadoc)
     *
     * @param context
     *
     * @param attrs
     *
     * @param defStyle
     *
     * @see cn.limc.androidcharts.view.GridChart#GridChart(Context,
     * AttributeSet, int)
     */
    public MACandleStickChart(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
    }

    /*
     * (non-Javadoc)
     *
     * @param context
     *
     * @param attrs
     *
     *
     *
     * @see cn.limc.androidcharts.view.GridChart#GridChart(Context,
     * AttributeSet)
     */
    public MACandleStickChart(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    @Override
    protected void calcDataValueRange() {
        super.calcDataValueRange();

        double maxValue = this.maxValue;
        double minValue = this.minValue;
        // 逐条输出MA线
        for (int i = 0; i < this.linesData.size(); i++) {
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

            // 判断显示为方柱或显示为线条
            for (int j = 0; j < this.maxSticksNum; j++) {
                DateValueEntity entity;
                if (axisYPosition == AXIS_Y_POSITION_LEFT) {
                    entity = line.getLineData().get(j);
                } else {
                    entity = line.getLineData().get(lineData.size() - 1 - j);
                }
                if (entity.getValue() < minValue) {
                    minValue = entity.getValue();
                }
                if (entity.getValue() > maxValue) {
                    maxValue = entity.getValue();
                }
            }
        }
        this.maxValue = maxValue;
        this.minValue = minValue;
    }

    /*
     * (non-Javadoc)
     *
     * <p>Called when is going to draw this chart<p> <p>チャートを書く前、メソッドを呼ぶ<p>
     * <p>绘制图表时调用<p>
     *
     * @param canvas
     *
     * @see android.view.View#onDraw(android.graphics.Canvas)
     */
    @Override
    protected void onDraw(Canvas canvas) {
        // drawAxisXgraduate(canvas, clickPostX);
        super.onDraw(canvas);
        // draw lines
        if (null != this.linesData) {
            if (0 != this.linesData.size()) {
                drawLines(canvas);
            }
        }
    }

    @Override
    protected void beginRedrawOnTouch(float clickPostX) {
        super.beginRedrawOnTouch(clickPostX);
        int index = (int) (stickData.size() * getTounchPrepcentage());
        if (index > stickData.size() - 1) {
            index = stickData.size() - 1;
        }
        BitherOHLCEntity bitherOHLCEntity = (BitherOHLCEntity) stickData
                .get(index);
        double close = bitherOHLCEntity.getClose();
        int moveToY = (int) (((close - minValue) / (maxValue - minValue)) * getDataQuadrantPaddingHeight());
        String tenLine = "";
        String thirtyLine = "";
        for (int i = 0; i < linesData.size(); i++) {
            LineEntity<DateValueEntity> line = (LineEntity<DateValueEntity>) linesData
                    .get(i);
            DateValueEntity dateValueEntity = line.getLineData().get(index);
            if (i == 0) {
                tenLine = formatDoubleToString(dateValueEntity.getValue());
            } else if (i == 1) {
                thirtyLine = formatDoubleToString(dateValueEntity.getValue());
            }

        }

        if (getTouchEventResponse() != null) {

            Object[] objs = new Object[]{bitherOHLCEntity.getDate(),
                    formatDoubleToString(bitherOHLCEntity.getOpen()),
                    formatDoubleToString(bitherOHLCEntity.getHigh()),
                    formatDoubleToString(bitherOHLCEntity.getLow()),
                    formatDoubleToString(bitherOHLCEntity.getClose()), tenLine,
                    thirtyLine,
                    formatDoubleToString(bitherOHLCEntity.getVolume())};
            getTouchEventResponse().notifyTouchContentChange(objs);
            getTouchEventResponse().notifyTouchPointMove((int) clickPostX,
                    moveToY);

        }

    }

    @Override
    protected void drawPointOfLine(Canvas canvas, float clickPostX) {
        super.drawPointOfLine(canvas, clickPostX);
        int index = (int) (stickData.size() * getTounchPrepcentage());
        if (index > stickData.size() - 1) {
            index = stickData.size() - 1;
        }
        for (int i = 0; i < linesData.size(); i++) {
            LineEntity<DateValueEntity> line = (LineEntity<DateValueEntity>) linesData
                    .get(i);
            float value = line.getLineData().get(index).getValue();
            float valueY = (float) ((1f - (value - minValue)
                    / (maxValue - minValue)) * getDataQuadrantPaddingHeight())
                    + getDataQuadrantPaddingStartY();
            Paint paint = new Paint();
            paint.setColor(line.getLineColor());
            paint.setAntiAlias(true);
            canvas.drawCircle(clickPostX, valueY, 8, paint);
        }
    }

    /**
     * <p>
     * draw lines
     * </p>
     * <p>
     * ラインを書く
     * </p>
     * <p>
     * 绘制线条
     * </p>
     *
     * @param canvas
     */
    protected void drawLines(Canvas canvas) {
        if (null == this.linesData) {
            return;
        }
        // distance between two points
        float lineLength = getDataQuadrantPaddingWidth() / maxSticksNum - 1;
        // start point‘s X
        float startX;

        // draw MA lines
        for (int i = 0; i < linesData.size(); i++) {
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

            // start point
            PointF ptFirst = null;
            if (axisYPosition == AXIS_Y_POSITION_LEFT) {
                // set start point’s X
                startX = getDataQuadrantPaddingStartX() + lineLength / 2;
                for (int j = 0; j < lineData.size(); j++) {
                    float value = lineData.get(j).getValue();
                    // calculate Y
                    float valueY = (float) ((1f - (value - minValue)
                            / (maxValue - minValue)) * getDataQuadrantPaddingHeight())
                            + getDataQuadrantPaddingStartY();

                    // if is not last point connect to previous point
                    if (j > 0) {
                        canvas.drawLine(ptFirst.x, ptFirst.y, startX, valueY,
                                mPaint);
                    }
                    // reset
                    ptFirst = new PointF(startX, valueY);
                    startX = startX + 1 + lineLength;
                }
            } else {
                // set start point’s X
                startX = getDataQuadrantPaddingEndX() - lineLength / 2;
                for (int j = lineData.size() - 1; j >= 0; j--) {
                    float value = lineData.get(j).getValue();
                    // calculate Y
                    float valueY = (float) ((1f - (value - minValue)
                            / (maxValue - minValue)) * getDataQuadrantPaddingHeight())
                            + getDataQuadrantPaddingStartY();

                    // if is not last point connect to previous point
                    if (j < lineData.size() - 1) {
                        canvas.drawLine(ptFirst.x, ptFirst.y, startX, valueY,
                                mPaint);
                    }
                    // reset
                    ptFirst = new PointF(startX, valueY);
                    startX = startX - 1 - lineLength;
                }
            }
        }
    }

    /**
     * @return the linesData
     */
    public List<LineEntity<DateValueEntity>> getLinesData() {
        return linesData;
    }

    /**
     * @param linesData the linesData to set
     */
    public void setLinesData(List<LineEntity<DateValueEntity>> linesData) {
        this.linesData = linesData;
    }
}
