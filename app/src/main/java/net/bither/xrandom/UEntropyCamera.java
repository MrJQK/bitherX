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

package net.bither.xrandom;

import android.hardware.Camera;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.view.SurfaceHolder;
import android.view.SurfaceView;

import net.bither.camera.CameraManager;

/**
 * Created by songchenwen on 14-9-11.
 */
public class UEntropyCamera implements SurfaceHolder.Callback, IUEntropySource,
        Thread.UncaughtExceptionHandler {
    private static final long AUTO_FOCUS_INTERVAL_MS = 2500L;

    private static boolean DISABLE_CONTINUOUS_AUTOFOCUS = Build.MODEL.equals("GT-I9100") //
            // Galaxy S2
            || Build.MODEL.equals("SGH-T989") // Galaxy S2
            || Build.MODEL.equals("SGH-T989D") // Galaxy S2 X
            || Build.MODEL.equals("SAMSUNG-SGH-I727") // Galaxy S2 Skyrocket
            || Build.MODEL.equals("GT-I9300") // Galaxy S3
            || Build.MODEL.equals("GT-N7000"); // Galaxy Note


    private final CameraManager cameraManager = new CameraManager();
    private SurfaceHolder surfaceHolder;
    private HandlerThread cameraThread;
    private Handler cameraHandler;

    private UEntropyCollector collector;

    public UEntropyCamera(SurfaceView surfaceView, UEntropyCollector collector) {
        this.collector = collector;
        surfaceView.getHolder().setType(SurfaceHolder.SURFACE_TYPE_PUSH_BUFFERS);
        surfaceView.getHolder().addCallback(this);
    }

    @Override
    public void surfaceCreated(SurfaceHolder holder) {
        if (surfaceHolder == null) {
            surfaceHolder = holder;
            cameraHandler.post(openRunnable);
        }
    }


    private final Runnable openRunnable = new Runnable() {
        @Override
        public void run() {
            try {
                final Camera camera = cameraManager.open(surfaceHolder,
                        !DISABLE_CONTINUOUS_AUTOFOCUS);

                final String focusMode = camera.getParameters().getFocusMode();
                final boolean nonContinuousAutoFocus = Camera.Parameters.FOCUS_MODE_AUTO.equals
                        (focusMode) || Camera.Parameters.FOCUS_MODE_MACRO.equals(focusMode);

                if (nonContinuousAutoFocus) {
                    cameraHandler.post(new AutoFocusRunnable(camera));
                }

                cameraHandler.post(fetchCameraDataRunnable);

            } catch (final Exception x) {
                uncaughtException(Thread.currentThread(), x);
            }
        }
    };

    private final Runnable closeRunnable = new Runnable() {
        @Override
        public void run() {
            cameraManager.close();

            // cancel background thread
            cameraHandler.removeCallbacksAndMessages(null);
            cameraThread.quit();
        }
    };

    @Override
    public void onResume() {
        if (cameraThread != null && cameraThread.isAlive()) {
            return;
        }
        cameraThread = new HandlerThread("UEntropyCameraThread",
                android.os.Process.THREAD_PRIORITY_BACKGROUND);
        cameraThread.setUncaughtExceptionHandler(this);
        cameraThread.start();
        cameraHandler = new Handler(cameraThread.getLooper());
        if (surfaceHolder != null) {
            cameraHandler.post(openRunnable);
        }
    }

    @Override
    public void onPause() {
        if (cameraThread != null && cameraThread.isAlive()) {
            cameraHandler.post(closeRunnable);
            surfaceHolder.removeCallback(this);
        }
    }

    @Override
    public UEntropyCollector.UEntropySource type() {
        return UEntropyCollector.UEntropySource.Camera;
    }
    private final class AutoFocusRunnable implements Runnable {
        private final Camera camera;

        public AutoFocusRunnable(final Camera camera) {
            this.camera = camera;
        }

        @Override
        public void run() {
            camera.autoFocus(new Camera.AutoFocusCallback() {
                @Override
                public void onAutoFocus(final boolean success, final Camera camera) {
                    // schedule again
                    cameraHandler.postDelayed(AutoFocusRunnable.this, AUTO_FOCUS_INTERVAL_MS);
                }
            });
        }
    }

    private final Runnable fetchCameraDataRunnable = new Runnable() {

        @Override
        public void run() {
            cameraManager.requestPreviewFrame(new Camera.PreviewCallback() {
                @Override
                public void onPreviewFrame(final byte[] data, final Camera camera) {
                    collector.onNewData(data, UEntropyCollector.UEntropySource.Camera);
                    cameraHandler.post(fetchCameraDataRunnable);
                }
            });
        }
    };


    @Override
    public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
    }

    @Override
    public void surfaceDestroyed(SurfaceHolder holder) {

    }

    @Override
    public void uncaughtException(Thread thread, Throwable ex) {
        collector.onError(new Exception(ex), UEntropyCamera.this);
    }

}
