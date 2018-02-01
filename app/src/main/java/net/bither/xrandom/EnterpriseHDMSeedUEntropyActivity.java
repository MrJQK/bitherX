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

import net.bither.bitherj.core.EnterpriseHDMSeed;
import net.bither.bitherj.crypto.SecureCharSequence;

/**
 * Created by songchenwen on 15/6/9.
 */
public class EnterpriseHDMSeedUEntropyActivity extends UEntropyActivity {
    private static final int MinGeneratingTime = 5000;
    private GenerateThread generateThread;

    @Override
    Thread getGeneratingThreadWithXRandom(UEntropyCollector collector, SecureCharSequence
            password) {
        generateThread = new GenerateThread(collector, password);
        return generateThread;
    }

    @Override
    void cancelGenerating(Runnable cancelRunnable) {
        generateThread.cancel(cancelRunnable);
    }

    @Override
    void didSuccess(Object obj) {
        if (obj == null) {
            setResult(RESULT_CANCELED);
        } else {
            setResult(RESULT_OK);
        }
        finish();
    }

    private class GenerateThread extends Thread {
        final private double startProgress = 0.3;

        private long startGeneratingTime;

        private SecureCharSequence password;
        private Runnable cancelRunnable;
        private UEntropyCollector entropyCollector;

        public GenerateThread(UEntropyCollector collector, SecureCharSequence password) {
            super();
            this.password = password;
            entropyCollector = collector;
        }

        @Override
        public synchronized void start() {
            if (password == null) {
                throw new IllegalStateException("GenerateThread does not have password");
            }
            startGeneratingTime = System.currentTimeMillis();
            super.start();
            onProgress(startProgress);
        }

        public void cancel(Runnable cancelRunnable) {
            this.cancelRunnable = cancelRunnable;
        }

        private void finishGenerate() {
            if (password != null) {
                password.wipe();
                password = null;
            }
            entropyCollector.stop();
        }

        @Override
        public void run() {
            boolean success = false;
            onProgress(startProgress);
            EnterpriseHDMSeed seed = null;
            try {
                entropyCollector.start();

                XRandom xRandom = new XRandom(entropyCollector);

                if (cancelRunnable != null) {
                    finishGenerate();
                    runOnUiThread(cancelRunnable);
                    return;
                }

                seed = new EnterpriseHDMSeed(xRandom, password);

                if (cancelRunnable != null) {
                    finishGenerate();
                    runOnUiThread(cancelRunnable);
                    return;
                }

                onProgress(1);

                entropyCollector.stop();
                success = seed != null;
            } catch (Exception e) {
                e.printStackTrace();
            }

            finishGenerate();
            if (success) {
                while (System.currentTimeMillis() - startGeneratingTime < MinGeneratingTime) {

                }
                onProgress(1);
                onSuccess(seed);
            } else {
                onFailed();
            }
        }
    }
}
