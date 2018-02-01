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

package net.bither.ui.base.keyboard;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.XmlResourceParser;
import android.graphics.drawable.Drawable;
import android.inputmethodservice.Keyboard;

import net.bither.R;

public class EntryKeyboard extends Keyboard {
    public static interface DrawKeyListener {
        public int[] beforeDrawKeyWithStates(Key key, int[] states);
    }

    public static final int KEYCODE_ENTER = 10;

    private static final int SHIFT_OFF = 0;
    private static final int SHIFT_ON = 1;
    private static final int SHIFT_LOCKED = 2;

    private Drawable mShiftIcon;
    private Drawable mShiftLockIcon;

    // These two arrays must be the same length
    private Drawable mOldShiftIcon;
    private Keyboard.Key mShiftKey;

    private Keyboard.Key mEnterKey;
    private int mShiftState = SHIFT_OFF;

    public EntryKeyboard(Context context, int xmlLayoutResId) {
        this(context, xmlLayoutResId, 0);
    }

    public EntryKeyboard(Context context, int xmlLayoutResId, int mode) {
        super(context, xmlLayoutResId, mode);
        init(context);
    }

    private void init(Context context) {
        final Resources res = context.getResources();
        mShiftIcon = res.getDrawable(R.drawable.sym_keyboard_shift_holo_dark);
        mShiftLockIcon = res.getDrawable(R.drawable.sym_keyboard_shift_locked_holo_dark);
    }

    public EntryKeyboard(Context context, int layoutTemplateResId, CharSequence characters,
                         int columns, int horizontalPadding) {
        super(context, layoutTemplateResId, characters, columns, horizontalPadding);
    }

    @Override
    protected Keyboard.Key createKeyFromXml(Resources res, Keyboard.Row parent, int x, int y,
                                            XmlResourceParser parser) {
        LatinKey key = new LatinKey(res, parent, x, y, parser);
        final int code = key.codes[0];
        if (code >= 0 && code != '\n' && (code < 32 || code > 127)) {
            key.label = " ";
            key.setEnabled(false);
        }
        switch (key.codes[0]) {
            case KEYCODE_ENTER:
                mEnterKey = key;
                break;
        }
        return key;
    }

    /**
     * Allows enter key resources to be overridden
     *
     * @param res       resources to grab given items from
     * @param previewId preview drawable shown on enter key
     * @param iconId    normal drawable shown on enter key
     * @param labelId   string shown on enter key
     */
    public void setEnterKeyResources(Resources res, int previewId, int iconId, int labelId) {
        if (mEnterKey != null) {
            // Reset some of the rarely used attributes.
            mEnterKey.popupCharacters = null;
            mEnterKey.popupResId = 0;
            mEnterKey.text = null;
            if (previewId != 0) {
                mEnterKey.iconPreview = res.getDrawable(previewId);
            }
            if (iconId != 0) {
                mEnterKey.icon = res.getDrawable(iconId);
            }
            if (labelId != 0) {
                mEnterKey.label = res.getText(labelId);
            }

            // Set the initial size of the preview icon
            if (mEnterKey.iconPreview != null) {
                mEnterKey.iconPreview.setBounds(0, 0, mEnterKey.iconPreview.getIntrinsicWidth(),
                        mEnterKey.iconPreview.getIntrinsicHeight());
            }
        }
    }

    public void setEnterKeyText(CharSequence text) {
        if(mEnterKey != null) {
            mEnterKey.label = text;
        }
    }

    public int getEnterKeyIndex() {
        return getKeys().indexOf(mEnterKey);
    }

    /**
     * Allows shiftlock to be turned on.  See {@link #setShiftLocked(boolean)}
     */
    public void enableShiftLock() {
        int index = getShiftKeyIndex();
        mShiftKey = getKeys().get(index);
        if (mShiftKey instanceof LatinKey) {
            ((LatinKey) mShiftKey).enableShiftLock();
        }
        mOldShiftIcon = mShiftKey.icon;
    }

    /**
     * Turn on shift lock. This turns on the LED for this key, if it has one.
     * It should be followed by a call to {@link android.inputmethodservice
     * .KeyboardView#invalidateKey(int)}
     * or {@link android.inputmethodservice.KeyboardView#invalidateAllKeys()}
     *
     * @param shiftLocked
     */
    public void setShiftLocked(boolean shiftLocked) {
        if (mShiftKey != null) {
            mShiftKey.on = shiftLocked;
            mShiftKey.icon = mShiftLockIcon;
        }
        mShiftState = shiftLocked ? SHIFT_LOCKED : SHIFT_ON;
    }

    /**
     * Turn on shift mode. Sets shift mode and turns on icon for shift key.
     * It should be followed by a call to {@link android.inputmethodservice
     * .KeyboardView#invalidateKey(int)}
     * or {@link android.inputmethodservice.KeyboardView#invalidateAllKeys()}
     *
     * @param shiftState
     */
    @Override
    public boolean setShifted(boolean shiftState) {
        boolean shiftChanged = false;
        if (shiftState == false) {
            shiftChanged = mShiftState != SHIFT_OFF;
            mShiftState = SHIFT_OFF;
        } else if (mShiftState == SHIFT_OFF) {
            shiftChanged = mShiftState == SHIFT_OFF;
            mShiftState = SHIFT_ON;
        }
        if (mShiftKey != null) {
            if (shiftState == false) {
                mShiftKey.on = false;
                mShiftKey.icon = mOldShiftIcon;
            } else if (mShiftState == SHIFT_OFF) {
                mShiftKey.on = false;
                mShiftKey.icon = mShiftIcon;
            }
        } else {
            // return super.setShifted(shiftState);
        }

        return shiftChanged;
    }

    /**
     * Whether or not keyboard is shifted.
     *
     * @return true if keyboard state is shifted.
     */
    @Override
    public boolean isShifted() {
        if (mShiftKey != null) {
            return mShiftState != SHIFT_OFF;
        } else {
            return super.isShifted();
        }
    }

    public void setDrawKeyListener(DrawKeyListener l) {
        for(Key k : getKeys()){
            if(k instanceof LatinKey){
                ((LatinKey)k).setDrawListener(l);
            }
        }
    }

    public static class LatinKey extends Keyboard.Key {
        private boolean mShiftLockEnabled;
        private boolean mEnabled = true;
        private DrawKeyListener drawListener;

        public LatinKey(Resources res, Keyboard.Row parent, int x, int y,
                        XmlResourceParser parser) {
            super(res, parent, x, y, parser);
            if (popupCharacters != null && popupCharacters.length() == 0) {
                // If there is a keyboard with no keys specified in popupCharacters
                popupResId = 0;
            }
        }

        void setEnabled(boolean enabled) {
            mEnabled = enabled;
        }

        void enableShiftLock() {
            mShiftLockEnabled = true;
        }

        @Override
        public void onReleased(boolean inside) {
            if (!mShiftLockEnabled) {
                super.onReleased(inside);
            } else {
                pressed = !pressed;
            }
        }

        @Override
        public int[] getCurrentDrawableState() {
            if (drawListener != null) {
                return drawListener.beforeDrawKeyWithStates(this, super.getCurrentDrawableState());
            }
            return super.getCurrentDrawableState();
        }

        /**
         * Overriding this method so that we can reduce the target area for certain keys.
         */
        @Override
        public boolean isInside(int x, int y) {
            if (!mEnabled) {
                return false;
            }
            return super.isInside(x, y);
        }

        public void setDrawListener(DrawKeyListener l) {
            drawListener = l;
        }
    }
}
