/**
 * Axway Appcelerator Titanium - ti.identity
 * Copyright (c) 2017 by Axway. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 */
package ti.identity;

import android.app.Activity;
import android.os.Build;
import java.lang.Override;
import java.util.HashMap;
import org.appcelerator.kroll.KrollDict;
import org.appcelerator.kroll.KrollFunction;
import org.appcelerator.kroll.KrollModule;
import org.appcelerator.kroll.KrollProxy;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.kroll.common.Log;
import org.appcelerator.titanium.util.TiConvert;

@Kroll.module(name = "Identity", id = "ti.identity")
public class TitaniumIdentityModule extends KrollModule
{
	private static final String TAG = "Identity";
	public static final int PERMISSION_CODE_FINGERPRINT = 99;

	public static final String PROPERTY_AUTHENTICATION_POLICY = "authenticationPolicy";

	@Kroll.constant
	public static final int SUCCESS = 0;
	@Kroll.constant
	public static final int SERVICE_MISSING = 1;
	@Kroll.constant
	public static final int SERVICE_VERSION_UPDATE_REQUIRED = 2;
	@Kroll.constant
	public static final int SERVICE_DISABLED = 3;
	@Kroll.constant
	public static final int SERVICE_INVALID = 9;

	@Kroll.constant
	public static final int AUTHENTICATION_POLICY_BIOMETRICS = 0;
	@Kroll.constant
	public static final int AUTHENTICATION_POLICY_PASSCODE = 1;

	@Kroll.constant
	public static final int ACCESSIBLE_ALWAYS = KeychainItemProxy.ACCESSIBLE_ALWAYS;
	@Kroll.constant
	public static final int ACCESSIBLE_ALWAYS_THIS_DEVICE_ONLY = KeychainItemProxy.ACCESSIBLE_ALWAYS_THIS_DEVICE_ONLY;
	@Kroll.constant
	public static final int ACCESSIBLE_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY =
		KeychainItemProxy.ACCESSIBLE_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY;

	@Kroll.constant
	public static final int ACCESS_CONTROL_USER_PRESENCE = KeychainItemProxy.ACCESS_CONTROL_USER_PRESENCE;
	@Kroll.constant
	public static final int ACCESS_CONTROL_DEVICE_PASSCODE = KeychainItemProxy.ACCESS_CONTROL_DEVICE_PASSCODE;
	@Kroll.constant
	public static final int ACCESS_CONTROL_TOUCH_ID_ANY = KeychainItemProxy.ACCESS_CONTROL_TOUCH_ID_ANY;
	@Kroll.constant
	public static final int ACCESS_CONTROL_TOUCH_ID_CURRENT_SET = KeychainItemProxy.ACCESS_CONTROL_TOUCH_ID_CURRENT_SET;

	@Kroll.constant
	public static final int ERROR_TOUCH_ID_LOCKOUT = 7;
	@Kroll.constant
	public static final int ERROR_AUTHENTICATION_FAILED = -1;
	@Kroll.constant
	public static final int ERROR_TOUCH_ID_NOT_ENROLLED = -2;
	@Kroll.constant
	public static final int ERROR_TOUCH_ID_NOT_AVAILABLE = -3;
	@Kroll.constant
	public static final int ERROR_PASSCODE_NOT_SET = -4;
	@Kroll.constant
	public static final int ERROR_KEY_PERMANENTLY_INVALIDATED = -5;

	@Kroll.constant
	public static final int FINGERPRINT_ACQUIRED_PARTIAL = 1;
	@Kroll.constant
	public static final int FINGERPRINT_ACQUIRED_INSUFFICIENT = 2;
	@Kroll.constant
	public static final int FINGERPRINT_ACQUIRED_IMAGER_DIRTY = 3;
	@Kroll.constant
	public static final int FINGERPRINT_ACQUIRED_TOO_SLOW = 4;
	@Kroll.constant
	public static final int FINGERPRINT_ACQUIRED_TOO_FAST = 5;

	protected FingerPrintHelper mfingerprintHelper;
	private Throwable fingerprintHelperException;

	private static int authenticationPolicy = AUTHENTICATION_POLICY_BIOMETRICS;

	public TitaniumIdentityModule()
	{
		super();
		init();
	}

	@Kroll
		.getProperty
		@Kroll.method
		public int getAuthenticationPolicy()
	{
		return authenticationPolicy;
	}

	@Kroll
		.setProperty
		@Kroll.method
		public void setAuthenticationPolicy(int policy)
	{
		authenticationPolicy = policy;
	}

	private void init()
	{
		if (Build.VERSION.SDK_INT >= 23) {
			try {
				mfingerprintHelper = new FingerPrintHelper();
			} catch (Exception e) {
				mfingerprintHelper = null;
				fingerprintHelperException = e.getCause();
				Log.e(TAG, fingerprintHelperException.getMessage());
			}
		}
	}

	@Override
	public void propertyChanged(String key, Object oldValue, Object newValue, KrollProxy proxy)
	{
		if (key.equals(PROPERTY_AUTHENTICATION_POLICY)) {
			authenticationPolicy = TiConvert.toInt(newValue);
		}
	}

	@Kroll.method
	public void authenticate(HashMap params)
	{
		if (mfingerprintHelper == null) {
			init();
		}
		if (params == null || mfingerprintHelper == null) {
			return;
		}
		if (params.containsKey("callback")) {
			Object callback = params.get("callback");
			String title = (String) params.get("title");
			String subTitle = (String) params.get("subTitle");
			String cancelRaison = (String) params.get("cancelRaison");
			if (callback instanceof KrollFunction) {
				mfingerprintHelper.startListening((KrollFunction) callback, title, subTitle, cancelRaison,
												  getKrollObject());
			}
		}
	}

	@Kroll.method
	public HashMap deviceCanAuthenticate()
	{
		if (mfingerprintHelper == null) {
			init();
		}
		if (Build.VERSION.SDK_INT >= 23 && mfingerprintHelper != null) {
			return mfingerprintHelper.deviceCanAuthenticate(authenticationPolicy);
		}

		KrollDict response = new KrollDict();
		response.put("canAuthenticate", false);
		response.put("code", TitaniumIdentityModule.ERROR_TOUCH_ID_NOT_AVAILABLE);
		if (Build.VERSION.SDK_INT < 23) {
			response.put("error", "Device is running with API < 23");
		} else if (fingerprintHelperException != null) {
			response.put("error", fingerprintHelperException.getMessage());
		} else {
			response.put("error", "Device does not support fingerprint authentication");
		}

		return response;
	}

	@Kroll.method
	public boolean isSupported()
	{
		if (mfingerprintHelper == null) {
			init();
		}
		if (Build.VERSION.SDK_INT >= 23 && mfingerprintHelper != null) {
			return mfingerprintHelper.isDeviceSupported();
		}
		return false;
	}

	@Override
	public void onPause(Activity activity)
	{
		super.onPause(activity);
		if (mfingerprintHelper != null) {
			mfingerprintHelper.stopListening();
		}
	}

	@Kroll.method
	public void invalidate()
	{
		if (mfingerprintHelper != null) {
			mfingerprintHelper.stopListening();
		}
	}

	@Override
	public String getApiName()
	{
		return "Ti.Identity";
	}
}
