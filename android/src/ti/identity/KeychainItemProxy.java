/**
 * Axway Appcelerator Titanium - ti.identity
 * Copyright (c) 2017 by Axway. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 */
package ti.identity;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.biometric.BiometricPrompt.AuthenticationCallback;
import androidx.fragment.app.FragmentActivity;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.appcelerator.kroll.KrollDict;
import org.appcelerator.kroll.KrollFunction;
import org.appcelerator.kroll.KrollProxy;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.kroll.common.Log;
import org.appcelerator.titanium.TiApplication;

@Kroll.proxy(creatableInModule = TitaniumIdentityModule.class)
public class KeychainItemProxy extends KrollProxy
{

	private static final String TAG = "KeychainItem";

	public static final String PROPERTY_IDENTIFIER = "identifier";
	public static final String PROPERTY_CIPHER = "cipher";
	public static final String PROPERTY_ACCESSIBILITY_MODE = "accessibilityMode";
	public static final String PROPERTY_ACCESS_CONTROL_MODE = "accessControlMode";

	public static final String EVENT_SAVE = "save";
	public static final String EVENT_READ = "read";
	public static final String EVENT_UPDATE = "update";
	public static final String EVENT_RESET = "reset";

	public static final int ACCESSIBLE_ALWAYS = 0;
	public static final int ACCESSIBLE_ALWAYS_THIS_DEVICE_ONLY = 1;
	public static final int ACCESSIBLE_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY = 2;

	public static final int ACCESS_CONTROL_USER_PRESENCE = 1;
	public static final int ACCESS_CONTROL_DEVICE_PASSCODE = 2;
	public static final int ACCESS_CONTROL_TOUCH_ID_ANY = 4;
	public static final int ACCESS_CONTROL_TOUCH_ID_CURRENT_SET = 8;

	private KeyStore keyStore;
	private SecretKey key;
	private Cipher cipher;
	private int ivSize = 16;
	private BiometricPrompt.CryptoObject cryptoObject;

	private String algorithm = KeyProperties.KEY_ALGORITHM_AES;
	private String blockMode = KeyProperties.BLOCK_MODE_CBC;
	private String padding = KeyProperties.ENCRYPTION_PADDING_PKCS7;

	protected BiometricManager biometricManager;
	protected BiometricPrompt.PromptInfo biometricPromptInfo;
	private BiometricPrompt.AuthenticationCallback authenticationCallback;

	private String identifier = "";
	private int accessibilityMode = 0;
	private int accessControlMode = 0;
	private KeyguardManager keyguardManager;
	private String suffix = "_kc.dat";
	private Context context;

	private class EVENT
	{
		public final String event;
		public final String value;

		public EVENT(String event, String value)
		{
			this.event = event;
			this.value = value;
		}

		public EVENT(String event)
		{
			this.event = event;
			this.value = null;
		}
	}
	private List<EVENT> eventQueue = new ArrayList<EVENT>();
	private boolean eventBusy = false;

	@SuppressWarnings("NewApi")
	public KeychainItemProxy()
	{
		super();

		defaultValues.put(PROPERTY_ACCESSIBILITY_MODE, 0);
		defaultValues.put(PROPERTY_ACCESS_CONTROL_MODE, 0);
		defaultValues.put(PROPERTY_CIPHER, getCipher());

		try {
			context = TiApplication.getAppRootOrCurrentActivity();

			// fingerprint authentication
			if (Build.VERSION.SDK_INT >= 23) {
				keyguardManager = context.getSystemService(KeyguardManager.class);
				biometricManager = BiometricManager.from(context);
				authenticationCallback = new AuthenticationCallback() {
					@Override
					public void onAuthenticationError(int errorCode, CharSequence errString)
					{
						switch (errorCode) {
							case BiometricPrompt.ERROR_USER_CANCELED:
							case BiometricPrompt.ERROR_CANCELED:
							case BiometricPrompt.ERROR_NEGATIVE_BUTTON:
								doEvents(TitaniumIdentityModule.ERROR_AUTHENTICATION_FAILED, errString.toString());
								break;
							default:
								doEvents(errorCode, errString.toString());
						}
					}

					@Override
					public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result)
					{
						doEvents(0, null);
					}

					@Override
					public void onAuthenticationFailed()
					{
						doEvents(TitaniumIdentityModule.ERROR_AUTHENTICATION_FAILED,
								 "failed to authenticate fingerprint!");
					}
				};

				final BiometricPrompt.PromptInfo.Builder promptInfo = new BiometricPrompt.PromptInfo.Builder();
				promptInfo.setTitle(TitaniumIdentityModule.reason);
				promptInfo.setSubtitle(TitaniumIdentityModule.reasonSubtitle);
				promptInfo.setDescription(TitaniumIdentityModule.reasonText);
				promptInfo.setNegativeButtonText(TitaniumIdentityModule.negativeButtonText);
				biometricPromptInfo = promptInfo.build();
			}

			// load Android key store
			keyStore = KeyStore.getInstance("AndroidKeyStore");
			keyStore.load(null);

		} catch (Exception e) {
			Log.e(TAG, "could not load Android key store: " + e.getMessage());
		}
	}

	@Kroll.getProperty
	@Kroll.method
	public int getAccessibilityMode()
	{
		return accessibilityMode;
	}

	@Kroll.getProperty
	@Kroll.method
	public int getAccessControlMode()
	{
		return accessControlMode;
	}

	@Kroll.getProperty
	@Kroll.method
	private String getCipher()
	{
		return algorithm + "/" + blockMode + "/" + padding;
	}

	@Kroll.getProperty
	@Kroll.method
	private String getIdentifier()
	{
		return identifier;
	}

	private boolean useFingerprintAuthentication()
	{
		if ((accessControlMode & (ACCESS_CONTROL_TOUCH_ID_ANY | ACCESS_CONTROL_TOUCH_ID_CURRENT_SET)) != 0) {
			return true;
		}
		return false;
	}

	private void processEvents()
	{
		if (!eventBusy && !eventQueue.isEmpty()) {
			eventBusy = true;

			EVENT e = eventQueue.get(0);
			KrollDict result = null;
			switch (e.event) {
				case EVENT_UPDATE:
				case EVENT_SAVE:
					result = initEncrypt();
					break;
				case EVENT_READ:
					result = initDecrypt();
					break;
				case EVENT_RESET:
					result = doReset();
					break;
			}
			if (result != null) {
				fireEvent(e.event, result);
				eventQueue.remove(e);
				eventBusy = false;
				processEvents();
			} else if (!useFingerprintAuthentication()) {
				doEvents(0, null);
			}
		}
	}

	private void doEvents(int errorCode, String message)
	{
		KrollDict result = null;
		if (!eventQueue.isEmpty()) {
			EVENT e = eventQueue.get(0);
			if (errorCode != 0) {
				result = new KrollDict();
				result.put("success", false);
				result.put("code", errorCode);
				result.put("error", message);
			} else {
				switch (e.event) {
					case EVENT_UPDATE:
						if (!exists()) {
							result = new KrollDict();
							result.put("success", false);
							result.put("code", -1);
							result.put("error", "could not update, item does not exist.");
							break;
						}
					case EVENT_SAVE:
						result = doEncrypt(e.value);
						break;
					case EVENT_READ:
						result = doDecrypt();
						break;
				}
			}
			if (result != null) {
				fireEvent(e.event, result);
			}
			eventQueue.remove(e);
		}
		eventBusy = false;
		processEvents();
	}

	@SuppressWarnings("NewApi")
	private KrollDict initEncrypt()
	{
		try {
			// initialize encryption cipher
			cipher.init(Cipher.ENCRYPT_MODE, key);

			// fingerprint authentication
			if (biometricManager != null && useFingerprintAuthentication()) {
				final Executor executor = Executors.newSingleThreadExecutor();
				final BiometricPrompt prompt = new BiometricPrompt(
					(FragmentActivity) TiApplication.getAppCurrentActivity(), executor, authenticationCallback);
				prompt.authenticate(biometricPromptInfo, cryptoObject);
			}

		} catch (Exception e) {
			KrollDict result = new KrollDict();
			result.put("identifier", identifier);
			result.put("success", false);
			if (e instanceof InvalidKeyException && key == null) {
				result.put("code", TitaniumIdentityModule.ERROR_PASSCODE_NOT_SET);
				result.put("error", "device is not secure, could not generate key!");
			} else if (e instanceof KeyPermanentlyInvalidatedException) {
				result.put("code", TitaniumIdentityModule.ERROR_KEY_PERMANENTLY_INVALIDATED);
				result.put("error", "key permantently invalidated!");

				try {
					if (keyStore != null) {
						keyStore.deleteEntry(identifier);
					}
				} catch (Exception ex) {
					// do nothing...
				}
			} else {
				result.put("code", -1);
				result.put("error", e.getMessage());
			}
			return result;
		}
		return null;
	}

	private KrollDict doEncrypt(String value)
	{
		KrollDict result = new KrollDict();
		result.put("identifier", identifier);
		try {
			// save encrypted data to private storage
			FileOutputStream fos = context.openFileOutput(identifier + suffix, Context.MODE_PRIVATE);

			// write IV
			fos.write(cipher.getIV());

			// write encrypted data
			byte[] data = value.getBytes(StandardCharsets.UTF_8);
			byte[] encryptedData = cipher.doFinal(data);
			fos.write(encryptedData);

			// close stream
			if (fos != null) {
				fos.close();
			}

			result.put("success", true);
			result.put("code", 0);
		} catch (Exception e) {
			result.put("success", false);
			result.put("code", -1);
			result.put("error", e.getMessage());
		}
		return result;
	}

	@SuppressWarnings("NewApi")
	private KrollDict initDecrypt()
	{
		try {
			// load file from private storage
			FileInputStream fin = context.openFileInput(identifier + suffix);

			// read IV
			byte[] iv = new byte[ivSize];
			fin.read(iv, 0, iv.length);

			// close stream
			if (fin != null) {
				fin.close();
			}

			// initialize decryption cipher
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

			// fingerprint authentication
			if (biometricManager != null && useFingerprintAuthentication()) {
				final Executor executor = Executors.newSingleThreadExecutor();
				final BiometricPrompt prompt = new BiometricPrompt(
					(FragmentActivity) TiApplication.getAppCurrentActivity(), executor, authenticationCallback);
				prompt.authenticate(biometricPromptInfo, cryptoObject);
			}

		} catch (Exception e) {
			KrollDict result = new KrollDict();
			result.put("identifier", identifier);
			result.put("success", false);
			result.put("code", -1);
			if (e instanceof FileNotFoundException) {
				result.put("error", "keychain data does not exist!");
			} else if (e instanceof InvalidKeyException && key == null) {
				result.put("code", TitaniumIdentityModule.ERROR_PASSCODE_NOT_SET);
				result.put("error", "device is not secure, could not generate key!");
			} else if (e instanceof KeyPermanentlyInvalidatedException) {
				result.put("code", TitaniumIdentityModule.ERROR_KEY_PERMANENTLY_INVALIDATED);
				result.put("error", "key permantently invalidated!");

				try {
					if (keyStore != null) {
						keyStore.deleteEntry(identifier);
					}
				} catch (Exception ex) {
					// do nothing...
				}
			} else {
				result.put("error", e.getMessage());
			}
			return result;
		}
		return null;
	}

	private KrollDict doDecrypt()
	{
		KrollDict result = new KrollDict();
		result.put("identifier", identifier);
		try {
			// load file from private storage
			FileInputStream fin = context.openFileInput(identifier + suffix);
			fin.skip(ivSize);

			// read decrypted data
			BufferedInputStream bis = new BufferedInputStream(fin);
			CipherInputStream cis = new CipherInputStream(bis, cipher);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] buffer = new byte[1024];
			int length = 0;
			String decrypted = "";

			// since we only encrypt strings, this is acceptable
			while ((length = cis.read(buffer)) != -1) {

				// obtain decrypted string from buffer
				baos.write(buffer, 0, length);
			}
			decrypted = new String(baos.toByteArray(), StandardCharsets.UTF_8).replace("\u0000+$", "");

			// close stream
			if (baos != null) {
				baos.close();
			}
			if (cis != null) {
				cis.close();
			}
			if (bis != null) {
				bis.close();
			}
			if (fin != null) {
				fin.close();
			}

			result.put("success", true);
			result.put("code", 0);
			result.put("value", decrypted);
		} catch (Exception e) {
			result.put("success", false);
			result.put("code", -1);
			if (e instanceof FileNotFoundException) {
				result.put("error", "keychain data does not exist!");
			} else {
				result.put("error", e.getMessage());
			}
		}
		return result;
	}

	private KrollDict doReset()
	{
		KrollDict result = new KrollDict();
		boolean deleted = false;

		// delete file from private storage
		File file = context.getFileStreamPath(identifier + suffix);
		if (file != null && file.exists()) {
			deleted = context.deleteFile(identifier + suffix);

			// remove key from Android key store
			/*if (deleted) {
				try {
					keyStore.deleteEntry(identifier);
				} catch (Exception e) {
					deleted = false;
					result.put("error", "could not remove key");
				}
			} else {*/
			if (!deleted) {
				result.put("error", "could not delete data");
			}
		}

		result.put("success", deleted);
		result.put("code", deleted ? 0 : -1);
		return result;
	}

	private boolean exists()
	{
		File file = context.getFileStreamPath(identifier + suffix);
		return file != null && file.exists();
	}

	public void resetEvents()
	{
		eventQueue.clear();
		eventBusy = false;
	}

	@Kroll.method
	public void save(String value)
	{
		eventQueue.add(new EVENT(EVENT_SAVE, value));
		processEvents();
	}

	@Kroll.method
	public void read()
	{
		eventQueue.add(new EVENT(EVENT_READ));
		processEvents();
	}

	@Kroll.method
	public void update(String value)
	{
		eventQueue.add(new EVENT(EVENT_UPDATE, value));
		processEvents();
	}

	@Kroll.method
	public void reset()
	{
		eventQueue.add(new EVENT(EVENT_RESET));
		processEvents();
	}

	@Kroll.method
	public void fetchExistence(Object callback)
	{
		if (callback instanceof KrollFunction) {
			KrollDict result = new KrollDict();
			result.put("exists", exists());
			((KrollFunction) callback).callAsync(krollObject, new Object[] { result });
		}
	}

	@Override
	@SuppressWarnings("NewApi")
	public void handleCreationDict(KrollDict dict)
	{
		super.handleCreationDict(dict);

		if (dict.containsKey(PROPERTY_CIPHER)) {
			String[] cipher = dict.getString(PROPERTY_CIPHER).split("/");
			if (cipher.length == 3) {
				algorithm = cipher[0];
				blockMode = cipher[1];
				padding = cipher[2];

				// set IV size
				ivSize = blockMode == KeyProperties.BLOCK_MODE_GCM ? 12 : 16;
			}
		}
		if (dict.containsKey(PROPERTY_ACCESSIBILITY_MODE)) {
			accessibilityMode = dict.getInt(PROPERTY_ACCESSIBILITY_MODE);
		}
		if (dict.containsKey(PROPERTY_ACCESS_CONTROL_MODE)) {
			accessControlMode = dict.getInt(PROPERTY_ACCESS_CONTROL_MODE);
		}
		if (dict.containsKey(PROPERTY_IDENTIFIER)) {
			identifier = dict.getString(PROPERTY_IDENTIFIER);
			if (!identifier.isEmpty()) {
				try {
					if (!keyStore.containsAlias(identifier)) {
						KeyGenerator generator = KeyGenerator.getInstance(algorithm, "AndroidKeyStore");
						KeyGenParameterSpec.Builder spec =
							new KeyGenParameterSpec
								.Builder(identifier, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
								.setBlockModes(blockMode)
								.setEncryptionPaddings(padding);

						if ((accessControlMode & (ACCESS_CONTROL_TOUCH_ID_ANY | ACCESS_CONTROL_TOUCH_ID_CURRENT_SET))
							!= 0) {
							spec.setUserAuthenticationRequired(true);
						}
						if ((accessControlMode & ACCESS_CONTROL_TOUCH_ID_CURRENT_SET) != 0
							&& Build.VERSION.SDK_INT >= 24) {
							spec.setInvalidatedByBiometricEnrollment(true);
						}

						generator.init(spec.build());
						key = generator.generateKey();
					} else {
						key = (SecretKey) keyStore.getKey(identifier, null);
					}
					if ((accessControlMode & (ACCESS_CONTROL_USER_PRESENCE | ACCESS_CONTROL_DEVICE_PASSCODE)) != 0
						&& !keyguardManager.isDeviceSecure()) {
						key = null;
						Log.e(TAG, "device is not secure, could not generate key!");
					}
					cipher = Cipher.getInstance(getCipher());
					if (biometricManager != null) {
						cryptoObject = new BiometricPrompt.CryptoObject(cipher);
					}
				} catch (Exception e) {
					Log.e(TAG, e.toString());
				}
			}
		}
	}

	@Override
	public String getApiName()
	{
		return "Ti.Identity.KeychainItem";
	}
}
