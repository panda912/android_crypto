package com.panda912.crypto.demo;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.AppCompatButton;
import androidx.appcompat.widget.AppCompatEditText;

import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;

import com.panda912.crypto.mbedtls.Crypto;

public class MainActivity extends AppCompatActivity implements OnClickListener {
  public static final String TAG = "MainActivity";

  private AppCompatEditText plainEt;
  private AppCompatEditText cipherEt;
  private AppCompatButton testBtn;
  private AppCompatButton aesEncryptBtn;
  private AppCompatButton aesDecryptBtn;
  private AppCompatButton desEncryptBtn;
  private AppCompatButton desDecryptBtn;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    plainEt = findViewById(R.id.et_plain);
    cipherEt = findViewById(R.id.et_cipher);
    testBtn = findViewById(R.id.btn_test);
    testBtn.setOnClickListener(this);
    aesEncryptBtn = findViewById(R.id.btn_aes_encrypt);
    aesEncryptBtn.setOnClickListener(this);
    aesDecryptBtn = findViewById(R.id.btn_aes_decrypt);
    aesDecryptBtn.setOnClickListener(this);
    desEncryptBtn = findViewById(R.id.btn_des_encrypt);
    desEncryptBtn.setOnClickListener(this);
    desDecryptBtn = findViewById(R.id.btn_des_decrypt);
    desDecryptBtn.setOnClickListener(this);
  }

  @Override
  public void onClick(View view) {
    if (view == testBtn) {
      for (int i = 0; i < 1000; i++) {
        byte[] cipher = Base64.decode(cipherEt.getText().toString(), Base64.DEFAULT);
        String plain = Crypto.desDecrypt(cipher, "12345678");
        plainEt.setText(plain);
//        try {
//          String cipher = Crypto.aesEncrypt(plainEt.getText().toString());
//          Log.i(TAG, "cipher=" + cipher);
//          cipherEt.setText(cipher);
//        } catch (Throwable throwable) {
//          throwable.printStackTrace();
//        }
      }
    } else if (view == aesEncryptBtn) {
      String plain = plainEt.getText().toString();
      byte[] cipher = Crypto.aesEncrypt(plain, "1234567890123456", "1234567890123456");
      String base64 = Base64.encodeToString(cipher, Base64.DEFAULT);
      cipherEt.setText(base64);
    } else if (view == aesDecryptBtn) {
      byte[] cipher = Base64.decode(cipherEt.getText().toString(), Base64.DEFAULT);
      Log.i(TAG, new String(cipher));
      String plain = Crypto.aesDecrypt(cipher, "1234567890123456", "1234567890123456");
      plainEt.setText(plain);
    } else if (view == desEncryptBtn) {
      String plain = plainEt.getText().toString();
      byte[] cipher = Crypto.desEncrypt(plain, "12345678", "12345678");
      String base64 = Base64.encodeToString(cipher, Base64.DEFAULT);
      cipherEt.setText(base64);
    } else if (view == desDecryptBtn) {
      byte[] cipher = Base64.decode(cipherEt.getText().toString(), Base64.DEFAULT);
      Log.i(TAG, new String(cipher));
      String plain = Crypto.desDecrypt(cipher, "12345678", "12345678");
      plainEt.setText(plain);
    }
  }
}