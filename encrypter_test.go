package laravelencryption

import (
	"encoding/json"
	"testing"
)

type testStruct struct {
	TestValue int `json:"a,omitempty"`
}

var (
	testEncryptedString = "eyJpdiI6IkpTUmFRK083ckMwSjJhSDhrNVB4b2c9PSIsInZhbHVlIjoiUkg0UEZ6N3dUTW1UcjFLT2MwMkQyQT09IiwibWFjIjoiOTU0ZjE2YTgxOGZjZTUzNTBjZjVjMzAzNjRlNTQ5N2YzYmM0ZjAzN2RkYzBkNWEzZjMwNGE2OTM4NTZlNWJlMyJ9"
	testPayload         = testStruct{
		TestValue: 1,
	}
	testKey      = "1234567890123456"
	wrongTestKey = testKey + "."
)

func TestNewWithKeys(t *testing.T) {
	_, e := NewEncrypter(wrongTestKey)
	if e == nil {
		t.Fatalf("shoud faild with wrongkey: %s", wrongTestKey)
	}
	_, e = NewEncrypter(testKey)
	if e != nil {
		t.Fatal(e)
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	b, _ := json.Marshal(testPayload)
	stringEncrypted, e := EncryptByte(b, testKey)
	t.Log("encrypted string", stringEncrypted)
	if e != nil {
		t.Fatal(e)
	}
	dec(t, stringEncrypted, testPayload)
}

func TestDecrypt(t *testing.T) {
	dec(t, testEncryptedString, testPayload)
}

func dec(t *testing.T, str string, targetValue testStruct) {
	decodeByte, e := DecryptString(str, testKey)
	if e != nil {
		t.Fatal(e)
	}
	target := testStruct{}
	e = json.Unmarshal(decodeByte, &target)
	if e != nil {
		t.Fatal(e)
	}

	if target != targetValue {
		t.Fatalf("error  decrypt payload %s", str)
	}
}
