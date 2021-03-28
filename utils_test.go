package go_authcode

import (
	"fmt"
	//"time"
	"testing"	

)


func TestHan(t *testing.T) {
	fmt.Println("abc是汉字吗：",IsChineseChar("abc"))
	fmt.Println("哎哎哎是汉字吗：",IsChineseChar("哎哎哎"))
}


func TestBase64_Bytes2Bytes(t *testing.T) {
	bRaw :=[]byte{0x01,0x02,0x03,0x04}
	fmt.Println("BRAW:",bRaw)

	if en,err :=Base64_Bytes2Bytes(BASE64_ENCODE,bRaw);err ==nil{
		fmt.Println("ENCODE:",en)

		if de,err :=Base64_Bytes2Bytes(BASE64_DECODE,en);err ==nil{
			fmt.Println("DECODE:",de)
		}else{
			fmt.Println("DECODE fail,err=",err)
		}

	}else{
		fmt.Println("ENCODE fail,err=",err)
	}
}

func TestBase64_string2Bytes(t *testing.T) {
	sRaw :="abcdeflg"
	fmt.Println("SRAW:",sRaw)
	
	if en,err :=Base64_String2Bytes(BASE64_ENCODE,sRaw);err ==nil{
		fmt.Println("ENCODE:",en)

		if de,err :=Base64_String2Bytes(BASE64_DECODE,string(en));err ==nil{
			fmt.Println("DECODE:",string(de))
		}else{
			fmt.Println("DECODE fail,err=",err)
		}

	}else{
		fmt.Println("ENCODE fail,err=",err)
	}
}

func TestBase64_Bytes2String(t *testing.T) {
	bRaw :=[]byte{0x01,0x02,0x03,0x04,0x05,0x06}
	fmt.Println("bRAW:",bRaw)
	
	if en,err :=Base64_Bytes2String(BASE64_ENCODE,bRaw);err ==nil{
		fmt.Println("ENCODE:",en)

		if de,err :=Base64_Bytes2String(BASE64_DECODE,[]byte(en));err ==nil{
			fmt.Println("DECODE:",[]byte(de))
		}else{
			fmt.Println("DECODE fail,err=",err)
		}

	}else{
		fmt.Println("ENCODE fail,err=",err)
	}
}

func TestBase64_String2String(t *testing.T) {
	sRaw :="/+abcdeflg/+"
	fmt.Println("sRAW:",sRaw)
	
	if en,err :=Base64_String2String(BASE64_ENCODE,sRaw);err ==nil{
		fmt.Println("ENCODE:",en)

		if de,err :=Base64_String2String(BASE64_DECODE,en);err ==nil{
			fmt.Println("DECODE:",de)
		}else{
			fmt.Println("DECODE fail,err=",err)
		}

	}else{
		fmt.Println("ENCODE fail,err=",err)
	}
}

func TestBase64_WEB_String2String(t *testing.T) {
	sRaw :="/+abcdeflg/+"
	fmt.Println("sRAW:",sRaw)
	
	if en,err :=Base64_WEB_String2String(BASE64_ENCODE,sRaw);err ==nil{
		fmt.Println("ENCODE:",en)

		if de,err :=Base64_WEB_String2String(BASE64_DECODE,en);err ==nil{
			fmt.Println("DECODE:",de)
		}else{
			fmt.Println("DECODE fail,err=",err)
		}

	}else{
		fmt.Println("ENCODE fail,err=",err)
	}
}

func TestBase64_WEB_Bytes2Bytes(t *testing.T) {
	bRaw :=[]byte("/+abcdeflg/+")
	fmt.Println("bRAW:",bRaw)
	
	if en,err :=Base64_WEB_Bytes2Bytes(BASE64_ENCODE,bRaw);err ==nil{
		fmt.Println("ENCODE:",en)

		if de,err :=Base64_WEB_Bytes2Bytes(BASE64_DECODE,en);err ==nil{
			fmt.Println("DECODE:",de)
		}else{
			fmt.Println("DECODE fail,err=",err)
		}

	}else{
		fmt.Println("ENCODE fail,err=",err)
	}
}

//测试结果可知，对于authcode，hex字符串形式的32位字符串才具有真正的使用价值
//因为keya与keyb以及很多其他细节都是基于32位字符串切割的，而不是基于16位字符串或者16位字节序列
func TestMd5(t *testing.T){
	bRaw :=[]byte{0x01,0x02,0x03}
	fmt.Println(Md5_Bytes2Bytes(bRaw),"len is:",len(Md5_Bytes2Bytes(bRaw)))
	fmt.Println(Md5_Bytes2Hexstring(bRaw),"len is:",len(Md5_Bytes2Hexstring(bRaw)))

	sRaw :=string(bRaw)
	fmt.Println(Md5_String2Hexstring(sRaw),"len is:",len(Md5_String2Hexstring(sRaw)))
}

func TestKeyDynamic(t *testing.T){
	keyDynamic :=make([]byte,8)
	keyDynamic =nil
	
	keyA :=[]byte{0x01,0x02,0x03}

	keyB := append([]byte{},keyDynamic...)

	keyC := append(keyA,keyDynamic...)

	fmt.Println("keyB:",keyB)
	fmt.Println("keyC:",keyC)

	fmt.Println("keyA:",keyA[:0])
	fmt.Println("keyA:",keyA[2:])
}